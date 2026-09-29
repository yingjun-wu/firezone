#![cfg_attr(test, allow(clippy::unwrap_used))]

use std::{
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use bytes::Bytes;
use futures::{StreamExt as _, stream::FuturesUnordered};
use http_body_util::{BodyExt, Full};
use rustls::ClientConfig;
use socket_factory::{SocketFactory, TcpSocket};
use tokio_rustls::TlsConnector;
use tokio_util::task::AbortOnDropHandle;

/// The negotiated request sender for a connection.
///
/// HTTP/2 multiplexes, so its sender is cheaply cloned and used concurrently.
/// HTTP/1.1 serialises one request at a time, so it is shared behind a mutex; the
/// `Clone` on [`HttpClient`] (which telemetry's parallel DoH path relies on) still
/// holds, but concurrent sends over an h1 connection take turns.
#[derive(Clone)]
enum Sender {
    H2(hyper::client::conn::http2::SendRequest<Full<Bytes>>),
    H1(Arc<tokio::sync::Mutex<hyper::client::conn::http1::SendRequest<Full<Bytes>>>>),
}

/// A future that drives a connection to completion. Boxed so the h2 and h1
/// connection types share one return shape.
type ConnectionDriver = Pin<Box<dyn Future<Output = ()> + Send>>;

/// An HTTP client that plugs into our [`SocketFactory`] abstraction.
///
/// One instance is tied to a given host. It negotiates HTTP/2 if the server
/// supports it (ALPN `h2`) and falls back to HTTP/1.1 otherwise. The connection is
/// maintained for the client's lifetime; once it fails, every request errors with
/// [`Closed`] and the client should be discarded.
#[derive(Clone)]
pub struct HttpClient {
    host: String,
    port: u16,
    scheme: &'static str,
    sender: Sender,

    #[expect(dead_code, reason = "We only need to keep it around.")]
    connection: Arc<AbortOnDropHandle<()>>,
}

impl HttpClient {
    pub async fn new(
        host: String,
        addresses: Vec<IpAddr>,
        socket_factory: Arc<dyn SocketFactory<TcpSocket>>,
    ) -> Result<Self> {
        // TODO: Use `rustls-platform-verifier` instead.
        let mut root_cert_store = rustls::RootCertStore::empty();
        root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        let (sender, driver) = connect(
            addresses,
            443,
            host.clone(),
            Arc::new(config),
            socket_factory,
        )
        .await?;

        let connection = tokio::spawn({
            let host = host.clone();

            async move {
                driver.await;
                tracing::debug!(%host, "HTTP connection finished");
            }
        });

        Ok(Self {
            host,
            port: 443,
            scheme: "https",
            sender,
            connection: Arc::new(AbortOnDropHandle::new(connection)),
        })
    }

    /// Connects to a local ingestion sidecar without TLS. Literal loopback
    /// addresses only; public and private network addresses still require HTTPS.
    pub async fn new_loopback_http(
        address: SocketAddr,
        socket_factory: Arc<dyn SocketFactory<TcpSocket>>,
    ) -> Result<Self> {
        anyhow::ensure!(address.ip().is_loopback(), "Plain HTTP requires loopback");
        let stream = socket_factory.bind(address)?.connect(address).await?;
        let (sender, connection) = hyper::client::conn::http1::Builder::new()
            .handshake::<_, Full<Bytes>>(hyper_util::rt::TokioIo::new(stream))
            .await?;
        let task = tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::debug!("Local HTTP connection failed: {error:#}");
            }
        });
        let host = match address.ip() {
            IpAddr::V4(ip) => ip.to_string(),
            IpAddr::V6(ip) => format!("[{ip}]"),
        };
        Ok(Self {
            host,
            port: address.port(),
            scheme: "http",
            sender: Sender::H1(Arc::new(tokio::sync::Mutex::new(sender))),
            connection: Arc::new(AbortOnDropHandle::new(task)),
        })
    }

    /// Whether the underlying connection has been closed.
    ///
    /// A closed client is permanently unusable and should be discarded.
    pub fn is_closed(&self) -> bool {
        match &self.sender {
            Sender::H2(client) => client.is_closed(),
            // A held lock means a request is in flight, so the connection is still
            // active; an idle lock lets us ask the sender directly.
            Sender::H1(mutex) => mutex.try_lock().is_ok_and(|sender| sender.is_closed()),
        }
    }

    pub fn send_request(
        &self,
        request: http::Request<Bytes>,
    ) -> Result<impl Future<Output = Result<http::Response<Bytes>>> + use<>> {
        anyhow::ensure!(!self.is_closed(), Closed);
        anyhow::ensure!(
            request.uri().scheme_str() == Some(self.scheme)
                && request
                    .uri()
                    .port_u16()
                    .unwrap_or(if self.scheme == "https" { 443 } else { 80 })
                    == self.port,
            "Request origin does not match connection"
        );

        let host = request
            .uri()
            .host()
            .context("Missing host in request URI")?
            .to_owned();
        anyhow::ensure!(
            host == self.host,
            "Can only send HTTP requests to host {}",
            self.host
        );

        let sender = self.sender.clone();

        Ok(async move {
            let (parts, body) = request.into_parts();
            let mut request = http::Request::from_parts(parts, Full::new(body));

            let response = match sender {
                Sender::H2(mut client) => {
                    client
                        .ready()
                        .await
                        .context("Failed to await readiness of HTTP/2 client")?;

                    client
                        .send_request(request)
                        .await
                        .context("Failed to send HTTP/2 request")
                        .context(Closed)?
                }
                Sender::H1(mutex) => {
                    // HTTP/1.1 carries the host in a `Host` header (HTTP/2 uses the
                    // `:authority` pseudo-header derived from the URI), so add it if
                    // the caller didn't.
                    if !request.headers().contains_key(http::header::HOST) {
                        let value = http::HeaderValue::from_str(
                            request
                                .uri()
                                .authority()
                                .context("Missing authority")?
                                .as_str(),
                        )
                        .context("Invalid host header")?;
                        request.headers_mut().insert(http::header::HOST, value);
                    }

                    let mut client = mutex.lock().await;
                    client
                        .ready()
                        .await
                        .context("Failed to await readiness of HTTP/1.1 client")?;

                    client
                        .send_request(request)
                        .await
                        .context("Failed to send HTTP/1.1 request")
                        .context(Closed)?
                }
            };

            let (parts, incoming) = response.into_parts();

            let body = incoming
                .collect()
                .await
                .context("Failed to receive HTTP response body")
                .context(Closed)?;

            Ok(http::Response::from_parts(parts, body.to_bytes()))
        })
    }
}

/// The connection behind an [`HttpClient`] is closed or has failed.
///
/// A transport error on a persistent connection leaves it dead or dying, so
/// every request that hits one carries this error, not only those sent after
/// [`HttpClient::is_closed`] starts reporting `true`.
#[derive(thiserror::Error, Debug)]
#[error("The connection is closed")]
pub struct Closed;

async fn connect(
    addresses: Vec<IpAddr>,
    port: u16,
    domain: String,
    tls_config: Arc<ClientConfig>,
    sf: Arc<dyn SocketFactory<TcpSocket>>,
) -> Result<(Sender, ConnectionDriver)> {
    tracing::debug!(?addresses, %domain, "Creating new HTTP connection");

    // Race the addresses instead of walking them in order. A blackholed address
    // fails only once the OS gives up on the TCP connect, over a minute later,
    // so in order a working address behind one is not reached until then.
    let mut attempts = addresses
        .into_iter()
        .map(|address| {
            let socket = SocketAddr::new(address, port);
            let domain = domain.clone();
            let tls_config = tls_config.clone();
            let sf = sf.clone();

            async move { (socket, connect_one(socket, domain, tls_config, sf).await) }
        })
        .collect::<FuturesUnordered<_>>();

    // Ends once every attempt has resolved. Returning early drops the losing
    // attempts, which cancels them.
    while let Some((socket, attempt)) = attempts.next().await {
        match attempt {
            Ok(connection) => {
                tracing::debug!(%socket, %domain, "Created new HTTP connection");

                return Ok(connection);
            }
            Err(e) => tracing::debug!(%socket, %domain, "Failed to create HTTP client: {e:#}"),
        }
    }

    anyhow::bail!("Failed to connect to '{domain}' on port {port}");
}

async fn connect_one(
    socket: SocketAddr,
    domain: String,
    tls_client_config: Arc<ClientConfig>,
    sf: Arc<dyn SocketFactory<TcpSocket>>,
) -> Result<(Sender, ConnectionDriver)> {
    let stream = sf
        .bind(socket)
        .context("Failed to create TCP socket")?
        .connect(socket)
        .await
        .context("Failed to connect TCP stream")?;

    let connector = TlsConnector::from(tls_client_config);
    let tls_domain = rustls_pki_types::ServerName::try_from(domain)?;

    let stream = connector.connect(tls_domain, stream).await?;

    // Drive the HTTP version off what the server negotiated via ALPN.
    let is_h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2".as_slice());
    let io = hyper_util::rt::TokioIo::new(stream);

    if is_h2 {
        let mut builder =
            hyper::client::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new());
        builder.timer(hyper_util::rt::TokioTimer::default());
        builder.keep_alive_timeout(Duration::from_secs(1));
        builder.keep_alive_while_idle(true);
        builder.keep_alive_interval(Some(Duration::from_secs(5)));

        let (sender, conn) = builder
            .handshake::<_, Full<Bytes>>(io)
            .await
            .context("Failed to handshake HTTP/2 connection")?;

        let driver = Box::pin(async move {
            if let Err(e) = conn.await {
                tracing::debug!("HTTP/2 connection failed: {e:#}");
            }
        });

        Ok((Sender::H2(sender), driver))
    } else {
        let (sender, conn) = hyper::client::conn::http1::Builder::new()
            .handshake::<_, Full<Bytes>>(io)
            .await
            .context("Failed to handshake HTTP/1.1 connection")?;

        let driver = Box::pin(async move {
            if let Err(e) = conn.await {
                tracing::debug!("HTTP/1.1 connection failed: {e:#}");
            }
        });

        Ok((
            Sender::H1(Arc::new(tokio::sync::Mutex::new(sender))),
            driver,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;

    #[tokio::test]
    async fn loopback_http_preserves_port_and_rejects_other_origins() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        assert!(
            HttpClient::new_loopback_http(
                "192.0.2.1:8080".parse().unwrap(),
                Arc::new(socket_factory::tcp)
            )
            .await
            .is_err()
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = [0; 2048];
            let n = stream.read(&mut bytes).await.unwrap();
            assert!(
                String::from_utf8_lossy(&bytes[..n])
                    .to_lowercase()
                    .contains(&format!("host: {address}"))
            );
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        let client = HttpClient::new_loopback_http(address, Arc::new(socket_factory::tcp))
            .await
            .unwrap();
        for uri in [
            format!("https://{address}/"),
            "http://127.0.0.1:1/".into(),
            format!("http://127.0.0.2:{}/", address.port()),
        ] {
            assert!(
                client
                    .send_request(
                        http::Request::builder()
                            .uri(uri)
                            .body(Bytes::new())
                            .unwrap()
                    )
                    .is_err()
            );
        }
        let request = http::Request::builder()
            .uri(format!("http://{address}/ingestion/flow_logs"))
            .body(Bytes::new())
            .unwrap();
        assert_eq!(
            client
                .send_request(request)
                .unwrap()
                .await
                .unwrap()
                .status(),
            http::StatusCode::NO_CONTENT
        );
        server.await.unwrap();
    }

    #[tokio::test]
    #[ignore = "Requires Internet"]
    async fn parallel_doh_queries() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .unwrap();

        let http_client = HttpClient::new(
            "one.one.one.one".to_owned(),
            vec![IpAddr::from([1, 1, 1, 1])],
            Arc::new(socket_factory::tcp),
        )
        .await
        .unwrap();

        let query = http::Request::builder()
            .uri("https://one.one.one.one/dns-query?name=example.com")
            .method("GET")
            .header("Accept", "application/dns-json")
            .body(Bytes::new())
            .unwrap();

        let response1 = http_client.send_request(query.clone()).unwrap();
        let response2 = http_client.send_request(query.clone()).unwrap();

        let (response1, response2) = futures::future::try_join(response1, response2)
            .await
            .unwrap();

        assert!(response1.status().is_success());
        assert!(response2.status().is_success());
    }
}
