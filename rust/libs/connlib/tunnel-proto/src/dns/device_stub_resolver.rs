use crate::{
    dns::{self, device_slug_in},
    expiring_map::{self, ExpiringMap},
    messages::client::FailReason,
};
use dns_types::DomainName;
use smallvec::{SmallVec, smallvec};
use std::{
    collections::{BTreeMap, VecDeque},
    iter,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, Instant},
};

/// How long to wait for the portal to resolve a device name before giving up.
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// TTL used in synthesised DNS responses for device resolutions.
///
/// Keeps downstream resolver caches short-lived so mapping changes propagate quickly.
const DNS_TTL: u32 = 1;

/// Answers device names through the portal. Defaults to `<slug>.firezone.network`.
/// The host can disable answer caching when every lookup requires authorization.
pub struct DeviceStubResolver {
    device_domain: DomainName,
    cache_answers: bool,
    resolved: BTreeMap<DomainName, (Ipv4Addr, Ipv6Addr)>,
    pending: ExpiringMap<DomainName, SmallVec<[PendingQuery; 2]>>,

    events: VecDeque<Event>,
}

pub(crate) enum ResolveStrategy {
    /// The query is not for a device name.
    Passthrough,
    /// The query is for a device name and a response has been formed.
    LocalResponse(dns_types::Response),
    /// The query is for a device name but we cannot answer it yet.
    Pending,
}

#[derive(Debug)]
pub(crate) enum Event {
    QueryDomain {
        domain: DomainName,
    },
    SendResponse {
        local: SocketAddr,
        remote: SocketAddr,
        transport: dns::Transport,
        response: dns_types::Response,
    },
}

#[derive(Debug)]
struct PendingQuery {
    local: SocketAddr,
    remote: SocketAddr,
    transport: dns::Transport,
    query: dns_types::Query,
}

impl Default for DeviceStubResolver {
    fn default() -> Self {
        Self {
            device_domain: dns::DEVICE_DOMAIN.parse().expect("valid device domain"),
            cache_answers: true,
            resolved: Default::default(),
            pending: Default::default(),
            events: Default::default(),
        }
    }
}

impl DeviceStubResolver {
    pub(crate) fn configure(
        &mut self,
        domain: DomainName,
        cache_answers: bool,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            !domain.to_string().trim_end_matches('.').is_empty(),
            "device domain must not be root"
        );
        if self.device_domain != domain || self.cache_answers != cache_answers {
            self.clear_cache();
            self.device_domain = domain;
            self.cache_answers = cache_answers;
        }
        Ok(())
    }

    pub(crate) fn clear_cache(&mut self) {
        self.resolved.clear();
        self.events.clear();
        for (_, waiters) in self.pending.extract_if(|_, _| true) {
            for pending in waiters {
                self.events.push_back(Event::SendResponse {
                    local: pending.local,
                    remote: pending.remote,
                    transport: pending.transport,
                    response: dns_types::Response::servfail(&pending.query),
                });
            }
        }
    }

    /// Processes a DNS query against the device domain.
    pub(crate) fn handle_query(
        &mut self,
        query: &dns_types::Query,
        local: SocketAddr,
        remote: SocketAddr,
        transport: dns::Transport,
        now: Instant,
    ) -> ResolveStrategy {
        let domain = query.domain();

        if device_slug_in(&domain, &self.device_domain).is_none() {
            return ResolveStrategy::Passthrough;
        }

        let qtype = query.qtype();

        // Only A and AAAA are answered from device resolutions; for any other
        // qtype, the name exists but we have no records of that type (NOERROR + empty).
        if qtype != dns_types::RecordType::A && qtype != dns_types::RecordType::AAAA {
            return ResolveStrategy::LocalResponse(
                dns_types::ResponseBuilder::for_query(query, dns_types::ResponseCode::NOERROR)
                    .build(),
            );
        }

        if let Some((ipv4, ipv6)) = self.resolved.get(&domain) {
            return ResolveStrategy::LocalResponse(build_response(
                query,
                domain.clone(),
                *ipv4,
                *ipv6,
            ));
        }

        let pending = PendingQuery {
            local,
            remote,
            transport,
            query: query.clone(),
        };

        if let Some(waiters) = self.pending.get_mut(&domain) {
            waiters.push(pending);

            return ResolveStrategy::Pending;
        }

        self.pending
            .insert(domain.clone(), smallvec![pending], now, QUERY_TIMEOUT);

        tracing::debug!(%domain, "Querying portal for device name");

        self.events.push_back(Event::QueryDomain { domain });

        ResolveStrategy::Pending
    }

    pub(crate) fn handle_device_domain_resolved(
        &mut self,
        domain: DomainName,
        result: Result<(Ipv4Addr, Ipv6Addr), FailReason>,
    ) {
        let Some(pending) = self.pending.remove(&domain) else {
            tracing::debug!(%domain, "Received device resolution for unknown query");
            return;
        };

        tracing::debug!(%domain, ?result, "Device name resolved");

        if let Ok((ipv4, ipv6)) = result
            && self.cache_answers
        {
            self.resolved.insert(domain, (ipv4, ipv6));
        }

        for pending in pending.value {
            let response = match result {
                Ok((ipv4, ipv6)) => {
                    build_response(&pending.query, pending.query.domain(), ipv4, ipv6)
                }
                Err(FailReason::NotFound) => dns_types::Response::nxdomain(&pending.query),
                Err(
                    FailReason::Offline
                    | FailReason::VersionMismatch
                    | FailReason::Forbidden
                    | FailReason::Disabled
                    | FailReason::AmbiguousAddress
                    | FailReason::MissingAddress
                    | FailReason::InvalidAddress
                    | FailReason::Unknown,
                ) => dns_types::Response::servfail(&pending.query),
            };

            self.events.push_back(Event::SendResponse {
                local: pending.local,
                remote: pending.remote,
                transport: pending.transport,
                response,
            });
        }
    }

    pub(crate) fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    pub(crate) fn handle_timeout(&mut self, now: Instant) {
        self.pending.handle_timeout(now);
        while let Some(expiring_map::Event::EntryExpired {
            key: domain,
            value: waiters,
        }) = self.pending.poll_event()
        {
            tracing::debug!(%domain, "Pending device DNS query timed out; returning SERVFAIL");

            for pending in waiters {
                let response = dns_types::Response::servfail(&pending.query);
                self.events.push_back(Event::SendResponse {
                    local: pending.local,
                    remote: pending.remote,
                    transport: pending.transport,
                    response,
                });
            }
        }
    }

    pub(crate) fn poll_timeout(&self) -> Option<Instant> {
        self.pending.poll_timeout()
    }
}

fn build_response(
    query: &dns_types::Query,
    domain: dns_types::DomainName,
    ipv4: Ipv4Addr,
    ipv6: Ipv6Addr,
) -> dns_types::Response {
    let builder = dns_types::ResponseBuilder::for_query(query, dns_types::ResponseCode::NOERROR);

    match query.qtype() {
        dns_types::RecordType::A => builder
            .with_records(iter::once((domain, DNS_TTL, dns_types::records::a(ipv4))))
            .build(),
        dns_types::RecordType::AAAA => builder
            .with_records(iter::once((
                domain,
                DNS_TTL,
                dns_types::records::aaaa(ipv6),
            )))
            .build(),
        // The name exists but we don't have a record of the requested type.
        _ => builder.build(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    const LOCAL: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53);
    const REMOTE: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);
    const DEVICE: &str = "laptop.firezone.network";
    const TEST_IPV4: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 42);
    const TEST_IPV6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x2021, 0x1111, 0, 0, 0, 0, 42);

    #[test]
    fn configured_domain_matches_only_one_label_and_preserves_default() {
        let mut resolver = DeviceStubResolver::default();
        assert!(resolver.configure(domain("."), false).is_err());
        assert!(matches!(
            handle(&mut resolver, DEVICE, dns_types::RecordType::A),
            ResolveStrategy::Pending
        ));
        resolver
            .configure(domain("devices.example.test."), false)
            .unwrap();
        assert!(
            matches!(drain(&mut resolver).as_slice(), [Event::SendResponse { response, .. }] if response.response_code() == dns_types::ResponseCode::SERVFAIL)
        );
        for name in [
            DEVICE,
            "devices.example.test",
            "a.b.devices.example.test",
            "a.devices.example.test.invalid",
        ] {
            assert!(matches!(
                handle(&mut resolver, name, dns_types::RecordType::A),
                ResolveStrategy::Passthrough
            ));
        }
        assert!(matches!(
            handle(
                &mut resolver,
                "LAPTOP.Devices.Example.Test.",
                dns_types::RecordType::AAAA
            ),
            ResolveStrategy::Pending
        ));
    }

    #[test]
    fn disabling_cache_rechecks_answers_and_clear_cancels_pending_queries() {
        let mut resolver = DeviceStubResolver::default();
        handle(&mut resolver, DEVICE, dns_types::RecordType::A);
        drain(&mut resolver);
        resolver.handle_device_domain_resolved(domain(DEVICE), Ok((TEST_IPV4, TEST_IPV6)));
        drain(&mut resolver);
        resolver
            .configure(domain(dns::DEVICE_DOMAIN), false)
            .unwrap();
        assert!(matches!(
            handle(&mut resolver, DEVICE, dns_types::RecordType::A),
            ResolveStrategy::Pending
        ));
        drain(&mut resolver);
        resolver.handle_device_domain_resolved(domain(DEVICE), Ok((TEST_IPV4, TEST_IPV6)));
        assert!(
            matches!(drain(&mut resolver).as_slice(), [Event::SendResponse { response, .. }] if response.records().count() == 1)
        );
        assert!(matches!(
            handle(&mut resolver, DEVICE, dns_types::RecordType::AAAA),
            ResolveStrategy::Pending
        ));
        resolver.clear_cache();
        assert!(
            matches!(drain(&mut resolver).as_slice(), [Event::SendResponse { response, .. }] if response.response_code() == dns_types::ResponseCode::SERVFAIL)
        );
        resolver.handle_device_domain_resolved(domain(DEVICE), Ok((TEST_IPV4, TEST_IPV6)));
        assert!(resolver.poll_event().is_none());
        assert!(matches!(
            handle(&mut resolver, DEVICE, dns_types::RecordType::A),
            ResolveStrategy::Pending
        ));
        drain(&mut resolver);
        resolver.handle_device_domain_resolved(domain(DEVICE), Err(FailReason::NotFound));
        assert!(
            matches!(drain(&mut resolver).as_slice(), [Event::SendResponse { response, .. }] if response.response_code() == dns_types::ResponseCode::NXDOMAIN)
        );
    }

    #[test]
    fn passes_through_names_outside_the_device_domain() {
        let mut resolver = DeviceStubResolver::default();

        for domain in [
            "other.example.com",
            "firezone.network",
            "a.b.firezone.network",
            "laptop.firezone.network.example.com",
        ] {
            let s = handle(&mut resolver, domain, dns_types::RecordType::A);

            assert!(matches!(s, ResolveStrategy::Passthrough), "{domain}");
        }

        assert!(resolver.poll_event().is_none());
    }

    #[test]
    fn answers_unsupported_qtypes_with_empty_noerror() {
        let mut resolver = DeviceStubResolver::default();

        let ResolveStrategy::LocalResponse(resp) =
            handle(&mut resolver, DEVICE, dns_types::RecordType::TXT)
        else {
            panic!("expected LocalResponse")
        };

        assert_eq!(resp.response_code(), dns_types::ResponseCode::NOERROR);
        assert_eq!(resp.records().count(), 0);
        assert!(resolver.poll_event().is_none());
    }

    #[test]
    fn queries_the_portal_once_for_a_and_aaaa() {
        let mut resolver = DeviceStubResolver::default();

        assert!(matches!(
            handle(&mut resolver, DEVICE, dns_types::RecordType::A),
            ResolveStrategy::Pending
        ));
        assert!(matches!(
            handle(&mut resolver, DEVICE, dns_types::RecordType::AAAA),
            ResolveStrategy::Pending
        ));

        let Some(Event::QueryDomain { domain }) = resolver.poll_event() else {
            panic!("expected QueryDomain event")
        };
        assert_eq!(domain.to_string(), DEVICE);
        assert!(resolver.poll_event().is_none());
    }

    #[test]
    fn resolution_answers_every_waiter() {
        let mut resolver = DeviceStubResolver::default();
        handle(&mut resolver, DEVICE, dns_types::RecordType::A);
        handle(&mut resolver, DEVICE, dns_types::RecordType::AAAA);
        let remote = SocketAddr::new(REMOTE.ip(), REMOTE.port() + 1);
        resolver.handle_query(
            &query(DEVICE, dns_types::RecordType::A).with_id(42),
            LOCAL,
            remote,
            dns::Transport::Tcp,
            Instant::now(),
        );
        drain(&mut resolver);

        resolver.handle_device_domain_resolved(domain(DEVICE), Ok((TEST_IPV4, TEST_IPV6)));

        let events = drain(&mut resolver);
        assert_eq!(events.len(), 3);
        for event in events {
            let Event::SendResponse {
                remote: response_remote,
                transport,
                response,
                ..
            } = event
            else {
                panic!("unexpected event: {event:?}")
            };
            match transport {
                dns::Transport::Tcp => {
                    assert_eq!(response_remote, remote);
                    assert_eq!(response.id(), 42);
                }
                dns::Transport::Udp => assert_eq!(response_remote, REMOTE),
            }
            let expected = match response.qtype() {
                dns_types::RecordType::A => dns_types::records::a(TEST_IPV4),
                dns_types::RecordType::AAAA => dns_types::records::aaaa(TEST_IPV6),
                qtype => panic!("unexpected record type: {qtype}"),
            };
            assert!(response.records().any(|r| r.data() == &expected));
        }
    }

    #[test]
    fn serves_repeat_queries_from_the_cache() {
        let mut resolver = DeviceStubResolver::default();
        handle(&mut resolver, DEVICE, dns_types::RecordType::A);
        drain(&mut resolver);
        resolver.handle_device_domain_resolved(domain(DEVICE), Ok((TEST_IPV4, TEST_IPV6)));
        drain(&mut resolver);

        let ResolveStrategy::LocalResponse(resp) =
            handle(&mut resolver, DEVICE, dns_types::RecordType::AAAA)
        else {
            panic!("expected LocalResponse")
        };

        assert!(
            resp.records()
                .any(|r| r.data() == &dns_types::records::aaaa(TEST_IPV6))
        );
        assert!(resolver.poll_event().is_none());
    }

    #[test]
    fn not_found_is_nxdomain_and_other_failures_are_servfail() {
        for (reason, code) in [
            (FailReason::NotFound, dns_types::ResponseCode::NXDOMAIN),
            (FailReason::Offline, dns_types::ResponseCode::SERVFAIL),
        ] {
            let mut resolver = DeviceStubResolver::default();
            handle(&mut resolver, DEVICE, dns_types::RecordType::A);
            drain(&mut resolver);

            resolver.handle_device_domain_resolved(domain(DEVICE), Err(reason));

            let events = drain(&mut resolver);
            let [Event::SendResponse { response, .. }] = events.as_slice() else {
                panic!("unexpected events: {events:?}")
            };
            assert_eq!(response.response_code(), code);
        }
    }

    #[test]
    fn pending_query_times_out_with_servfail() {
        let mut resolver = DeviceStubResolver::default();
        let now = Instant::now();
        resolver.handle_query(
            &query(DEVICE, dns_types::RecordType::A),
            LOCAL,
            REMOTE,
            dns::Transport::Udp,
            now,
        );
        resolver.handle_query(
            &query(DEVICE, dns_types::RecordType::A).with_id(42),
            LOCAL,
            REMOTE,
            dns::Transport::Udp,
            now + Duration::from_secs(1),
        );
        drain(&mut resolver);

        resolver.handle_timeout(now + QUERY_TIMEOUT);

        let events = drain(&mut resolver);
        assert_eq!(events.len(), 2);
        for event in events {
            let Event::SendResponse { response, .. } = event else {
                panic!("unexpected event: {event:?}")
            };
            assert_eq!(response.response_code(), dns_types::ResponseCode::SERVFAIL);
        }

        resolver.handle_device_domain_resolved(domain(DEVICE), Ok((TEST_IPV4, TEST_IPV6)));

        assert!(resolver.poll_event().is_none());
    }

    fn handle(
        resolver: &mut DeviceStubResolver,
        domain: &str,
        record_type: dns_types::RecordType,
    ) -> ResolveStrategy {
        resolver.handle_query(
            &query(domain, record_type),
            LOCAL,
            REMOTE,
            dns::Transport::Udp,
            Instant::now(),
        )
    }

    fn drain(resolver: &mut DeviceStubResolver) -> Vec<Event> {
        iter::from_fn(|| resolver.poll_event()).collect()
    }

    fn domain(domain: &str) -> DomainName {
        domain.parse().unwrap()
    }

    fn query(domain: &str, record_type: dns_types::RecordType) -> dns_types::Query {
        dns_types::Query::new(domain.parse().unwrap(), record_type)
    }
}
