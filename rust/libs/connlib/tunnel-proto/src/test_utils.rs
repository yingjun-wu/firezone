use connlib_model::RelayId;
use snownet::{Node, RelaySocket};
use std::{
    collections::BTreeSet,
    fmt,
    hash::Hash,
    net::SocketAddr,
    time::{Duration, Instant},
};

/// Complete actual STUN discovery without a socket or a TURN allocation.
pub(crate) fn discover_relay<T: Copy + Eq + Hash + Ord + fmt::Display>(
    node: &mut Node<T, RelayId>,
    now: Instant,
) {
    let relay: SocketAddr = "127.0.0.1:3478".parse().unwrap();
    let local: SocketAddr = "127.0.0.2:10000".parse().unwrap();
    node.update_relays(
        BTreeSet::new(),
        &BTreeSet::from([(
            RelayId::from_u128(1),
            RelaySocket::from(relay),
            "test".into(),
            "password".into(),
            "firezone".into(),
        )]),
        now,
    );
    let request = std::iter::from_fn(|| node.poll_transmit())
        .find(|t| t.payload[..2] == [0, 1])
        .expect("STUN binding request");
    let mut response = vec![1, 1, 0, 12];
    response.extend_from_slice(&request.payload[4..20]);
    response.extend_from_slice(&[0, 0x20, 0, 8, 0, 1]);
    response.extend_from_slice(&(10000u16 ^ 0x2112).to_be_bytes());
    response.extend_from_slice(&(u32::from_be_bytes([127, 0, 0, 2]) ^ 0x2112a442).to_be_bytes());
    node.decapsulate(local, relay, &response, now + Duration::from_millis(1))
        .unwrap();
}
