use connlib_model::{GatewayId, PublicKey, ResourceId};
use std::{collections::BTreeSet, sync::Arc, time::Instant};
use tunnel::{
    ClientTunnel, GatewayTunnel,
    resource::{InternetResource, Resource},
};

#[tokio::test]
async fn edgewall_api_remains_accessible_through_tunnel() {
    let mut client = ClientTunnel::new(
        Arc::new(socket_factory::tcp),
        Arc::new(socket_factory::udp),
        BTreeSet::new(),
        false,
        Instant::now(),
    );
    let mut gateway = GatewayTunnel::new(
        Arc::new(socket_factory::tcp),
        Arc::new(socket_factory::udp),
        BTreeSet::new(),
        Instant::now(),
    );
    assert_eq!(PublicKey::from(client.private_key()), client.public_key());
    assert_eq!(PublicKey::from(gateway.private_key()), gateway.public_key());
    assert!(client.take_tun().is_none());
    assert!(gateway.take_tun().is_none());

    let id = ResourceId::from_u128(1);
    let resource = Resource::Internet(InternetResource {
        id: ResourceId(id.0),
        name: "Internet".into(),
        sites: vec![],
    });
    assert_eq!(resource.id(), id);
    assert!(client.state_mut().gateway_tun_by_resource(&id).is_none());
    let gateway_id = GatewayId::from_u128(2);
    assert!(client.state_mut().gateway_tun_by_id(&gateway_id).is_none());
    assert!(
        client
            .state_mut()
            .get_site_by_gateway(&gateway_id)
            .is_none()
    );
    assert!(
        client
            .state_mut()
            .get_sites_by_gateways(&[gateway_id])
            .is_empty()
    );
}
