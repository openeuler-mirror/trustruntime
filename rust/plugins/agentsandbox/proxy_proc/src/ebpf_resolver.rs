use agentsandbox_config::ContainerId;
use agentsandbox_proxy::model::{Protocol, ResolverOutput};
use agentsandbox_proxy::registry::Resolver;
use agentsandbox_security::{EbpfLoader, NET_PROTOCOL_TCP};
use std::net::SocketAddr;
use std::sync::Arc;

/// Creates a proxy crate `Resolver` callback backed by eBPF cgroup_lookup_map.
pub fn create_ebpf_resolver(loader: Arc<EbpfLoader>) -> Resolver {
    Arc::new(move |source: SocketAddr, target: SocketAddr, _protocol: Protocol| -> Option<ResolverOutput> {
        let key = build_flow_key(source, target)?;
        let cgroup_id = loader.lookup_cgroup_by_flow(&key)?;
        Some(ResolverOutput {
            container_id: ContainerId::new(cgroup_id).as_key(),
            binary_path: String::new(),
        })
    })
}

/// Wrapper type for external consumers that need a named struct.
pub struct BpfFlowResolver {
    pub loader: Arc<EbpfLoader>,
}

impl BpfFlowResolver {
    pub fn new(loader: Arc<EbpfLoader>) -> Self {
        Self { loader }
    }

    /// Converts to a Resolver callback.
    pub fn into_resolver(self) -> Resolver {
        create_ebpf_resolver(self.loader)
    }
}

/// Constructs a security::FlowKey from two SocketAddrs (IPv4/IPv6 compatible).
fn build_flow_key(source: SocketAddr, target: SocketAddr) -> Option<agentsandbox_security::FlowKey> {
    match (source, target) {
        (SocketAddr::V4(src), SocketAddr::V4(dst)) => {
            Some(agentsandbox_security::FlowKey::from_ipv4(
                src.ip().octets(),
                src.port(),
                dst.ip().octets(),
                dst.port(),
                NET_PROTOCOL_TCP,
            ))
        }
        (SocketAddr::V6(src), SocketAddr::V6(dst)) => {
            Some(agentsandbox_security::FlowKey::from_ipv6(
                src.ip().octets(),
                src.port(),
                dst.ip().octets(),
                dst.port(),
                NET_PROTOCOL_TCP,
            ))
        }
        _ => None,
    }
}
