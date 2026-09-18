#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/socket.h>
#include "common.bpf.h"

char LICENSE[] SEC("license") = "GPL";

/* Writes (flow_key → cgroup_id) into cgroup_lookup_map on ACTIVE_ESTABLISHED.
 *
 * Fires when a container process's connect() succeeds — at this point the kernel
 * has assigned a source port and the full 5-tuple is available in bpf_sock_ops.
 *
 * proxy_proc accepts the redirected TCP connection, constructs the same flow_key
 * from getpeername + getsockname, and queries cgroup_lookup_map to recover cgroup_id.
 *
 * LRU hash: kernel auto-evicts stale entries — no manual cleanup needed.
 */
static __always_inline void record_flow(struct bpf_sock_ops *ctx) {
    if (!ctx) {
        return;
    }

    __u64 cgroup_id = bpf_get_current_cgroup_id();

    struct flow_key key = {};
    /* sockops only fires for TCP, so the 5-tuple protocol is always TCP. */
    key.protocol = NET_PROTOCOL_TCP;

    if (ctx->family == AF_INET) {
        key.family = AF_INET;
        /* bpf_sock_ops stores IPv4 in network byte order in local_ip4/remote_ip4.
         * We store raw bytes; proxy_proc constructs key from getpeername/getsockname
         * using the same raw byte order (sockaddr_in.sin_addr.s_addr). */
        __builtin_memcpy(key.src_ip, &ctx->local_ip4, 4);
        __builtin_memcpy(key.dst_ip, &ctx->remote_ip4, 4);
        /* local_port/remote_port in bpf_sock_ops are in host byte order. */
        key.src_port = ctx->local_port;
        key.dst_port = ctx->remote_port;
    } else {
        /* IPv6: copy full 16-byte addresses. */
        key.family = AF_INET6;
        __builtin_memcpy(key.src_ip, ctx->local_ip6, 16);
        __builtin_memcpy(key.dst_ip, ctx->remote_ip6, 16);
        key.src_port = ctx->local_port;
        key.dst_port = ctx->remote_port;
    }

    bpf_map_update_elem(&cgroup_lookup_map, &key, &cgroup_id, BPF_ANY);
}

SEC("sockops")
int handle_sockops(struct bpf_sock_ops *ctx) {
    switch (ctx->op) {
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        /* Container process initiated connect() and it succeeded.
         * Full 5-tuple (src/dst IP + src/dst port) + protocol now available. */
        record_flow(ctx);
        break;
    default:
        break;
    }
    return 0;
}
