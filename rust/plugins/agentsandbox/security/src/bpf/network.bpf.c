#include <vmlinux.h>
#include "common.bpf.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <linux/errno.h>

char LICENSE[] SEC("license") = "GPL";

/* SOCK_* constants are #defines in the kernel and therefore absent from
 * vmlinux.h; keep the stable ABI values here. */
#define SOCK_STREAM 1
#define SOCK_DGRAM  2

static __always_inline struct proxy_config *get_proxy_config(void) {
    __u32 key = 0;
    return bpf_map_lookup_elem(&proxy_config_map, &key);
}

/* Maps a socket type to a NET_PROTOCOL_* code used for network rule matching. */
static __always_inline __u8 sock_type_to_proto(short type) {
    if (type == SOCK_STREAM) {
        return NET_PROTOCOL_TCP;
    }
    if (type == SOCK_DGRAM) {
        return NET_PROTOCOL_UDP;
    }
    return NET_PROTOCOL_ANY;
}

/* Reads the 16-byte IPv6 destination out of bpf_sock_addr.user_ip6 (four __u32
 * words in network byte order) into canonical network byte order. Reads each ctx
 * word directly with an immediate offset so the verifier accepts the ctx access
 * (a pointer+loop pattern trips the verifier's "modified ctx ptr" check). Byte
 * order is recovered via byte extraction on the stack scalars. */
static __always_inline void net_read_user_ip6(struct bpf_sock_addr *ctx, __u8 *dst) {
    __u32 w0 = ctx->user_ip6[0];
    __u32 w1 = ctx->user_ip6[1];
    __u32 w2 = ctx->user_ip6[2];
    __u32 w3 = ctx->user_ip6[3];
    dst[0]  = (__u8)w0;        dst[1]  = (__u8)(w0 >> 8);
    dst[2]  = (__u8)(w0 >> 16); dst[3]  = (__u8)(w0 >> 24);
    dst[4]  = (__u8)w1;        dst[5]  = (__u8)(w1 >> 8);
    dst[6]  = (__u8)(w1 >> 16); dst[7]  = (__u8)(w1 >> 24);
    dst[8]  = (__u8)w2;        dst[9]  = (__u8)(w2 >> 8);
    dst[10] = (__u8)(w2 >> 16); dst[11] = (__u8)(w2 >> 24);
    dst[12] = (__u8)w3;        dst[13] = (__u8)(w3 >> 8);
    dst[14] = (__u8)(w3 >> 16); dst[15] = (__u8)(w3 >> 24);
}

/* Inverse of net_read_user_ip6: writes 16 canonical network-order bytes into
 * bpf_sock_addr.user_ip6 (used to rewrite the destination on redirect). Writes
 * each ctx word directly to keep the verifier happy. */
static __always_inline void net_write_user_ip6(struct bpf_sock_addr *ctx, const __u8 *src) {
    ctx->user_ip6[0] = (__u32)src[0] | ((__u32)src[1] << 8) |
                       ((__u32)src[2] << 16) | ((__u32)src[3] << 24);
    ctx->user_ip6[1] = (__u32)src[4] | ((__u32)src[5] << 8) |
                       ((__u32)src[6] << 16) | ((__u32)src[7] << 24);
    ctx->user_ip6[2] = (__u32)src[8] | ((__u32)src[9] << 8) |
                       ((__u32)src[10] << 16) | ((__u32)src[11] << 24);
    ctx->user_ip6[3] = (__u32)src[12] | ((__u32)src[13] << 8) |
                       ((__u32)src[14] << 16) | ((__u32)src[15] << 24);
}

static __always_inline int net_ip6_in_cidr(const __u8 *addr, const __u8 *net, const __u8 *mask) {
#pragma clang loop unroll(disable)
    for (int i = 0; i < 16; i++) {
        if ((addr[i] & mask[i]) != (net[i] & mask[i])) {
            return 0;
        }
    }
    return 1;
}

static __always_inline int net_ip6_eq(const __u8 *a, const __u8 *b) {
#pragma unroll
    for (int i = 0; i < 16; i++) {
        if (a[i] != b[i]) {
            return 0;
        }
    }
    return 1;
}

/* Reads a destination sockaddr that may live in either kernel memory (sendto(2)
 * copies msg_name into a kernel stack buffer before the LSM hook) or user memory
 * (sendmsg(2) keeps msg_name as a user pointer). Tries the kernel probe first
 * and falls back to the user probe. Fills family + ip4/ip6 + port for
 * AF_INET/AF_INET6; returns 0 on success, -1 on unreadable/unsupported. */
static __always_inline int read_net_sockaddr(void *addr, __u8 *family, __u32 *ip4,
                                             __u8 *ip6, __u16 *port) {
    __u16 fam = 0;
    if (bpf_probe_read_kernel(&fam, sizeof(fam), addr) != 0 &&
        bpf_probe_read_user(&fam, sizeof(fam), addr) != 0) {
        return -1;
    }
    *family = (__u8)fam;

    if (fam == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        __be32 a;
        __be16 p;
        if (bpf_probe_read_kernel(&a, sizeof(a), &sin->sin_addr.s_addr) != 0 &&
            bpf_probe_read_user(&a, sizeof(a), &sin->sin_addr.s_addr) != 0) {
            return -1;
        }
        if (bpf_probe_read_kernel(&p, sizeof(p), &sin->sin_port) != 0 &&
            bpf_probe_read_user(&p, sizeof(p), &sin->sin_port) != 0) {
            return -1;
        }
        *ip4 = a;
        *port = bpf_ntohs(p);
        return 0;
    }

    if (fam == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
        __be16 p;
        if (bpf_probe_read_kernel(ip6, 16, &sin6->sin6_addr) != 0 &&
            bpf_probe_read_user(ip6, 16, &sin6->sin6_addr) != 0) {
            return -1;
        }
        if (bpf_probe_read_kernel(&p, sizeof(p), &sin6->sin6_port) != 0 &&
            bpf_probe_read_user(&p, sizeof(p), &sin6->sin6_port) != 0) {
            return -1;
        }
        *port = bpf_ntohs(p);
        return 0;
    }

    return -1;
}

/* IPv4 rule match. family==0 (wildcard) or AF_INET only. */
static __always_inline int match_network_rule(const struct network_rule *rule,
                                              __u32 dst_ip, __u16 dst_port, __u8 protocol) {
    if (rule->family != 0 && rule->family != AF_INET) {
        return 0;
    }
    if ((dst_ip & rule->target_mask) != (rule->target_ip & rule->target_mask)) {
        return 0;
    }
    if (rule->port != 0 && rule->port != dst_port) {
        return 0;
    }
    if (rule->protocol != NET_PROTOCOL_ANY && rule->protocol != protocol) {
        return 0;
    }
    return 1;
}

/* IPv6 rule match. family==0 (wildcard) or AF_INET6 only. */
static __always_inline int match_network_rule6(const struct network_rule *rule,
                                               const __u8 *dst_ip6, __u16 dst_port, __u8 protocol) {
    if (rule->family != 0 && rule->family != AF_INET6) {
        return 0;
    }
    if (rule->family == AF_INET6 &&
        !net_ip6_in_cidr(dst_ip6, rule->target_ip6, rule->target_mask6)) {
        return 0;
    }
    if (rule->port != 0 && rule->port != dst_port) {
        return 0;
    }
    if (rule->protocol != NET_PROTOCOL_ANY && rule->protocol != protocol) {
        return 0;
    }
    return 1;
}

static __always_inline int check_network_rules(__u64 cgroup_id, __u32 dst_ip, __u16 dst_port,
                                               __u8 protocol, __u8 default_action) {
    struct network_rules *rules = bpf_map_lookup_elem(&network_rules_map, &cgroup_id);
    if (!rules) {
        return default_action;
    }
#pragma clang loop unroll(disable)
    for (int i = 0; i < MAX_NETWORK_RULES; i++) {
        if (i >= rules->count) {
            break;
        }
        if (match_network_rule(&rules->rules[i], dst_ip, dst_port, protocol)) {
            return rules->rules[i].action;
        }
    }
    return default_action;
}

static __always_inline int check_network_rules6(__u64 cgroup_id, const __u8 *dst_ip6, __u16 dst_port,
                                                __u8 protocol, __u8 default_action) {
    struct network_rules *rules = bpf_map_lookup_elem(&network_rules_map, &cgroup_id);
    if (!rules) {
        return default_action;
    }
#pragma clang loop unroll(disable)
    for (int i = 0; i < MAX_NETWORK_RULES; i++) {
        if (i >= rules->count) {
            break;
        }
        if (match_network_rule6(&rules->rules[i], dst_ip6, dst_port, protocol)) {
            return rules->rules[i].action;
        }
    }
    return default_action;
}

/* Emits a network security event into event_ringbuf. Fails silently if the ring
 * buffer is full (enforcement is unaffected). Callers decide their own return
 * value (cgroup hooks return 0/1; LSM hooks return 0/-errno). */
static __always_inline void emit_net_event(__u64 cgroup_id, __u32 pid, __u8 action) {
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    struct security_event *event = bpf_ringbuf_reserve(&event_ringbuf, sizeof(*event), 0);
    if (!event) {
        return;
    }

    __builtin_memset(event, 0, sizeof(*event));

    event->timestamp = bpf_ktime_get_ns();
    event->cgroup_id = cgroup_id;
    event->pid = pid;
    __builtin_memcpy(event->event_type, "network", 8);
    __builtin_memcpy(event->process_name, comm, 16);

    if (action == NET_ACTION_BLOCK) {
        __builtin_memcpy(event->action, "block", 5);
        __builtin_memcpy(event->result, "blocked", 7);
    } else if (action == NET_ACTION_REDIRECT) {
        __builtin_memcpy(event->action, "redirect", 9);
        __builtin_memcpy(event->result, "redirected", 10);
    } else {
        __builtin_memcpy(event->action, "allow", 5);
        __builtin_memcpy(event->result, "allowed", 7);
    }
    bpf_ringbuf_submit(event, 0);
}

SEC("cgroup/connect4")
int handle_connect4(struct bpf_sock_addr *ctx) {
    if (!ctx) {
        return 1;
    }

    struct proxy_config *proxy = get_proxy_config();

    __u64 cgroup_id = bpf_get_current_cgroup_id();

    struct policy_value *pv = bpf_map_lookup_elem(&policy_map, &cgroup_id);
    if (!pv) {
        return 1;
    }

    __u32 dst_ip = ctx->user_ip4;
    __u16 dst_port = bpf_ntohs(ctx->user_port);
    __u8 protocol = ctx->protocol;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (pv->container_port != 0 && dst_port == pv->container_port
        && proxy && dst_ip == proxy->container_ip) {
        if (proxy && proxy->model_route_port != 0) {
            ctx->user_ip4 = proxy->proxy_ip;
            ctx->user_port = bpf_htons(proxy->model_route_port);
        }
        emit_net_event(cgroup_id, pid, NET_ACTION_REDIRECT);
        return 1;
    }

    int action = check_network_rules(cgroup_id, dst_ip, dst_port, protocol, pv->default_action);

    if (action == NET_ACTION_BLOCK) {
        emit_net_event(cgroup_id, pid, NET_ACTION_BLOCK);
        return 0;
    }

    if (action == NET_ACTION_REDIRECT) {
        if (proxy && proxy->proxy_port != 0) {
            ctx->user_ip4 = proxy->proxy_ip;
            ctx->user_port = bpf_htons(proxy->proxy_port);
        }
        emit_net_event(cgroup_id, pid, NET_ACTION_REDIRECT);
        return 1;
    }

    emit_net_event(cgroup_id, pid, NET_ACTION_ALLOW);
    return 1;
}

SEC("cgroup/connect6")
int handle_connect6(struct bpf_sock_addr *ctx) {
    if (!ctx) {
        return 1;
    }

    struct proxy_config *proxy = get_proxy_config();

    __u64 cgroup_id = bpf_get_current_cgroup_id();

    struct policy_value *pv = bpf_map_lookup_elem(&policy_map, &cgroup_id);
    if (!pv) {
        return 1;
    }

    __u8 dst_ip6[16] = {};
    net_read_user_ip6(ctx, dst_ip6);
    __u16 dst_port = bpf_ntohs(ctx->user_port);
    __u8 protocol = ctx->protocol;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (pv->container_port != 0 && dst_port == pv->container_port
        && proxy && net_ip6_eq(dst_ip6, proxy->container_ip6)) {
        if (proxy && proxy->model_route_port != 0) {
            net_write_user_ip6(ctx, proxy->proxy_ip6);
            ctx->user_port = bpf_htons(proxy->model_route_port);
        }
        emit_net_event(cgroup_id, pid, NET_ACTION_REDIRECT);
        return 1;
    }

    int action = check_network_rules6(cgroup_id, dst_ip6, dst_port, protocol, pv->default_action);

    if (action == NET_ACTION_BLOCK) {
        emit_net_event(cgroup_id, pid, NET_ACTION_BLOCK);
        return 0;
    }

    if (action == NET_ACTION_REDIRECT) {
        if (proxy && proxy->proxy_port != 0) {
            net_write_user_ip6(ctx, proxy->proxy_ip6);
            ctx->user_port = bpf_htons(proxy->proxy_port);
        }
        emit_net_event(cgroup_id, pid, NET_ACTION_REDIRECT);
        return 1;
    }

    emit_net_event(cgroup_id, pid, NET_ACTION_ALLOW);
    return 1;
}

/* LSM-level uniform deny fallback for connect(2).
 *
 * cgroup/connect4 + connect6 already handle block/redirect/allow for inet
 * connects and emit events; this hook only closes gaps they miss by denying
 * (return -EPERM) when a BLOCK rule matches. allow/redirect pass through
 * (return 0) so no duplicate allow/redirect events are emitted. The `address`
 * parameter is the kernel stack copy built by move_addr_to_kernel. */
SEC("lsm/socket_connect")
int BPF_PROG(handle_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen) {
    if (!sock || !address) {
        return 0;
    }

    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct policy_value *pv = bpf_map_lookup_elem(&policy_map, &cgroup_id);
    if (!pv) {
        return 0;
    }

    __u16 sa_family = 0;
    if (bpf_probe_read_kernel(&sa_family, sizeof(sa_family), &address->sa_family) < 0) {
        return 0;
    }

    short sock_type = 0;
    if (bpf_probe_read_kernel(&sock_type, sizeof(sock_type), &sock->type) < 0) {
        return 0;
    }
    __u8 protocol = sock_type_to_proto(sock_type);

    __u8 dst_ip6[16] = {};
    __u32 dst_ip4 = 0;
    __u16 dst_port = 0;
    int action;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)address;
        __be32 ip4;
        __be16 port;
        if (bpf_probe_read_kernel(&ip4, sizeof(ip4), &sin->sin_addr.s_addr) < 0) {
            return 0;
        }
        if (bpf_probe_read_kernel(&port, sizeof(port), &sin->sin_port) < 0) {
            return 0;
        }
        dst_ip4 = ip4;
        dst_port = bpf_ntohs(port);
        action = check_network_rules(cgroup_id, dst_ip4, dst_port, protocol, pv->default_action);
    } else if (sa_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)address;
        __be16 port;
        if (bpf_probe_read_kernel(dst_ip6, sizeof(dst_ip6), &sin6->sin6_addr) < 0) {
            return 0;
        }
        if (bpf_probe_read_kernel(&port, sizeof(port), &sin6->sin6_port) < 0) {
            return 0;
        }
        dst_port = bpf_ntohs(port);
        action = check_network_rules6(cgroup_id, dst_ip6, dst_port, protocol, pv->default_action);
    } else {
        return 0;
    }

    if (action == NET_ACTION_BLOCK) {
        emit_net_event(cgroup_id, pid, NET_ACTION_BLOCK);
        return -EPERM;
    }
    return 0;
}

/* LSM-level deny for unconnected UDP sendto(2)/sendmsg(2).
 *
 * Datagrams sent without a prior connect() never reach cgroup/connect4|6, so the
 * per-message destination (msg->msg_name, a user-space sockaddr in the common
 * sendto/sendmsg path) is read here and checked against the network rules. Only
 * UDP is enforced (protocol derived from sock->type); other protocols pass
 * through unchanged. */
SEC("lsm/socket_sendmsg")
int BPF_PROG(handle_socket_sendmsg, struct socket *sock, struct msghdr *msg, int size) {
    if (!sock || !msg) {
        return 0;
    }

    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct policy_value *pv = bpf_map_lookup_elem(&policy_map, &cgroup_id);
    if (!pv) {
        return 0;
    }

    short sock_type = 0;
    if (bpf_probe_read_kernel(&sock_type, sizeof(sock_type), &sock->type) < 0) {
        return 0;
    }
    __u8 protocol = sock_type_to_proto(sock_type);
    if (protocol != NET_PROTOCOL_UDP) {
        return 0;
    }

    void *msg_name = NULL;
    int msg_namelen = 0;
    if (bpf_probe_read_kernel(&msg_name, sizeof(msg_name), &msg->msg_name) < 0) {
        return 0;
    }
    if (bpf_probe_read_kernel(&msg_namelen, sizeof(msg_namelen), &msg->msg_namelen) < 0) {
        return 0;
    }
    if (!msg_name || msg_namelen <= 0) {
        return 0;
    }

    __u8 sa_family = 0;
    __u32 dst_ip4 = 0;
    __u8 dst_ip6[16] = {};
    __u16 dst_port = 0;
    if (read_net_sockaddr(msg_name, &sa_family, &dst_ip4, dst_ip6, &dst_port) < 0) {
        return 0;
    }

    int action = (sa_family == AF_INET6)
        ? check_network_rules6(cgroup_id, dst_ip6, dst_port, protocol, pv->default_action)
        : check_network_rules(cgroup_id, dst_ip4, dst_port, protocol, pv->default_action);

    if (action == NET_ACTION_BLOCK) {
        __u32 pid = bpf_get_current_pid_tgid() >> 32;
        emit_net_event(cgroup_id, pid, NET_ACTION_BLOCK);
        return -EPERM;
    }
    return 0;
}