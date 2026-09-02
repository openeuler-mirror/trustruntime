#include "common.bpf.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <linux/errno.h>

char LICENSE[] SEC("license") = "GPL";

static __always_inline struct proxy_config *get_proxy_config(void) {
    __u32 key = 0;
    return bpf_map_lookup_elem(&proxy_config_map, &key);
}

static __always_inline int match_network_rule(struct network_rule *rule, __u32 dst_ip, __u16 dst_port, __u8 protocol) {

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

static __always_inline int check_network_rules(__u64 cgroup_id, __u32 dst_ip, __u16 dst_port, __u8 protocol, __u8 default_action) {

    struct network_rules *rules = bpf_map_lookup_elem(&network_rules_map, &cgroup_id);
    if (!rules) {
        return default_action;
    }

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

static __always_inline int emit_net_event(__u64 cgroup_id, __u32 pid, __u8 action) {

    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    struct security_event *event = bpf_ringbuf_reserve(&event_ringbuf, sizeof(*event), 0);
    if (!event) {
        return action == NET_ACTION_BLOCK ? 0 : 1;
    }

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
    return 0;
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
