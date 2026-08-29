#include "common.bpf.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/in.h>
#include <linux/socket.h>

char LICENSE[] SEC("license") = "GPL";

/* Network connect hook: modifies container connect() target to proxy TCP port.
 * Not a middle proxy - modifies destination address so SO_PEERCRED returns container pid.
 */

#define PROXY_PORT 8443

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 65535);
    __type(key, __u32);
    __type(value, __u64);
} sock_map SEC(".maps");

SEC("cgroup/connect4")
int handle_connect4(struct bpf_sock_addr *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    /* Modify destination to proxy TCP port */
    ctx->user_port = bpf_htons(PROXY_PORT);

    /* Keep original IP - SO_PEERCRED will return container process pid */
    return 1;
}
