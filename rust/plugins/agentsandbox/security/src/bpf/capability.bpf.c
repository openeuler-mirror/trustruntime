#include "common.bpf.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

SEC("lsm/security_capable")
int BPF_PROG(handle_capable, const struct cred *cred, struct cap_audit_info *info, int cap, int opts, int ret) {
    if (ret != 0) {
        return ret;
    }
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct security_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.pid = pid;
    __builtin_memcpy(event.event_type, "privilege_escalation", 20);
    __builtin_memcpy(event.action, "block", 5);
    __builtin_memcpy(event.result, "blocked", 7);
    __builtin_memcpy(event.process_name, comm, 16);
    bpf_send_event(event);
    return -EPERM;
}
