#include "common.bpf.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

SEC("lsm/security_file_open")
int BPF_PROG(handle_file_open, struct file *file) {
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct security_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.pid = pid;
    __builtin_memcpy(event.event_type, "filesystem_access", 17);
    __builtin_memcpy(event.action, "block", 5);
    __builtin_memcpy(event.result, "blocked", 7);
    __builtin_memcpy(event.process_name, comm, 16);
    bpf_send_event(event);
    return -EACCES;
}
