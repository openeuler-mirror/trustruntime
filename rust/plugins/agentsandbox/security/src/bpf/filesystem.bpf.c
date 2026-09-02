#include "common.bpf.h"
#include <vmlinux.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/fcntl.h>
#include <linux/errno.h>

char LICENSE[] SEC("license") = "GPL";

static __always_inline int fs_path_prefix_match(const char *path, const char *prefix) {
    for (int i = 0; i < MAX_PATH_PATTERN_LEN; i++) {
        if (prefix[i] == '\0') {
            return 1;
        }
        if (path[i] != prefix[i]) {
            return 0;
        }
    }
    return 0;
}

static __always_inline int fs_path_exact_match(const char *path, const char *target) {
    for (int i = 0; i < MAX_PATH_PATTERN_LEN; i++) {
        if (path[i] != target[i]) {
            return 0;
        }
        if (path[i] == '\0') {
            return 1;
        }
    }
    return 0;
}

static __always_inline __u8 fmode_to_perm(fmode_t fmode) {
    __u8 perm = 0;
    if (fmode & FMODE_READ) {
        perm |= FS_PERM_READ;
    }
    if (fmode & FMODE_WRITE) {
        perm |= FS_PERM_WRITE;
    }
    if (fmode & FMODE_EXEC) {
        perm |= FS_PERM_EXEC;
    }
    return perm;
}

static __always_inline int check_fs_path_rules(__u64 cgroup_id, __u8 requested_perm, struct file *file) {

    struct fs_path_rules *rules = bpf_map_lookup_elem(&fs_path_rules_map, &cgroup_id);
    if (!rules) {
        return -1;
    }

    char file_path[MAX_EXE_PATH_LEN];
    __builtin_memset(file_path, 0, sizeof(file_path));
    if (bpf_d_path(&file->f_path, file_path, sizeof(file_path)) < 0) {
        return -1;
    }

    for (int i = 0; i < MAX_FS_PATH_RULES; i++) {
        if (i >= rules->count) {
            break;
        }
        struct fs_path_rule *rule = &rules->rules[i];

        int path_matched = 0;
        if (rule->match_type == PATH_MATCH_PREFIX) {
            path_matched = fs_path_prefix_match(file_path, rule->path);
        } else {
            path_matched = fs_path_exact_match(file_path, rule->path);
        }
        if (!path_matched) {
            continue;
        }

        if ((rule->perm_mask & requested_perm) != requested_perm) {
            return 1;
        }
        return 0;
    }
    return -1;
}

static __always_inline int emit_fs_event(
    __u64 cgroup_id, __u32 pid, __u8 mode) {

    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    struct security_event *event = bpf_ringbuf_reserve(&event_ringbuf, sizeof(*event), 0);
    if (!event) {
        return mode == 0 ? -EACCES : 0;
    }

    event->timestamp = bpf_ktime_get_ns();
    event->cgroup_id = cgroup_id;
    event->pid = pid;
    __builtin_memcpy(event->event_type, "filesystem_access", 17);
    __builtin_memcpy(event->process_name, comm, 16);

    if (mode == 0) {
        __builtin_memcpy(event->action, "block", 5);
        __builtin_memcpy(event->result, "blocked", 7);
        bpf_ringbuf_submit(event, 0);
        return -EACCES;
    }

    __builtin_memcpy(event->action, "alert", 5);
    __builtin_memcpy(event->result, "logged", 6);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("lsm/security_file_open")
int BPF_PROG(handle_file_open, struct file *file) {
    if (!file) {
        return 0;
    }

    __u64 cgroup_id = bpf_get_current_cgroup_id();

    struct policy_value *pv = bpf_map_lookup_elem(&policy_map, &cgroup_id);
    if (!pv) {
        return -EPERM;
    }

    struct sock_block_entry *blocked_sock = bpf_map_lookup_elem(&sock_block_map, &cgroup_id);
    if (blocked_sock) {
        char file_path[MAX_EXE_PATH_LEN];
        __builtin_memset(file_path, 0, sizeof(file_path));
        if (bpf_d_path(&file->f_path, file_path, sizeof(file_path)) >= 0) {
            if (fs_path_exact_match(file_path, blocked_sock->path)) {
                __u32 pid = bpf_get_current_pid_tgid() >> 32;
                return emit_fs_event(cgroup_id, pid, pv->enforcement_mode);
            }
        }
    }

    __u8 requested_perm = fmode_to_perm(file->f_mode);
    if (requested_perm == 0) {
        return 0;
    }

    int blocked = check_fs_path_rules(cgroup_id, requested_perm, file);
    if (blocked == 0) {
        return 0;
    }
    if (blocked < 0 && pv->default_action == NET_ACTION_ALLOW) {
        return 0;
    }

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    return emit_fs_event(cgroup_id, pid, pv->enforcement_mode);
}
