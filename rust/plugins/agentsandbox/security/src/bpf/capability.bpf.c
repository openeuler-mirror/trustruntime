#include <vmlinux.h>
#include "common.bpf.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>

char LICENSE[] SEC("license") = "GPL";

static __always_inline __u64 load_u64(const char *p) {
    __u64 v;
    __builtin_memcpy(&v, p, sizeof(v));
    return v;
}

static __always_inline int has_zero(__u64 v) {
    return ((v - 0x0101010101010101ULL) & ~v & 0x8080808080808080ULL) != 0;
}

static __always_inline int path_prefix_match(const char *path, const char *prefix) {
#pragma clang loop unroll(disable)
    for (int i = 0; i < MAX_PATH_PATTERN_LEN / 8; i++) {
        __u64 a = load_u64(path + i * 8);
        __u64 b = load_u64(prefix + i * 8);
        __u64 z = ~b & (b - 0x0101010101010101ULL) & 0x8080808080808080ULL;
        if (z) {
            __u64 lowest = z & (~z + 1);
            __u64 mask = lowest | (lowest - 1);
            if ((a & mask) != (b & mask)) {
                return 0;
            }
            return 1;
        }
        if (a != b) {
            return 0;
        }
    }
    return 0;
}

static __always_inline int path_exact_match(const char *path, const char *target) {
#pragma clang loop unroll(disable)
    for (int i = 0; i < MAX_PATH_PATTERN_LEN / 8; i++) {
        __u64 a = load_u64(path + i * 8);
        __u64 b = load_u64(target + i * 8);
        if (a != b) {
            return 0;
        }
        if (has_zero(a)) {
            return 1;
        }
    }
    return 0;
}

/* Sleepable hook: caches the executable's absolute path at exec time.
 *
 * Fires exactly once per execve via bprm_check_security. bprm->file is the
 * executable's struct file (not the interpreter or any shared library), so we
 * resolve its path with bpf_d_path (allowed here, sleepable) and cache it keyed
 * by tgid so the non-sleepable capable hook can look it up without bpf_d_path. */
SEC("lsm/bprm_check_security")
int BPF_PROG(handle_bprm_exec, struct linux_binprm *bprm) {
    if (!bprm || !bprm->file) {
        return 0;
    }

    char path[MAX_EXE_PATH_LEN];
    __builtin_memset(path, 0, sizeof(path));
    if (bpf_d_path(&bprm->file->f_path, path, sizeof(path)) < 0) {
        return 0;
    }

    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_update_elem(&task_exe_path_map, &tgid, path, BPF_ANY);
    return 0;
}

static __always_inline int check_path_rules(__u64 cgroup_id, int cap) {
    struct cap_path_rules *rules = bpf_map_lookup_elem(&cap_path_rules_map, &cgroup_id);
    if (!rules) {
        return 0;
    }

    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    const char *exe_path = bpf_map_lookup_elem(&task_exe_path_map, &tgid);
    if (!exe_path) {
        return 0;
    }

    __u64 cap_bit = 1ULL << cap;

    for (int i = 0; i < MAX_CAP_PATH_RULES; i++) {
        if (i >= rules->count) {
            break;
        }
        struct cap_path_rule *rule = &rules->rules[i];

        int path_matched = 0;
        if (rule->match_type == PATH_MATCH_PREFIX) {
            path_matched = path_prefix_match(exe_path, rule->path);
        } else {
            path_matched = path_exact_match(exe_path, rule->path);
        }
        if (!path_matched) {
            continue;
        }

        /* scoped deny: 路径匹配 + cap 在 deny 列表 → 拦截 */
        if (rule->cap_mask & cap_bit) {
            return 1;
        }
    }
    return 0;
}

static __always_inline int emit_event(__u64 cgroup_id, __u32 pid, __u8 enforcement_mode) {
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    struct security_event *event = bpf_ringbuf_reserve(&event_ringbuf, sizeof(*event), 0);
    if (!event) {
        return enforcement_mode == 0 ? -EPERM : 0;
    }

    /* ringbuf reserve does not zero memory; clear the record so unset fields
     * (e.g. operation_detail) are empty NUL-terminated strings, not garbage. */
    __builtin_memset(event, 0, sizeof(*event));

    event->timestamp = bpf_ktime_get_ns();
    event->cgroup_id = cgroup_id;
    event->pid = pid;
    __builtin_memcpy(event->event_type, "privilege_escalation", 20);
    __builtin_memcpy(event->process_name, comm, 16);

    if (enforcement_mode == 0) {
        __builtin_memcpy(event->action, "block", 5);
        __builtin_memcpy(event->result, "blocked", 7);
        bpf_ringbuf_submit(event, 0);
        return -EPERM;
    }

    __builtin_memcpy(event->action, "alert", 5);
    __builtin_memcpy(event->result, "logged", 6);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("lsm/capable")
int BPF_PROG(handle_capable, const struct cred *cred, struct user_namespace *ns, int cap, unsigned int opts) {
    if (cap < 0 || cap >= 64) {
        return 0;
    }

    __u64 cgroup_id = bpf_get_current_cgroup_id();

    struct policy_value *pv = bpf_map_lookup_elem(&policy_map, &cgroup_id);
    if (!pv) {
        return 0;
    }

    __u64 cap_bit = 1ULL << cap;
    int matched = (pv->cap_mask & cap_bit) != 0;

    if (!matched && pv->has_path_rules) {
        matched = check_path_rules(cgroup_id, cap);
    }

    if (!matched) {
        if (pv->default_action == NET_ACTION_BLOCK) {
            __u32 pid = bpf_get_current_pid_tgid() >> 32;
            return emit_event(cgroup_id, pid, pv->enforcement_mode);
        }
        return 0;
    }

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    return emit_event(cgroup_id, pid, pv->enforcement_mode);
}
