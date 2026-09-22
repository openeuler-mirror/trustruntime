#include <vmlinux.h>
#include "common.bpf.h"
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>

char LICENSE[] SEC("license") = "GPL";

static __always_inline int get_exe_inode(__u64 *ino, __u32 *dev) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    if (!task) {
        return -1;
    }
    struct mm_struct *mm = task->mm;
    if (!mm) {
        return -1;
    }
    struct file *exe_file = mm->exe_file;
    if (!exe_file) {
        return -1;
    }
    struct inode *inode = exe_file->f_inode;
    if (!inode) {
        return -1;
    }
    *ino = inode->i_ino;
    *dev = inode->i_sb->s_dev;
    return 0;
}

static __always_inline int check_path_rules(__u64 cgroup_id, int cap) {
    struct cap_path_rules *rules = bpf_map_lookup_elem(&cap_path_rules_map, &cgroup_id);
    if (!rules) {
        return 0;
    }

    __u64 ino;
    __u32 dev;
    if (get_exe_inode(&ino, &dev) < 0) {
        return 0;
    }

    __u64 cap_bit = 1ULL << cap;

    for (int i = 0; i < MAX_CAP_PATH_RULES; i++) {
        if (i >= rules->count) {
            break;
        }
        struct cap_path_rule *rule = &rules->rules[i];

        if (rule->ino != ino || rule->dev != dev) {
            continue;
        }

        if (rule->cap_mask & cap_bit) {
            return 0;
        }
        return 1;
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
        return -EPERM;
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
