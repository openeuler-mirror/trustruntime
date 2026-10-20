#include <vmlinux.h>
#include "common.bpf.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>

char LICENSE[] SEC("license") = "GPL";

static int32_t pre_pend_name(Bufs *str_buf, struct qstr d_name, int32_t offset) {
    int32_t offset_tmp = offset;
    char slash = '/';
    offset_tmp -= (int32_t)(d_name.len + 1);
    if (offset_tmp < 0) {
        return -1;
    }

    long sz = bpf_probe_read_str(&(str_buf->buf[((uint32_t)offset_tmp) & (MAX_COMBIND_LENGTH - 1)]),
                                 (d_name.len + 1) & (MAX_COMBIND_LENGTH - 1),
                                 d_name.name);
    if (sz > 1) {
        bpf_probe_read(&(str_buf->buf[((uint32_t)offset_tmp + d_name.len) & (MAX_COMBIND_LENGTH - 1)]),
                       1, &slash);
    } else {
        offset_tmp += (int32_t)(d_name.len + 1);
    }
    return offset_tmp;
}

static inline struct mount *get_real_mount(struct vfsmount *mnt) {
    return container_of(mnt, struct mount, mnt);
}

static int32_t pre_pend_path(struct path *path, Bufs *str_buf) {
    if ((path == NULL) || (str_buf == NULL)) {
        return -1;
    }

    char slash = '/';
    char null = '\0';
    int32_t offset = MAX_COMBIND_LENGTH;
    struct dentry *dentry = path->dentry;
    struct vfsmount *vfsmnt = path->mnt;
    struct mount *mnt = get_real_mount(vfsmnt);
    struct dentry *d_parent;
    struct dentry *mnt_root;
    struct qstr d_name;

    #pragma unroll
    for (int32_t i = 0; i < MAX_LOOP_LIMIT; i++) {
        d_parent = BPF_CORE_READ(dentry, d_parent);
        mnt_root = BPF_CORE_READ(vfsmnt, mnt_root);
        if (dentry == mnt_root) {
            if (mnt != BPF_CORE_READ(mnt, mnt_parent)) {
                dentry = BPF_CORE_READ(mnt, mnt_mountpoint);
                mnt = BPF_CORE_READ(mnt, mnt_parent);
                vfsmnt = &mnt->mnt;
                continue;
            }
            break;
        }

        if (dentry == d_parent) {
            break;
        }

        d_name = BPF_CORE_READ(dentry, d_name);
        offset = pre_pend_name(str_buf, d_name, offset);
        if (offset < 1) {
            break;
        }
        dentry = d_parent;
    }

    if ((offset == MAX_COMBIND_LENGTH) || (offset < 1)) {
        return -1;
    }

    bpf_probe_read(&(str_buf->buf[MAX_COMBIND_LENGTH - 1]), 1, &null);
    offset--;
    bpf_probe_read(&(str_buf->buf[((uint32_t)offset) & (MAX_COMBIND_LENGTH - 1)]), 1, &slash);

    return offset;
}

static char *get_source() {
    struct task_struct *task = (struct task_struct *)(uintptr_t)bpf_get_current_task();
    int32_t buf_idx = CAP_SOURCE_BUF;
    Bufs *file_buf = bpf_map_lookup_elem(&g_bufs, &buf_idx);
    if (file_buf == NULL) {
        return NULL;
    }
    struct path file_path = BPF_CORE_READ(task, mm, exe_file, f_path);
    int32_t file_off = pre_pend_path(&file_path, file_buf);
    if (file_off < 0) {
        return NULL;
    }
    char *source = &(file_buf->buf[((uint32_t)file_off) & (MAX_COMBIND_LENGTH - 1)]);
    return source;
}

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
            __u64 mask = (lowest >> 7) - 1;
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

static __always_inline int check_path_rules(__u64 cgroup_id, int cap) {
    struct cap_path_rules *rules = bpf_map_lookup_elem(&cap_path_rules_map, &cgroup_id);
    if (!rules) {
        return 0;
    }

    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    const char *exe_path = get_source();
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
