#include <vmlinux.h>
#include "common.bpf.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>

/* Kernel-internal FMODE_* flags are #defines in include/linux/fs.h, not present
 * in vmlinux.h (BTF dump) nor any UAPI header. Define the values the program reads. */
#define FMODE_READ  0x1
#define FMODE_WRITE 0x2
#define FMODE_EXEC  0x4

char LICENSE[] SEC("license") = "GPL";

static __always_inline __u64 load_u64(const char *p) {
    __u64 v;
    __builtin_memcpy(&v, p, sizeof(v));
    return v;
}

static __always_inline int fs_has_zero(__u64 v) {
    return ((v - 0x0101010101010101ULL) & ~v & 0x8080808080808080ULL) != 0;
}

static __always_inline int fs_path_prefix_match(const char *path, const char *prefix) {
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

static __always_inline int fs_path_exact_match(const char *path, const char *target) {
#pragma clang loop unroll(disable)
    for (int i = 0; i < MAX_PATH_PATTERN_LEN / 8; i++) {
        __u64 a = load_u64(path + i * 8);
        __u64 b = load_u64(target + i * 8);
        if (a != b) {
            return 0;
        }
        if (fs_has_zero(a)) {
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

static __always_inline int check_fs_path_rules(__u64 cgroup_id, __u8 requested_perm, const char *file_path) {

    struct fs_path_rules *rules = bpf_map_lookup_elem(&fs_path_rules_map, &cgroup_id);
    if (!rules) {
        return -1;
    }

#pragma clang loop unroll(disable)
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

static __always_inline int check_fs_path_rules_file(__u64 cgroup_id, __u8 requested_perm, struct file *file) {
    char file_path[MAX_EXE_PATH_LEN];
    __builtin_memset(file_path, 0, sizeof(file_path));
    if (bpf_d_path(&file->f_path, file_path, sizeof(file_path)) < 0) {
        return -1;
    }
    return check_fs_path_rules(cgroup_id, requested_perm, file_path);
}

static __always_inline int emit_fs_event(
    __u64 cgroup_id, __u32 pid, __u8 mode) {

    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    struct security_event *event = bpf_ringbuf_reserve(&event_ringbuf, sizeof(*event), 0);
    if (!event) {
        return mode == 0 ? -EACCES : 0;
    }

    /* ringbuf reserve does not zero memory; clear the record so unset fields
     * (e.g. operation_detail) are empty NUL-terminated strings, not garbage. */
    __builtin_memset(event, 0, sizeof(*event));

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

SEC("lsm/file_open")
int BPF_PROG(handle_file_open, struct file *file) {
    if (!file) {
        return 0;
    }

    __u64 cgroup_id = bpf_get_current_cgroup_id();

    struct policy_value *pv = bpf_map_lookup_elem(&policy_map, &cgroup_id);
    if (!pv) {
        return 0;
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

    int blocked = check_fs_path_rules_file(cgroup_id, requested_perm, file);
    if (blocked == 0) {
        return 0;
    }
    if (blocked < 0 && pv->default_action == NET_ACTION_ALLOW) {
        return 0;
    }

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    return emit_fs_event(cgroup_id, pid, pv->enforcement_mode);
}

/* Sleepable hook: enforces exec permission on the executable's path and caches
 * its absolute path for the non-sleepable capable hook.
 *
 * Fires exactly once per execve via bprm_check_security. bprm->file is the
 * executable's struct file (not the interpreter or any shared library), so we
 * resolve its path with bpf_d_path (allowed here, sleepable). Unlike
 * file_open, whose f_mode never carries FMODE_EXEC, bprm_check_security is the
 * authoritative point to gate execution against fs_path_rules with
 * FS_PERM_EXEC. On success the path is cached keyed by tgid. */
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

    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct policy_value *pv = bpf_map_lookup_elem(&policy_map, &cgroup_id);
    if (pv) {
        int blocked = check_fs_path_rules(cgroup_id, FS_PERM_EXEC, path);
        int allowed = (blocked == 0) || (blocked < 0 && pv->default_action == NET_ACTION_ALLOW);
        if (!allowed) {
            return emit_fs_event(cgroup_id, tgid, pv->enforcement_mode);
        }
    }
    return 0;
}

/* LSM hook: blocks connect(2) to the HiController socket path registered in
 * sock_block_map for the container's cgroup.
 *
 * file_open does NOT fire for AF_UNIX connect(2): the kernel resolves the
 * pathname socket via kern_path (no file open) and then triggers
 * security_unix_stream_connect instead. `other` is the listening socket's
 * struct sock; since struct unix_sock.sk is its first member, `other` doubles
 * as the struct unix_sock pointer, and the bound pathname lives in
 * addr->name->sun_path. On a match, the connect is denied (emit_fs_event
 * returns -EACCES in block mode; logged-only in alert mode), closing the
 * post-hook window where the container could otherwise reconnect and tamper
 * with its policy via register/unregister.
 */
SEC("lsm/unix_stream_connect")
int BPF_PROG(handle_unix_stream_connect, struct sock *sock, struct sock *other, struct sock *newsk) {
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    struct sock_block_entry *blocked = bpf_map_lookup_elem(&sock_block_map, &cgroup_id);
    if (!blocked) {
        return 0;
    }

    if (!other) {
        return 0;
    }

    /* `other` is BTF-typed struct sock, but the real object is a struct unix_sock
     * (sk is its first member, so container_of is a no-op cast). addr lies beyond
     * struct sock's BTF size, so a direct dereference is rejected by the verifier
     * ("access beyond struct sock"). Read it via CO-RE: BPF_CORE_READ resolves the
     * field offset at load time against the runtime BTF and reads the pointer with
     * bpf_probe_read_kernel (untrusted source, fault-safe at runtime), avoiding the
     * BTF bound check on the direct load. */
    struct unix_address *addr = BPF_CORE_READ((struct unix_sock *)other, addr);
    if (!addr) {
        return 0;
    }

    /* sun_path is a fixed 108-byte array inside sockaddr_un, but the kernel only
     * stores the bound pathname + NUL there; the bytes after the NUL are
     * uninitialized. fs_path_exact_match compares full 8-byte words, so reading
     * the raw 108 bytes would leave the trailing garbage and never match the
     * zero-padded blocked->path. Use bpf_probe_read_kernel_str to copy only up
     * to (and including) the NUL, leaving the memset-zeroed tail intact. */
    int32_t buf_idx = UNIX_SOCK_BUF;
    Bufs *sock_buf = bpf_map_lookup_elem(&g_bufs, &buf_idx);
    if (!sock_buf) {
        return 0;
    }
    char *path = sock_buf->buf;
    __builtin_memset(path, 0, MAX_PATH_PATTERN_LEN);
    if (bpf_probe_read_kernel_str(path, 108,
                                  (void *)((unsigned long)addr
                                           + offsetof(struct unix_address, name)
                                           + offsetof(struct sockaddr_un, sun_path))) < 0) {
        return 0;
    }

    if (fs_path_exact_match(path, blocked->path)) {
        __u32 pid = bpf_get_current_pid_tgid() >> 32;
        struct policy_value *pv = bpf_map_lookup_elem(&policy_map, &cgroup_id);
        __u8 mode = pv ? pv->enforcement_mode : 0;
        return emit_fs_event(cgroup_id, pid, mode);
    }
    return 0;
}
