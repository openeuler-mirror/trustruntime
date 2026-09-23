#ifndef __COMMON_BPF_H
#define __COMMON_BPF_H

/*
 * Basic types (__u64 etc.) and BPF_MAP_TYPE_* enums must be provided by the
 * including translation unit *before* this header:
 *   - <vmlinux.h>   for capability/filesystem (CO-RE internal kernel structs)
 *   - <linux/bpf.h> for network/sockops (UAPI-only programs)
 */
#include <bpf/bpf_helpers.h>

/* Address-family constants are #defines in the kernel and therefore absent from
 * vmlinux.h; the stripped Ubuntu linux-libc-dev <linux/socket.h> also omits them. */
#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

#define MAX_CGROUP_ID_LEN 256
#define MAX_EVENT_DETAIL 128
#define MAX_PROCESS_NAME 16
#define MAX_PATH_PATTERN_LEN 256
#define MAX_CAP_PATH_RULES 32
#define MAX_FS_PATH_RULES 32
#define MAX_NETWORK_RULES 32
#define MAX_EXE_PATH_LEN 256
#define MAX_TARGET_LEN 64

/* Path match type for fs_path_rule.match_type */
#define PATH_MATCH_EXACT   0
#define PATH_MATCH_PREFIX  1

/* File access permission bits for fs_path_rule.perm_mask */
#define FS_PERM_READ    (1 << 0)
#define FS_PERM_WRITE   (1 << 1)
#define FS_PERM_EXEC    (1 << 2)

/* Network rule action codes for network_rule.action / policy_value.default_action */
#define NET_ACTION_ALLOW    0
#define NET_ACTION_BLOCK    1
#define NET_ACTION_REDIRECT 2

/* Network protocol identifiers for network_rule.protocol */
#define NET_PROTOCOL_ANY    0
#define NET_PROTOCOL_TCP    6
#define NET_PROTOCOL_UDP    17

struct security_event {
    __u64 timestamp;
    __u64 cgroup_id;
    char event_type[32];
    char operation_detail[MAX_EVENT_DETAIL];
    char action[16];
    char result[16];
    char process_name[MAX_PROCESS_NAME];
    __u32 pid;
};

struct policy_value {
    __u8 enforcement_mode;
    __u8 rule_count;
    __u64 cap_mask;
    __u8 has_path_rules;
    __u8 default_action;
    __u16 container_port;
};

struct cap_path_rule {
    __u64 cap_mask;
    __u8 match_type;
    char path[MAX_PATH_PATTERN_LEN];
};

struct cap_path_rules {
    __u8 count;
    struct cap_path_rule rules[MAX_CAP_PATH_RULES];
};

struct fs_path_rule {
    __u8 perm_mask;
    __u8 match_type;
    char path[MAX_PATH_PATTERN_LEN];
};

struct fs_path_rules {
    __u8 count;
    struct fs_path_rule rules[MAX_FS_PATH_RULES];
};

struct network_rule {
    __u32 target_ip;
    __u32 target_mask;
    __u16 port;
    __u8 protocol;
    __u8 action;
};

struct network_rules {
    __u8 count;
    struct network_rule rules[MAX_NETWORK_RULES];
};

struct proxy_config {
    __u32 proxy_ip;
    __u16 proxy_port;
    __u16 model_route_port;
    __u32 container_ip;
};

struct sock_block_entry {
    char path[MAX_PATH_PATTERN_LEN];
};

/* Container security policy map.
 * key:   cgroup_id (__u64) — identifies the container/cgroup
 * value: struct policy_value — enforcement mode + cap bitmask + path-rule flag
 * Written by user-space SecurityPolicyManager, read by all BPF programs.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct policy_value);
} policy_map SEC(".maps");

/* Path-conditioned capability rules map.
 * key:   cgroup_id (__u64) — identifies the container/cgroup
 * value: struct cap_path_rules — up to MAX_CAP_PATH_RULES cap+path entries
 * Only populated when policy_value.has_path_rules == 1.
 * Written by user-space EbpfLoader, read by capability.bpf.c.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct cap_path_rules);
} cap_path_rules_map SEC(".maps");

/* Per-task executable path cache.
 * key:   tgid (__u32) — thread group id from bpf_get_current_pid_tgid() >> 32
 * value: char[MAX_EXE_PATH_LEN] — NUL-terminated absolute executable path
 *
 * Written by the bprm_check_security LSM program (sleepable hook): the
 * executable path is resolved via bpf_d_path (allowed there) once per exec.
 * The non-sleepable capable hook reads
 * this map to resolve path-conditioned capability rules without bpf_d_path.
 * LRU hash auto-evicts entries for exited processes; no manual cleanup needed.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, char[MAX_EXE_PATH_LEN]);
} task_exe_path_map SEC(".maps");

/* Filesystem path permission rules map.
 * key:   cgroup_id (__u64) — identifies the container/cgroup
 * value: struct fs_path_rules — up to MAX_FS_PATH_RULES path+perm entries
 * Written by user-space EbpfLoader, read by filesystem.bpf.c.
 * Semantics: path matched + requested perm not in perm_mask → block.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct fs_path_rules);
} fs_path_rules_map SEC(".maps");

/* Network connect rules map.
 * key:   cgroup_id (__u64) — identifies the container/cgroup
 * value: struct network_rules — up to MAX_NETWORK_RULES target/port/proto/action entries
 * Written by user-space EbpfLoader, read by network.bpf.c.
 * Semantics: first matching rule decides action (allow/block/redirect).
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct network_rules);
} network_rules_map SEC(".maps");

/* Global proxy port configuration.
 * key:   0 (single-entry array map)
 * value: struct proxy_config — proxy_port for redirect action
 * Written once at startup by user-space EbpfLoader, read by network.bpf.c.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct proxy_config);
} proxy_config_map SEC(".maps");

/* HiController sock block map.
 * key:   cgroup_id (__u64) — identifies the container/cgroup
 * value: struct sock_block_entry — sock path to block after hook completes
 * Written by user-space after container registration, read by filesystem.bpf.c.
 * Independent from fs_path_rules_map to avoid consuming rule slots.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct sock_block_entry);
} sock_block_map SEC(".maps");

/* Security event ring buffer.
 * Producer: all BPF programs (capability/filesystem/network).
 * Consumer: user-space EbpfLoader::poll_events → write_security_log.
 * Entries may be dropped under high load; policy enforcement is unaffected.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096 * 64);
} event_ringbuf SEC(".maps");

/* Container cgroup lookup map.
 * key:   struct flow_key — 5-tuple (src/dst IP + port + protocol + family)
 * value: cgroup_id (__u64) — cgroup ID of the connecting container
 *
 * Written by sockops.bpf.c on BPF_SOCK_OPS_ACTIVE_ESTABLISHED (connect succeeded,
 * full 5-tuple available). Read by proxy_proc via EbpfLoader::lookup_cgroup_by_flow
 * to recover cgroup_id from an accepted TCP connection.
 *
 * LRU hash: kernel auto-evicts least-recently-used entries when full, no manual cleanup.
 * IPv4/IPv6 compatible: family=AF_INET(2) stores IPv4 in first 4 bytes of ip fields;
 * family=AF_INET6(10) stores full 16-byte IPv6 addresses.
 */
struct flow_key {
    __u8  family;       /* AF_INET=2, AF_INET6=10 */
    __u8  protocol;     /* IPPROTO_TCP=6, IPPROTO_UDP=17 */
    __u8  src_ip[16];   /* source IP (IPv4 in first 4 bytes if AF_INET) */
    __u8  dst_ip[16];   /* destination IP (IPv4 in first 4 bytes if AF_INET) */
    __u16 src_port;     /* source port (host byte order) */
    __u16 dst_port;     /* destination port (host byte order) */
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_key);
    __type(value, __u64);
} cgroup_lookup_map SEC(".maps");

#endif
