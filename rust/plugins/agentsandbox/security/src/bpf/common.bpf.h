#ifndef __COMMON_BPF_H
#define __COMMON_BPF_H

#define MAX_CGROUP_ID_LEN 256

struct security_event {
    __u64 timestamp;
    char cgroup_id[MAX_CGROUP_ID_LEN];
    char event_type[32];
    char operation_detail[128];
    char action[16];
    char result[16];
    char process_name[16];
    __u32 pid;
};

struct bpf_map_def_sec {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[MAX_CGROUP_ID_LEN]);
    __type(value, __u8);
};

#endif
