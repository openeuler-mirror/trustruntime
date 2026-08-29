#!/bin/bash
set -e

# stopContainer hook: called by OCI runtime on container stop.
# 1. Get cgroup_id
# 2. Notify HiController to remove BPF map entry and cgroup_id→group_id mapping

CGROUP_ID="$(cat /proc/self/cgroup | head -1 | cut -d: -f3)"
HC_SOCK="/var/run/agentsandbox/hc.sock"

echo "stopContainer hook: cgroup_id=${CGROUP_ID}"

echo "{\"msg_type\":\"unregister\",\"payload\":{\"cgroup_id\":\"${CGROUP_ID}\"},\"request_id\":\"hook-$$\"}" | \
    socat - UNIX-CONNECT:"${HC_SOCK}"

exit 0
