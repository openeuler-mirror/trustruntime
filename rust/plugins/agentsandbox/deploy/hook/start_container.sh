#!/bin/bash
set -e

# startContainer hook: called by OCI runtime on container start.
# 1. Get cgroup_id and config_path
# 2. Notify HiController via Unix socket (cgroup_id + config_path)
# 3. Read pre-made CA certificate from local path
# 4. Write CA to container trust chain

CONFIG_PATH="$1"
CGROUP_ID="$(cat /proc/self/cgroup | head -1 | cut -d: -f3)"

HC_SOCK="/var/run/agentsandbox/hc.sock"
CA_CERT_PATH="/etc/agentsandbox/ca.crt"

echo "startContainer hook: cgroup_id=${CGROUP_ID}"

# Notify HiController
echo "{\"msg_type\":\"register\",\"payload\":{\"cgroup_id\":\"${CGROUP_ID}\",\"config_path\":\"${CONFIG_PATH}\"},\"request_id\":\"hook-$$\"}" | \
    socat - UNIX-CONNECT:"${HC_SOCK}"

# Read pre-made CA and write to container trust chain
if [ -f "${CA_CERT_PATH}" ]; then
    mkdir -p /etc/ssl/certs/agentsandbox/
    cp "${CA_CERT_PATH}" /etc/ssl/certs/agentsandbox/ca.crt
    update-ca-certificates 2>/dev/null || true
fi

exit 0
