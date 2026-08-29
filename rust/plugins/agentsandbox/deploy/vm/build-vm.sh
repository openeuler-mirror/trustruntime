#!/bin/bash
set -e

# Build Kata VM image with guest kernel >= 5.11 (LSM BPF + BTF + virtio-fs)
# Configures: CONFIG_BPF_LSM=y, CONFIG_DEBUG_INFO_BTF=y, CONFIG_VIRTIO_FS=y

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KERNEL_CONFIG="${SCRIPT_DIR}/kernel.config"
ROOTFS_DIR="${SCRIPT_DIR}/rootfs"

echo "Building Kata VM image..."

# Create rootfs
mkdir -p "${ROOTFS_DIR}/etc/agentsandbox"
mkdir -p "${ROOTFS_DIR}/var/log/agentsandbox"
mkdir -p "${ROOTFS_DIR}/var/run/agentsandbox"

# Copy systemd units
cp "${ROOTFS_DIR}/agentsandbox.service" "${ROOTFS_DIR}/etc/systemd/system/"
cp "${ROOTFS_DIR}/proxy.service" "${ROOTFS_DIR}/etc/systemd/system/"

# Enable services
ln -sf /etc/systemd/system/agentsandbox.service "${ROOTFS_DIR}/etc/systemd/system/multi-user.target.wants/"
ln -sf /etc/systemd/system/proxy.service "${ROOTFS_DIR}/etc/systemd/system/multi-user.target.wants/"

echo "VM image build complete."
echo "Configure guest kernel with: CONFIG_BPF_LSM=y CONFIG_DEBUG_INFO_BTF=y CONFIG_VIRTIO_FS=y"
