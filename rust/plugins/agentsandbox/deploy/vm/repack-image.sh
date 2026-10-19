#!/bin/bash
set -euo pipefail

# Repack Kata VM image (raw disk with MBR/GPT partitions) with agentsandbox components.
#
# Handles both:
#   - raw ext4 filesystem image (no partition table)
#   - raw disk image with MBR/GPT partition table (ext4 root partition inside)
#
# Usage:
#   sudo ./repack-image.sh                              # full: build + repack
#   sudo ./repack-image.sh --skip-build                 # skip cargo build
#   sudo ./repack-image.sh --image /path/to.img         # custom source image
#   sudo ./repack-image.sh --output /path/to.img        # custom output path
#   sudo ./repack-image.sh --bin-dir /custom/bin        # custom binary directory
#   sudo ./repack-image.sh --rpm /path/to/pkg.rpm       # install extra rpm(s) into image

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
ROOTFS_DIR="${SCRIPT_DIR}/rootfs"
CA_DIR="${SCRIPT_DIR}/../ca"
CONFIG_DIR="${SCRIPT_DIR}/../configs"

IMAGE="/usr/share/kata-containers/kata-containers.img"
OUTPUT=""
BIN_DIR=""
SKIP_BUILD=0
RPM_FILES=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --image)      IMAGE="$2"; shift 2 ;;
        --output)     OUTPUT="$2"; shift 2 ;;
        --bin-dir)    BIN_DIR="$2"; shift 2 ;;
        --rpm)        RPM_FILES+=("$2"); shift 2 ;;
        --skip-build) SKIP_BUILD=1; shift ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

[ -z "$OUTPUT" ] && OUTPUT="${IMAGE%.*}-new.img"
[ -z "$BIN_DIR" ] && BIN_DIR="${WORKSPACE_DIR}/script/out/bin"

echo "============================================"
echo " Kata VM Image Repack"
echo " Source:    $IMAGE"
echo " Output:    $OUTPUT"
echo " Workspace: $WORKSPACE_DIR"
echo " Skip build: $SKIP_BUILD"
echo "============================================"

# ---- Checks ----

[ "$(id -u)" -eq 0 ] || { echo "ERROR: must run as root (losetup/mount)"; exit 1; }

for cmd in file mount losetup cp chmod mkdir ln e2fsck blockdev; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "ERROR: $cmd not found"; exit 1; }
done

if [ ${#RPM_FILES[@]} -gt 0 ]; then
    for cmd in rpm2cpio cpio; do
        command -v "$cmd" >/dev/null 2>&1 || { echo "ERROR: $cmd not found (required for --rpm)"; exit 1; }
    done
fi

[ -f "$IMAGE" ] || { echo "ERROR: image not found: $IMAGE"; exit 1; }

# ---- Functions ----

LOOP_DEV=""
MOUNT_POINT=""

cleanup() {
    if [ -n "$MOUNT_POINT" ] && mountpoint -q "$MOUNT_POINT" 2>/dev/null; then
        sync
        umount "$MOUNT_POINT" 2>/dev/null || umount -l "$MOUNT_POINT" 2>/dev/null
    fi
    if [ -n "$LOOP_DEV" ]; then
        losetup -d "$LOOP_DEV" 2>/dev/null
    fi
    [ -n "$MOUNT_POINT" ] && rmdir "$MOUNT_POINT" 2>/dev/null
}
trap cleanup EXIT INT TERM

inject_file() {
    local src="$1" dst="$2" mode="${3:-644}"
    local dst_full="$MOUNT_POINT$dst"
    mkdir -p "$(dirname "$dst_full")"
    cp "$src" "$dst_full"
    chmod "$mode" "$dst_full"
    echo "  [inject] $dst ($mode)"
}

inject_dir() {
    mkdir -p "$MOUNT_POINT$1"
    echo "  [mkdir]  $1"
}

inject_symlink() {
    local target="$1" link="$2"
    mkdir -p "$(dirname "$MOUNT_POINT$link")"
    ln -sf "$target" "$MOUNT_POINT$link"
    echo "  [symlink] $link -> $target"
}

detect_format() {
    local img="$1"
    local fmt
    fmt=$(file -b "$img" | head -1)

    if echo "$fmt" | grep -qi "ext4\|ext2\|ext3"; then
        echo "raw-fs"
    elif echo "$fmt" | grep -qi "boot sector\|DOS/MBR\|partition table"; then
        echo "raw-disk"
    else
        local first_byte
        first_byte=$(xxd -l 1 -p "$img" 2>/dev/null)
        if [ "$first_byte" = "fa" ]; then
            echo "raw-disk"
        else
            echo "raw-fs"
        fi
    fi
}

find_root_partition() {
    local loop="$1"
    local part_dev=""
    local largest_size=0

    for part in "${loop}"p*; do
        [ -b "$part" ] || continue
        local size
        size=$(blockdev --getsize64 "$part" 2>/dev/null || echo 0)
        if [ "$size" -gt "$largest_size" ]; then
            largest_size=$size
            part_dev="$part"
        fi
    done

    if [ -z "$part_dev" ]; then
        echo ""
        return 1
    fi
    echo "$part_dev"
}

# ---- [1/6] Verify source image ----

echo ""
echo "[1/6] Verifying source image..."
FORMAT=$(detect_format "$IMAGE")
echo "  Format: $FORMAT"

case "$FORMAT" in
    raw-fs)   echo "  Type: raw filesystem (no partition table)" ;;
    raw-disk) echo "  Type: raw disk image (with partition table)" ;;
    *)        echo "ERROR: unsupported format"; exit 1 ;;
esac

# ---- [2/6] Build binaries ----

if [ "$SKIP_BUILD" -eq 0 ]; then
    echo ""
    echo "[2/6] Building workspace crates..."
    cd "$WORKSPACE_DIR"
    bash script/build.sh
fi

for bin in agentsandbox-controller agentsandbox-hook agentsandbox-proxy; do
    [ -f "$BIN_DIR/$bin" ] || { echo "ERROR: $bin not found in $BIN_DIR"; exit 1; }
done
echo "  Binaries ready"

# ---- [3/6] Copy image ----

echo ""
echo "[3/6] Copying image..."
cp "$IMAGE" "$OUTPUT"
echo "  Copied to $OUTPUT ($(du -h "$OUTPUT" | cut -f1))"

# ---- [4/6] Mount image ----

echo ""
echo "[4/6] Mounting image..."
MOUNT_POINT=$(mktemp -d)

if [ "$FORMAT" = "raw-disk" ]; then
    LOOP_DEV=$(losetup -P --find --show "$OUTPUT")
    echo "  Loop device: $LOOP_DEV (with partition scan)"

    sleep 2

    ROOT_PART=$(find_root_partition "$LOOP_DEV")
    if [ -z "$ROOT_PART" ]; then
        echo "ERROR: no partition found"
        ls -la "${LOOP_DEV}"*
        exit 1
    fi
    echo "  Root partition: $ROOT_PART ($(blockdev --getsize64 "$ROOT_PART" | numfmt --to=iec 2>/dev/null || echo "?"))"

    # Check and fix filesystem before mounting (replay journal, fix errors)
    echo "  Running e2fsck before mount..."
    e2fsck -f -y "$ROOT_PART" 2>&1 | sed 's/^/    /' || true

    mount -t ext4 -o rw "$ROOT_PART" "$MOUNT_POINT"
else
    LOOP_DEV=$(losetup --find --show "$OUTPUT")
    echo "  Loop device: $LOOP_DEV"

    echo "  Running e2fsck before mount..."
    e2fsck -f -y "$LOOP_DEV" 2>&1 | sed 's/^/    /' || true

    mount -t ext4 -o rw "$LOOP_DEV" "$MOUNT_POINT"
fi

echo "  Mount point: $MOUNT_POINT"

# Verify mount succeeded
if [ ! -d "$MOUNT_POINT/usr" ] && [ ! -d "$MOUNT_POINT/etc" ]; then
    echo "WARN: /usr and /etc not found in mounted image"
    echo "  Contents:"
    ls -la "$MOUNT_POINT/" | head -20
fi

# Check available space
AVAIL_KB=$(df -k "$MOUNT_POINT" | tail -1 | awk '{print $4}')
echo "  Available space: ${AVAIL_KB} KB"

# Calculate binary sizes
BIN_SIZE_KB=0
for bin in agentsandbox-controller agentsandbox-hook agentsandbox-proxy; do
    sz=$(du -k "$BIN_DIR/$bin" | cut -f1)
    BIN_SIZE_KB=$((BIN_SIZE_KB + sz))
done
echo "  Binary sizes: ${BIN_SIZE_KB} KB"

if [ "$AVAIL_KB" -lt "$BIN_SIZE_KB" ]; then
    echo "ERROR: insufficient space (available=${AVAIL_KB}KB, needed=${BIN_SIZE_KB}KB)"
    echo "  Resize the image first:"
    echo "    dd if=/dev/zero bs=1M count=500 >> $OUTPUT"
    echo "    losetup -c $LOOP_DEV"
    echo "    resize2fs ${ROOT_PART:-$LOOP_DEV}"
    exit 1
fi

# ---- [5/6] Inject files ----

echo ""
echo "[5a/6] Injecting files..."

inject_dir /usr/bin
inject_dir /etc/agentsandbox
inject_dir /etc/agentsandbox/configs
inject_dir /etc/systemd/system
inject_dir /etc/systemd/system/basic.target.wants
inject_dir /var/log/agentsandbox
inject_dir /run/agentsandbox
inject_dir /etc/ssl/certs

inject_file "$BIN_DIR/agentsandbox-controller" /usr/bin/agentsandbox-controller 755
inject_file "$BIN_DIR/agentsandbox-hook"       /usr/bin/agentsandbox-hook       755
inject_file "$BIN_DIR/agentsandbox-proxy"      /usr/bin/agentsandbox-proxy      755

if [ -f "$CA_DIR/ca.crt" ]; then
    inject_file "$CA_DIR/ca.crt" /etc/agentsandbox/ca.crt 644
fi
if [ -f "$CA_DIR/ca.key" ]; then
    inject_file "$CA_DIR/ca.key" /etc/agentsandbox/ca.key 600
fi

if [ -f "$ROOTFS_DIR/agentsandbox.env" ]; then
    inject_file "$ROOTFS_DIR/agentsandbox.env" /etc/agentsandbox/agentsandbox.env 644
fi

if [ -f "$ROOTFS_DIR/agentsandbox.service" ]; then
    inject_file "$ROOTFS_DIR/agentsandbox.service"   /etc/systemd/system/agentsandbox.service   644
fi
if [ -f "$ROOTFS_DIR/proxy.service" ]; then
    inject_file "$ROOTFS_DIR/proxy.service"          /etc/systemd/system/proxy.service          644
fi
if [ -f "$ROOTFS_DIR/run-agentsandbox.mount" ]; then
    inject_file "$ROOTFS_DIR/run-agentsandbox.mount" /etc/systemd/system/run-agentsandbox.mount 644
fi

inject_symlink /etc/systemd/system/agentsandbox.service   /etc/systemd/system/basic.target.wants/agentsandbox.service
inject_symlink /etc/systemd/system/proxy.service          /etc/systemd/system/basic.target.wants/proxy.service
inject_symlink /etc/systemd/system/run-agentsandbox.mount /etc/systemd/system/basic.target.wants/run-agentsandbox.mount

if [ -d "$CONFIG_DIR" ]; then
    for toml in "$CONFIG_DIR"/*.toml; do
        [ -f "$toml" ] && inject_file "$toml" "/etc/agentsandbox/configs/$(basename "$toml")" 644
    done
else
    cat > "$MOUNT_POINT/etc/agentsandbox/configs/default.toml" << 'EOF'
version = 1
[proxy]
default_action = "block"
audit_enabled = true
policy_change_strategy = "drain"
max_connection_lifetime = 300
[[proxy.rulesets]]
name = "default"
host = { type = "host", context = "*", priv = 0 }
targetrules = [
  { method = "*", path = "*", action = "allow" },
]
binaryrules = []
[security]
enforcement_mode = "alert"
default_action = "allow"
EOF
    echo "  [create] /etc/agentsandbox/configs/default.toml"
fi

# ---- [5b/6] Install extra RPM packages ----

if [ ${#RPM_FILES[@]} -gt 0 ]; then
    echo "[5b/6] Install extra RPM packages..."
    for rpm_file in "${RPM_FILES[@]}"; do
        [ -f "$rpm_file" ] || { echo "ERROR: rpm not fount: $rpm_file"; exit 1; }
        echo "  [rpm] $rpm_file"
        rpm2cpio "$rpm_file" | (cd "$MOUNT_POINT" && cpio -idmv --no-absolute-filenames)
    done
    ldconfig -r $MOUNT_POINT
fi

# ---- [6/6] Unmount, fix filesystem, verify ----

echo ""
echo "[6/6] Unmounting and verifying..."

# Sync all writes to disk
sync

# Unmount
umount "$MOUNT_POINT"
MOUNT_POINT_CLEAN="yes"

# Run e2fsck after unmount to ensure clean filesystem state
echo "  Running e2fsck after unmount..."
if [ -n "${ROOT_PART:-}" ]; then
    e2fsck -f -y "$ROOT_PART" 2>&1 | sed 's/^/    /' || true
else
    e2fsck -f -y "$LOOP_DEV" 2>&1 | sed 's/^/    /' || true
fi

# Detach loop device
losetup -d "$LOOP_DEV"
LOOP_DEV=""
rmdir "$MOUNT_POINT" 2>/dev/null
MOUNT_POINT=""

echo ""
echo "============================================"
echo " Repack complete"
echo "   Source:  $IMAGE ($(du -h "$IMAGE" | cut -f1))"
echo "   Output:  $OUTPUT ($(du -h "$OUTPUT" | cut -f1))"
echo "   Format:  $FORMAT"
echo "============================================"
echo ""
echo "To deploy:"
echo "  sudo cp $OUTPUT $IMAGE"
echo "  sudo systemctl restart containerd"
echo ""
echo "To verify:"
echo "  file $OUTPUT"
echo "  sudo losetup -P --find --show $OUTPUT"
echo "  sudo mount /dev/loopNp1 /mnt && ls /mnt/usr/bin/agentsandbox-*"
echo "  sudo umount /mnt && sudo losetup -d /dev/loopN"
