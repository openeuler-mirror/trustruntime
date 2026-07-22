#!/bin/bash

set -e
set -x

cd "$(dirname "$0")"
[ -d tmp ] && rm -rf tmp
mkdir -p tmp
xz -dkc dep/openEuler.qcow2.xz > tmp/openEuler.qcow2

if ! pgrep -x "libvirtd" > /dev/null; then
    echo "Starting libvirtd..."
    /usr/sbin/libvirtd -d
else
    echo "libvirtd is already running."
fi

export LIBGUESTFS_BACKEND=direct
KERNEL_VERSION=$(virt-ls -a tmp/openEuler.qcow2 /lib/modules)

mkdir -p output
virt-copy-out -a tmp/openEuler.qcow2 /boot/vmlinuz-$KERNEL_VERSION output/
mv output/vmlinuz-$KERNEL_VERSION output/vmlinuz

virt-customize -a tmp/openEuler.qcow2 \
    --network \
    --install tar \
    --install rinetd \
    --append-line /etc/rinetd.conf:"0.0.0.0 34255 127.0.0.1 8799" \
    --run-command 'systemctl enable rinetd' \
    --copy-in input/:/tmp \
    --run-command 'rpm -ivh /tmp/input/*.rpm --nodeps --replacefiles' \
    --run-command "sed -i 's/^PermitRootLogin yes/PermitRootLogin prohibit-password/' /etc/ssh/ssh_config" \
    --touch /root/.ssh/authorized_keys \
    --chmod 0600:/root/.ssh/authorized_keys \
    --run-command 'rm -rf /etc/fstab' \
    --run-command 'rpm -e --nodeps linux-firmware' \
    --delete /tmp

guestfish --ro -a tmp/openEuler.qcow2 run : mount /dev/sda2 / : tar-out / tmp/euler_rootfs.tar.gz compress:gzip

virt-copy-out -a tmp/openEuler.qcow2 /lib/modules/$KERNEL_VERSION/kernel tmp/
find tmp/kernel -type f -name '*.ko.xz' -exec xz -dk {} +

BUSYBOX_SRC=$(rpm2cpio dep/busybox.src.rpm |cpio --quiet -D tmp/ -idmv "*.tar.*" 2>&1)
mkdir -p tmp/busybox
tar -axf tmp/$BUSYBOX_SRC -C tmp/busybox/ --strip-components=1
pushd tmp/busybox/ > /dev/null
make clean
make defconfig
make LDFLAGS="--static"
popd > /dev/null

KERNEL_SRC=$(rpm2cpio dep/kernel.src.rpm |cpio --quiet -D tmp/ -idmv "*.tar.*" 2>&1)
mkdir -p tmp/linux-usr
tar -xzf tmp/$KERNEL_SRC -C tmp/linux-usr/ --strip-components=2 '*/usr'
pushd tmp/linux-usr/ > /dev/null
make gen_init_cpio
chmod 555 gen_init_cpio
popd > /dev/null

tmp/linux-usr/gen_init_cpio ./initrd.list > output/payload.initrd
