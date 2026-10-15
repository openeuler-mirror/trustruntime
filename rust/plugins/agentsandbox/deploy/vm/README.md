# repack-image.sh — Kata VM Image Repack

`repack-image.sh` 把 AgentSandbox 组件（二进制、CA、systemd 单元、配置）打包进 Kata VM 镜像（`kata-containers.img`），生成可直接部署的新镜像。

## 概述

脚本做的事：

1. 识别源镜像格式（裸 ext4 文件系统 / 带 MBR/GPT 分区表的整盘镜像）。
2. （可选）调用 `script/build.sh` 编译工作区 crate。
3. 拷贝源镜像到输出路径。
4. 通过 `losetup` + `e2fsck` + `mount` 挂载镜像。
5. 注入二进制、CA、环境变量、systemd 单元、策略配置。
6. （可选）把额外 RPM 包解包进镜像。
7. 卸载、`e2fsck` 校验、输出结果。

## 前置条件

- **必须以 root 运行**（需要 `losetup`/`mount`）。
- 系统工具：`file mount losetup cp chmod mkdir ln e2fsck blockdev`。
- 使用 `--rpm` 时额外需要：`rpm2cpio cpio`。

## 用法

```bash
cd deploy/vm

sudo ./repack-image.sh                              # 完整：编译 + 打包
sudo ./repack-image.sh --skip-build                 # 跳过 cargo 编译（使用已有产物）
sudo ./repack-image.sh --image /path/to/source.img  # 指定源镜像
sudo ./repack-image.sh --output /path/to/out.img    # 指定输出路径
sudo ./repack-image.sh --bin-dir /custom/bin        # 指定二进制目录
sudo ./repack-image.sh --rpm /path/to/pkg.rpm       # 额外注入 rpm 包（可多次指定）
```

## 选项

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `--image <path>` | `/usr/share/kata-containers/kata-containers.img` | 源镜像 |
| `--output <path>` | `<源镜像去掉 .img>-new.img` | 输出镜像 |
| `--bin-dir <path>` | `<workspace>/script/out/bin` | 二进制目录 |
| `--rpm <path>` | 无 | 额外 RPM 包，可重复 |
| `--skip-build` | 关闭 | 跳过编译步骤 |

## 注入内容

| 来源 | 镜像内位置 | 权限 |
|------|-----------|------|
| `$BIN_DIR/agentsandbox-controller` | `/usr/bin/agentsandbox-controller` | 755 |
| `$BIN_DIR/agentsandbox-hook` | `/usr/bin/agentsandbox-hook` | 755 |
| `$BIN_DIR/agentsandbox-proxy` | `/usr/bin/agentsandbox-proxy` | 755 |
| `deploy/ca/ca.crt`（若存在） | `/etc/agentsandbox/ca.crt` | 644 |
| `deploy/ca/ca.key`（若存在） | `/etc/agentsandbox/ca.key` | 600 |
| `rootfs/agentsandbox.env`（若存在） | `/etc/agentsandbox/agentsandbox.env` | 644 |
| `rootfs/agentsandbox.service` | `/etc/systemd/system/agentsandbox.service` | 644 |
| `rootfs/proxy.service` | `/etc/systemd/system/proxy.service` | 644 |
| `rootfs/run-agentsandbox.mount` | `/etc/systemd/system/run-agentsandbox.mount` | 644 |
| `deploy/configs/*.toml` | `/etc/agentsandbox/configs/<name>.toml` | 644 |

三个 systemd 单元还会被软链接到 `basic.target.wants/` 下以开机自启。若 `deploy/configs` 无 TOML 文件，脚本会生成一个默认的 `default.toml`（proxy 全 allow、security alert）。

## 空间不足

挂载后脚本会对比剩余空间与二进制大小，空间不足时报错并提示扩容方法：

```bash
dd if=/dev/zero bs=1M count=500 >> <output.img>
losetup -c <loopdev>
resize2fs <root-partition-or-loopdev>
```

## 部署

打包完成后：

```bash
sudo cp <output.img> /usr/share/kata-containers/kata-containers.img
sudo systemctl restart containerd
```

## 验证

```bash
file <output.img>
sudo losetup -P --find --show <output.img>
sudo mount /dev/loopNp1 /mnt && ls /mnt/usr/bin/agentsandbox-*
sudo umount /mnt && sudo losetup -d /dev/loopN
```

## 相关脚本

- `build-vm.sh`：配置 guest 内核选项（BPF LSM + BTF + virtio-fs），准备 rootfs。
- `../kata/README.md`：Kata + K8s 部署的整体流程与 hook 说明。
