# Systemd Service Configuration

TrustRuntime 作为长期运行的后台服务，需要 systemd 管理。我们决定在 `packaging/` 目录提供 `trustruntime.service` 模板，使用 `Type=notify` 与代码中的 `sd_notify` 配合，让 systemd 正确感知服务启动状态。服务以 root 运行，通过 systemd 安全选项限制权限。

## Status

accepted

## Considered Options

- **方案 A: 不提供 service 文件** — 用户自行配置，易出错且无标准可循
- **方案 B: Type=simple** — 忽略 sd_notify，systemd 无法准确感知服务就绪时机
- **方案 C: Type=notify + 配套 service 文件（选定）** — systemd 正确感知服务状态，提供完整部署模板

## Decisions

### 发布物范围

提供二进制 + `packaging/trustruntime.service` 模板，不含安装脚本。运维可根据环境调整。

### 路径配置

全部硬编码：`/usr/bin/trustruntime`、`/etc/trustruntime/agent.toml`、`/var/log/trustruntime/`。与 CONTEXT.md 约定一致。

### 服务依赖

`After=network.target`：vsock 是本地通信机制，仅需网络栈初始化，不需等待网络连接。

### 类型与超时

- `Type=notify`：进程通过 sd_notify 发送 READY=1
- `TimeoutStartSec=30s`：启动流程简单，30s 充足
- `TimeoutStopSec=10s`：与代码 5s 关闭超时对齐

### 重启策略

- `Restart=on-failure`：仅异常退出时重启
- `RestartPreventExitStatus=1`：启动失败（exit 1）不重启，避免循环
- `RestartSec=5`：重启间隔

### 资源限制

`CPUQuota=10%`, `MemoryMax=30M`：限制资源占用。

### 安全加固

- `ProtectSystem=strict`：只读系统目录
- `ReadWritePaths=/var/log/trustruntime`：仅允许日志目录写入
- `NoNewPrivileges=yes`：禁止提权

### 日志配置

`StandardOutput=null`, `StandardError=null`：log4rs 已处理日志，避免 journal 冗余。

### 状态通知

代码新增 `notify_status()` 方法，通信证书过期时调用 `daemon.notify_status("通信证书已过期")`，显示在 `systemctl status` 输出中。

## Consequences

- `packaging/trustruntime.service` 作为部署模板，用户复制到 `/etc/systemd/system/`
- `packaging/README.md` 提供安装说明
- daemon.rs 需新增 `notify_status()` 方法
- 设计文档 06-process-lifecycle.md 已更新 notify_status API 和启动行为