# TrustRuntime 部署

## RPM安装（推荐）

RPM安装会自动完成以下步骤：

```bash
rpm -ivh trustruntime-*.rpm
# 自动：复制二进制、安装配置模板、创建日志目录、安装systemd服务
```

安装完成后，需修改配置文件，然后手动启动服务：

```bash
systemctl enable trustruntime
systemctl start trustruntime
```

## 查看状态

```bash
systemctl status trustruntime
```

## 证书更新后重启

```bash
systemctl restart trustruntime
```