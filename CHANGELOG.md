# Changelog

All notable changes to TrustRuntime will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- 文档补充：
  - `docs/user-guide.md` - 使用指南（安装/配置/运维）
  - `docs/contributing.md` - 开发指南（贡献流程/编码规范）
  - `docs/faq.md` - FAQ 常见问题
  - `docs/architecture.md` - 架构设计（系统架构图、数据流图、时序图）

---

## [0.1.0] - 2026-06-XX

### Added

- 核心功能
  - 签名接口 (0x10→0x11)：CMS 签名，ECC-256 算法
  - 验签+签名接口 (0x12→0x13)：先验签再签名
  - 验签接口 (0x14→0x15)：验签并判断证书身份

- 通信层
  - TLS over vsock 双向认证
  - OpenSSL SslAcceptor（TLS 1.2/1.3）
  - 并发连接限流（Semaphore，最大 16 连接）
  - 报文格式校验（version、len、size）

- 证书管理
  - PEM/DER 双格式自动识别
  - 证书链校验
  - CRL 校验（可选）
  - 证书过期定时巡检（每 24h）

- 进程管理
  - systemd 服务托管
  - sd_notify 协议（READY/STOPPING）
  - SIGTERM/SIGINT 信号处理
  - 优雅关闭（5s 超时）

- 打包部署
  - RPM 打包支持
  - systemd unit 配置
  - 资源限制（CPU 10%，Memory 30M）

- 框架设计
  - Plugin trait 插件抽象
  - TransportLayer trait 通信抽象
  - DataHandler trait 业务处理
  - Cargo workspace 项目结构

- 错误处理
  - 统一结果码体系（ADR-0001）
  - OpenSSL ErrorStack 映射
  - Handler panic recovery

- 日志系统
  - log4rs 实现
  - 日志滚动（10MB，10 个文件）
  - gzip 归档
  - 权限控制（0o440）

- 文档
  - `CONTEXT.md` - 术语表
  - `docs/interface.md` - 接口文档
  - `docs/requirements.md` - 需求文档
  - `docs/functional-design.md` - 功能设计
  - `docs/detailed-design/` - 详细设计（7 个模块）
  - `docs/adr/` - 架构决策记录（8 个 ADR）

- 测试
  - 单元测试
  - 集成测试
  - 测试证书生成工具（cert-gen）
  - 集成测试脚本（run-integration-tests.sh）

### Architecture Decisions

- ADR-0001: 统一结果码编码
- ADR-0002: CMS 库选型（OpenSSL）
- ADR-0003: 插件集成模式
- ADR-0004: 统一 OpenSSL 用于 TLS 和 CMS
- ADR-0005: TransportLayer 抽象
- ADR-0006: systemd 服务配置
- ADR-0007: 错误码扩展机制
- ADR-0008: 测试架构

---

## 版本说明

### 版本号规则

- **MAJOR**: 不兼容的 API 变化
- **MINOR**: 向后兼容的功能新增
- **PATCH**: 向后兼容的 Bug 修复

### 变更类型

- **Added**: 新功能
- **Changed**: 功能变更
- **Deprecated**: 即将移除的功能
- **Removed**: 已移除的功能
- **Fixed**: Bug 修复
- **Security**: 安全相关修复