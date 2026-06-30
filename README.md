# TrustRuntime

CMS签名验签服务，部署于机密计算虚机中，通过vsock提供签名、验签+签名、验签三类安全接口。

## 架构

```
trustruntime/
├── rust/                    # Cargo workspace
│   ├── framework/           # 通用进程框架 (trustruntime-framework)
│   ├── trustruntime/        # 主程序入口
│   ├── plugins/trustring/   # 签名验签业务插件
│   ├── integration-tests/   # 集成测试
│   ├── tools/cert-gen/      # 测试证书生成工具
│   └── scripts/             # 开发测试脚本
├── docs/                    # 设计文档
│   ├── adr/                 # 架构决策记录
│   ├── detailed-design/     # 详细设计
│   ├── requirements.md      # 需求设计文档
│   ├── interface.md         # 接口文档
│   └── functional-design.md # 功能设计文档
├── conf/                    # 默认配置
├── packaging/               # RPM打包
├── CONTEXT.md               # 术语表
├── AGENTS.md                # Agent指令
└── .opencode/               # opencode配置
```

## 快速开始

### 构建

```bash
cd rust
cargo build --release
```

### 测试

```bash
cd rust
cargo test --workspace
```

### 运行

开发测试：

```bash
cd rust
cargo build --release
./target/release/trustruntime --config ../conf/agent.toml
```

> **Windows用户替代方案**：使用WSL执行上述命令，参见 `.opencode/skills/wsl-cargo/SKILL.md`。

生产部署（RPM安装后）：

```bash
trustruntime --config /etc/trustruntime/agent.toml
```

## 接口

| 类型 | 功能 |
|------|------|
| 0x10→0x11 | 签名：sign(data + 本地证书id) |
| 0x12→0x13 | 验签+签名：先验签，再签名 |
| 0x14→0x15 | 验签：验证签名并判断证书身份 |

## 文档

### 使用者

- [使用指南](docs/user-guide.md) - 安装、配置、运维
- [接口文档](docs/interface.md) - API 参考
- [FAQ](docs/faq.md) - 常见问题

### 开发者

- [开发指南](docs/contributing.md) - 贡献流程、编码规范
- [架构设计](docs/architecture.md) - 系统架构图、数据流
- [详细设计](docs/detailed-design/) - 各模块详细设计
- [架构决策](docs/adr/) - ADR 记录

### 其他

- [需求文档](docs/requirements.md) - 需求规格
- [术语表](CONTEXT.md) - 项目术语
- [变更日志](CHANGELOG.md) - 版本历史
- [示例代码](rust/examples/) - 使用示例

## 部署

参见 [packaging/README.md](packaging/README.md)