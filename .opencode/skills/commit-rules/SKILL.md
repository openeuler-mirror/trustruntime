---
name: commit-rules
description: 强制执行 Conventional Commits 格式和 PR 拆分原则。在创建提交、编写提交信息、规划 PR 或用户提及 "commit"、"PR"、"提交" 时使用。
---

# 提交规则

## 提交信息格式

```
<type>: <标题（英文）>

<描述（中文）>

Code-Owner: <邮箱>
Co-Authored-By: glm-5 (alibaba-cn)
```

## 类型关键字 (Conventional Commits)

| 类型 | 用途 |
|------|------|
| `feat` | 新功能 |
| `fix` | 修复问题 |
| `test` | 测试用例 |
| `docs` | 文档 |
| `refactor` | 重构 |
| `chore` | 构建/配置/杂项 |
| `style` | 代码风格 |
| `perf` | 性能优化 |

## PR 拆分原则

1. **每个 PR 包含**：相关文档 + 代码 + 单元测试
2. **文档先行**：PR 描述中引用设计文档
3. **依赖顺序**：底层模块先提交
4. **编译保证**：每次提交都能编译通过

## 示例

```
feat: add CMS signing implementation

使用 OpenSSL ECC-256 算法实现 CMS 签名功能。

功能特性：
- 使用本地证书签名数据
- 提取 Subject Key ID 作为证书标识
- 支持 PEM/DER 格式证书

依赖模块：
- trustruntime-framework/cert
- trustruntime-framework/message

Code-Owner: your_name@example.com
Co-Authored-By: glm-5 (alibaba-cn)
```

## 检查清单

提交前检查：
- [ ] 使用正确的类型关键字
- [ ] 标题简洁（50字符以内），使用英文
- [ ] 描述清晰说明"做了什么"和"为什么"，使用中文
- [ ] 指定 Code-Owner
- [ ] 添加 Co-Authored-By
- [ ] 包含相关文档（如适用）
- [ ] 包含测试（如适用）
- [ ] 代码可编译