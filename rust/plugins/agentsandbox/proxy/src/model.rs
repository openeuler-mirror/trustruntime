/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

//! 过滤策略数据结构与共享契约类型（filter_config v1.2、K3 决策、K4 审计条目）。
//!
//! 契约来源：SR-design §3.2.2 / 模块详细设计说明书 4.1.3（K5 入参类型、
//! Action/Reason 常量）与 AR-003 AR-clarify §2.3.1（audit_log_entry 11 字段）。
//! proxy 只接收已解析结构，不解析 TOML（config 库在 HC/集成方进程）。

use serde::{Deserialize, Serialize};

/// 默认策略：无规则匹配时的决策。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Policy {
    /// 允许。
    Allow,
    /// 拒绝。
    Deny,
    /// 告警（2026-09-09）：黑白名单均未命中时——流量**放行** +
    /// 审计条目标记告警（`AuditLogEntry::entry_type = Alert`）。
    Alert,
}

/// 求值决策动作（K3 契约常量："allow" / "deny"）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// 允许（转发）。
    Allow,
    /// 拒绝（关闭）。
    Deny,
}

/// 决策原因枚举（K3 契约常量，说明书 4.1.3；serde 值与审计 JSON 一致）。
///
/// 覆盖求值命中（whitelist/blacklist/default）、配置关联失败（config/group_id
/// not_found）、证书（ca/cert_error）、审计（log_write_error）、目标出站三类
///（target_tls_error/connection_refused/connection_timeout）、binary 身份缺失
///（binary_not_found）、推理路由命中（inference_route——旁通过滤引擎的三态
/// 决策均以此 reason 记审计）与目标 IP 预解析失败（dns_resolve_error——
/// fail-closed，2026-09-09）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    WhitelistMatch,
    BlacklistMatch,
    DefaultPolicy,
    ConfigNotFound,
    GroupIdNotFound,
    CaError,
    CertError,
    LogWriteError,
    TargetTlsError,
    ConnectionRefused,
    ConnectionTimeout,
    BinaryNotFound,
    InferenceRoute,
    DnsResolveError,
}

/// 规则动作（2026-09-16 结构重设计）：deny=黑名单阻断 / alert=黑名单
/// 告警（放行 + 审计标记 type=1）/ allow=白名单放行。
///
/// `deny` 接受别名 `"block"`（HC 侧安全模块术语——TOML 形态兼容）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    /// 黑名单阻断（403 + 审计 deny）。
    #[serde(alias = "block")]
    Deny,
    /// 黑名单告警（放行 + 审计 type=1——不阻断）。
    Alert,
    /// 白名单放行。
    Allow,
}

/// 规则集主机匹配类型：ip（目标 IP/CIDR）/ host（域名通配）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HostType {
    /// 按 DNS 预解析的目标 IP 匹配 `addr`（精确或 CIDR；任一命中即命中）。
    Ip,
    /// 按请求域名（SNI/Host 头）匹配 `context`（单星 glob，大小写不敏感）。
    Host,
}

/// 规则集主机匹配条件（`{type, addr?, context?, prio}`）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostRule {
    /// 匹配类型（TOML 字段名 `type`）。
    #[serde(rename = "type")]
    pub host_type: HostType,
    /// type=ip：目标 IP 或 CIDR（如 `169.254.169.254` / `10.0.0.0/8`）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addr: Option<String>,
    /// type=host：域名通配（如 `*.trusted.com`）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    /// 优先级（**越大越优先**——rule_list 按 prio 降序求值）。
    pub prio: u32,
}

/// 目标规则（method + path → action）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetRule {
    /// HTTP 方法（单星 glob，大小写敏感：`GET` / `*` / `G*T`）。
    pub method: String,
    /// 请求路径（单星 glob，不含 query：`/v1/*` / `*`）。
    pub path: String,
    /// 命中动作。
    pub action: RuleAction,
}

/// binary 规则（进程路径 → action）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryRule {
    /// 进程二进制路径（单星 glob：`/usr/bin/curl` / `*`）。
    pub path: String,
    /// 命中动作（allow = 透传——继续匹配 targetrules）。
    pub action: RuleAction,
}

/// 规则集（rule_list 元素——2026-09-16 结构重设计，替代原
/// whitelist/blacklist 平铺条目）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleSet {
    /// 规则集名（非空——观测/审计定位）。
    pub name: String,
    /// 主机匹配条件（含 prio 优先级）。
    pub host: HostRule,
    /// 目标规则（method+path → action）。
    #[serde(default)]
    pub targetrules: Vec<TargetRule>,
    /// binary 规则（进程路径 → action；allow 透传）。
    #[serde(default)]
    pub binaryrules: Vec<BinaryRule>,
    /// 目标端口约束（Some 时仅匹配该端口；None 任意端口）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

/// 过滤策略配置（单份结构，交付通道区分两场景）。
///
/// 求值顺序（2026-09-16）：rule_list 按 `host.prio` **降序**链式遍历——
/// 首个主机匹配的规则集内先 binaryrules 后 targetrules（各按
/// deny>alert>allow 排序），**首个规则命中即决策**；规则集内未命中则
/// 继续下一规则集；全部未命中走 `default_policy`。排序由
/// [`crate::registry::Registry::set_container_config`] 存储时归一化。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterConfig {
    /// 无规则命中时默认策略。
    pub default_policy: Policy,
    /// 规则集列表（按 host.prio 降序求值）。
    #[serde(default)]
    pub rule_list: Vec<RuleSet>,
}

/// 求值决策（K3 契约返回——2026-09-16 起 evaluate 返回此结构）。
///
/// `alert`：告警标记（alert 规则命中或 default_policy=alert）——审计
/// 条目 type=1（放行 + 告警）；action 恒为真实流量动作（allow/deny）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    /// 流量动作（allow=转发 / deny=阻断）。
    pub action: Action,
    /// 决策原因（审计 reason）。
    pub reason: Reason,
    /// 告警标记（审计条目 type=1）。
    pub alert: bool,
}

impl FilterConfig {
    /// 是否存在 binary 维度条件（任一规则集声明 binaryrules）。
    ///
    /// 服务管道的条件性判定点：无 binary 条件不触发 binary_not_found
    /// fail-closed；有 binaryrules 且 binary_path 未解析 → 拒绝。
    pub fn has_binary_condition(&self) -> bool {
        self.rule_list.iter().any(|rs| !rs.binaryrules.is_empty())
    }

    /// 是否存在目标 IP 维度条件（任一规则集 host.type=ip）。
    ///
    /// 服务管道的条件性判定点（与 binary 维度同模式）：仅含 IP 条件的
    /// 配置才触发 DNS 预解析（无 IP 条件零解析开销）；解析失败
    /// fail-closed（`Reason::DnsResolveError`）。
    pub fn has_ip_condition(&self) -> bool {
        self.rule_list
            .iter()
            .any(|rs| rs.host.host_type == HostType::Ip)
    }
}

/// 审计条目类型（协议字段 `type`：0=审计 / 1=告警；serde 数值映射）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
#[serde(into = "u8", try_from = "u8")]
pub enum AuditEntryType {
    /// 0：审计条目（常规）。
    #[default]
    Audit = 0,
    /// 1：告警条目——default_policy=alert 且黑白名单均未命中时放行的
    /// 流量（2026-09-09）。
    Alert = 1,
}

impl From<AuditEntryType> for u8 {
    fn from(t: AuditEntryType) -> Self {
        t as u8
    }
}

impl TryFrom<u8> for AuditEntryType {
    type Error = &'static str;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(Self::Audit),
            1 => Ok(Self::Alert),
            _ => Err("audit entry type out of range (0/1)"),
        }
    }
}

/// 审计日志条目（AR-003 AR-clarify §2.3.1；AR-001 组装、K4 传递；
/// 2026-09-09 扩展 type 字段——12 字段）。
///
/// `status_code`：目标响应码，拒绝路径为 0；`source_ip`（场景一容器源 IP）与
/// `target_ip` 可空（`None` 序列化为 null，不省略字段）；`entry_type`：
/// 0=审计 / 1=告警（旧条目无该字段时反序列化为 Audit——向后兼容）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditLogEntry {
    /// UTC ISO-8601（秒精度，如 `2026-08-26T01:42:59Z`）。
    pub timestamp: String,
    /// 容器标识（监听端点绑定的 container_id——2026-09-01 API 重设计）。
    pub container_id: String,
    /// 审计场景标识："kata" / "lib"。
    pub scenario: String,
    /// SNI 域名。
    pub domain: String,
    /// 请求路径（不含 query string）。
    pub url_path: String,
    /// HTTP 方法。
    pub method: String,
    /// 目标响应码；拒绝路径为 0。
    pub status_code: u16,
    /// 决策动作。
    pub action: Action,
    /// 决策原因。
    pub reason: Reason,
    /// 场景一容器源 IP；场景二可空。
    pub source_ip: Option<String>,
    /// 目标 IP；连接未建立（拒绝）时可空。
    pub target_ip: Option<String>,
    /// 条目类型（协议字段 type：0=审计 / 1=告警）。
    #[serde(rename = "type", default)]
    pub entry_type: AuditEntryType,
}

/// 审计场景标识常量（K4："kata" 场景一 / "lib" 场景二）。
///
/// 消费方（管道 binary 门控、审计 entry 组装）统一引用常量，防裸字符串
/// typo 静默旁路场景语义（如 binary fail-closed）。
pub const SCENARIO_KATA: &str = "kata";
/// 场景二（lib 集成）场景标识。
pub const SCENARIO_LIB: &str = "lib";

/// 生成 UTC ISO-8601 时间戳（秒精度，无外部时间库依赖）。
pub fn utc_now_iso8601() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    iso8601_from_unix(secs)
}

/// 纪元秒 → UTC ISO-8601（秒精度；公历民用日期经 civil_from_days 算法换算）。
fn iso8601_from_unix(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // 公历民用日期（Howard Hinnant civil_from_days 算法）。
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mth = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mth <= 2 { y + 1 } else { y };
    format!("{y:04}-{mth:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(binaryrules: u32) -> FilterConfig {
        let mk_ruleset = |binaryrules: u32| RuleSet {
            name: "rs".to_string(),
            host: HostRule {
                host_type: HostType::Host,
                addr: None,
                context: Some("a.com".to_string()),
                prio: 100,
            },
            targetrules: vec![TargetRule {
                method: "*".to_string(),
                path: "*".to_string(),
                action: RuleAction::Allow,
            }],
            binaryrules: (0..binaryrules)
                .map(|_| BinaryRule {
                    path: "*".to_string(),
                    action: RuleAction::Deny,
                })
                .collect(),
            port: None,
        };
        FilterConfig {
            default_policy: Policy::Deny,
            rule_list: vec![mk_ruleset(binaryrules)],
        }
    }

    // has_binary_condition 判定面（条件性触发的生产判定点——2026-09-16
    // 新语义：任一规则集声明 binaryrules）。
    #[test]
    fn has_binary_condition_rulesets() {
        assert!(!entry(0).has_binary_condition());
        assert!(entry(1).has_binary_condition());
        assert!(entry(3).has_binary_condition());
        // 空列表。
        assert!(!FilterConfig {
            default_policy: Policy::Deny,
            rule_list: vec![],
        }
        .has_binary_condition());
    }

    // has_ip_condition 判定面（新语义：任一规则集 host.type=ip → 触发
    // DNS 预解析）。
    #[test]
    fn has_ip_condition_host_type() {
        let mk = |host_type: HostType| FilterConfig {
            default_policy: Policy::Deny,
            rule_list: vec![RuleSet {
                name: "rs".to_string(),
                host: HostRule {
                    host_type,
                    addr: Some("10.0.0.1".to_string()),
                    context: Some("a.com".to_string()),
                    prio: 100,
                },
                targetrules: vec![],
                binaryrules: vec![],
                port: None,
            }],
        };
        assert!(mk(HostType::Ip).has_ip_condition());
        assert!(!mk(HostType::Host).has_ip_condition());
        // 空列表。
        assert!(!FilterConfig {
            default_policy: Policy::Deny,
            rule_list: vec![],
        }
        .has_ip_condition());
    }

    // 规则结构 serde：JSON（UDS refresh_policy 通道）往返 + block 别名 +
    // port 预留字段透传。
    #[test]
    fn ruleset_serde_roundtrip() {
        let fc = FilterConfig {
            default_policy: Policy::Deny,
            rule_list: vec![RuleSet {
                name: "block-metadata-service".to_string(),
                host: HostRule {
                    host_type: HostType::Ip,
                    addr: Some("169.254.169.254".to_string()),
                    context: None,
                    prio: 50,
                },
                targetrules: vec![TargetRule {
                    method: "*".to_string(),
                    path: "*".to_string(),
                    action: RuleAction::Deny,
                }],
                binaryrules: vec![BinaryRule {
                    path: "*".to_string(),
                    action: RuleAction::Deny,
                }],
                port: Some(8843),
            }],
        };
        let json = serde_json::to_string(&fc).unwrap();
        let back: FilterConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, fc);
        assert!(json.contains("\"type\":\"ip\""));
        assert!(json.contains("\"prio\":50"));
        assert!(json.contains("\"port\":8843"));

        // block 别名（HC 侧 TOML 术语）→ Deny。
        let from_alias: RuleAction = serde_json::from_str("\"block\"").unwrap();
        assert_eq!(from_alias, RuleAction::Deny);
        // 标准值。
        assert_eq!(
            serde_json::to_string(&RuleAction::Alert).unwrap(),
            "\"alert\""
        );
    }

    // K3 契约序列化：Action/Reason 值与审计 JSON 常量一致。
    #[test]
    fn action_reason_serde_values() {
        assert_eq!(serde_json::to_string(&Action::Allow).unwrap(), "\"allow\"");
        assert_eq!(serde_json::to_string(&Action::Deny).unwrap(), "\"deny\"");
        assert_eq!(
            serde_json::to_string(&Reason::WhitelistMatch).unwrap(),
            "\"whitelist_match\""
        );
        assert_eq!(
            serde_json::to_string(&Reason::TargetTlsError).unwrap(),
            "\"target_tls_error\""
        );
        assert_eq!(
            serde_json::to_string(&Reason::BinaryNotFound).unwrap(),
            "\"binary_not_found\""
        );
        assert_eq!(
            serde_json::to_string(&Reason::ConnectionTimeout).unwrap(),
            "\"connection_timeout\""
        );
    }

    // K4 契约序列化：audit_log_entry 12 字段（可空字段为 null 不省略；
    // type 数值映射 0/1）。
    #[test]
    fn audit_entry_serde_fields() {
        let e = AuditLogEntry {
            timestamp: "2026-08-26T01:42:59Z".to_string(),
            container_id: "c-test".to_string(),
            scenario: "kata".to_string(),
            domain: "api.example.com".to_string(),
            url_path: "/v1/chat".to_string(),
            method: "POST".to_string(),
            status_code: 0,
            action: Action::Deny,
            reason: Reason::BlacklistMatch,
            source_ip: Some("10.0.0.5".to_string()),
            target_ip: None,
            entry_type: AuditEntryType::Audit,
        };
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains("\"timestamp\":\"2026-08-26T01:42:59Z\""));
        assert!(json.contains("\"status_code\":0"));
        assert!(json.contains("\"target_ip\":null"));
        assert!(json.contains("\"type\":0"));
        let back: AuditLogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back, e);

        // 告警条目：type=1。
        let alert = AuditLogEntry {
            action: Action::Allow,
            reason: Reason::DefaultPolicy,
            entry_type: AuditEntryType::Alert,
            ..e
        };
        let json = serde_json::to_string(&alert).unwrap();
        assert!(json.contains("\"type\":1"));
        assert_eq!(serde_json::from_str::<AuditLogEntry>(&json).unwrap(), alert);
    }

    // 向后兼容：旧条目（无 type 字段）反序列化为 Audit；非法值拒绝。
    #[test]
    fn audit_entry_type_compatibility() {
        let legacy = r#"{
            "timestamp":"2026-08-26T01:42:59Z","container_id":"c","scenario":"lib",
            "domain":"a.com","url_path":"/","method":"GET","status_code":200,
            "action":"allow","reason":"default_policy","source_ip":null,"target_ip":null
        }"#;
        let back: AuditLogEntry = serde_json::from_str(legacy).unwrap();
        assert_eq!(back.entry_type, AuditEntryType::Audit);

        assert!(serde_json::from_str::<AuditEntryType>("2").is_err());
        assert_eq!(serde_json::to_string(&AuditEntryType::Alert).unwrap(), "1");
        assert_eq!(
            AuditEntryType::try_from(0u8).unwrap(),
            AuditEntryType::Audit
        );
        assert!(AuditEntryType::try_from(3u8).is_err());
    }

    // 时间戳格式：UTC ISO-8601 秒精度。已知纪元值断言（civil_from_days
    // 算法的闰日/年边界锁定）+ 当前时间形态校验。
    #[test]
    fn utc_now_iso8601_shape() {
        assert_eq!(iso8601_from_unix(0), "1970-01-01T00:00:00Z");
        // 2024-02-29T00:00:00Z（闰日）。
        assert_eq!(iso8601_from_unix(1_709_164_800), "2024-02-29T00:00:00Z");
        // 2026-08-26T01:42:59Z（与 AuditLogEntry 示例 timestamp 互证）。
        assert_eq!(
            iso8601_from_unix(1_787_708_579),
            "2026-08-26T01:42:59Z"
        );
        // 纪元前（负值）换算正确性（1969-12-31T23:59:59Z）。
        assert_eq!(iso8601_from_unix(-1), "1969-12-31T23:59:59Z");
        let ts = utc_now_iso8601();
        assert_eq!(ts.len(), 20, "ts = {ts}");
        assert!(ts.ends_with('Z'));
        assert!(ts.starts_with("20"));
    }
}

// ===== 容器端点 API 类型（2026-09-01 API 重设计：单容器实现 + 多容器扩展预留）=====

/// 容器 CA 材料（[`crate::facade::set_container_ca`] 入参；双 PEM 结构体）。
#[derive(Debug, Clone)]
pub struct CaCert {
    /// PEM 编码 X.509 CA 证书。
    pub cert_pem: Vec<u8>,
    /// PEM 编码 PKCS#8 私钥。
    pub key_pem: Vec<u8>,
}

/// 容器监听端点（`{ip, port}`——纯地址形态；容器身份经
/// [`crate::registry::Resolver`] 连接级运行时解析，零静态配置）。
#[derive(Debug, Clone)]
pub struct ContainerEndpoint {
    /// 监听 IP（支持 IPv4/IPv6）。
    pub ip: std::net::IpAddr,
    /// 监听端口（1-65535）。
    pub port: u16,
}

/// 连接协议类型（[`crate::registry::Resolver`] 入参；当前监听统一
/// TCP——后续协议扩展经新增变体）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// TCP 连接。
    Tcp,
}

/// Resolver 回调输出：容器身份 + 进程二进制路径（连接级身份解析结果）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolverOutput {
    /// 容器标识（非空；配置/CA 查表键）。
    pub container_id: String,
    /// 进程二进制路径（如 `/usr/bin/python3`；空串视为未解析——
    /// 规则含 binary 条件时按 binary_not_found fail-closed）。
    pub binary_path: String,
}

/// proxy 初始化配置（[`crate::facade::proxy_init`] 入参；单容器实现 +
/// 多容器扩展预留——容器身份经 [`crate::registry::Resolver`] 连接级
/// 运行时解析，不经静态配置）。
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// 转发流量接收端点（接入完整服务管道：MITM/过滤/审计/转发）。
    pub forwarding: ContainerEndpoint,
    /// 推理路由列表（host+url 精确匹配；命中的请求旁通过滤引擎，
    /// 交推理路由外部库裁决——AR-005）。
    pub inference_routes: Vec<InferenceRoute>,
}

/// 推理路由条目（`{host, url}`——host 对请求域名（SNI/Host 头）精确
/// 匹配（大小写不敏感，DNS 语义），url 对请求路径精确匹配（区分
/// 大小写，不含 query string））。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceRoute {
    /// 目标域名（非空）。
    pub host: String,
    /// 请求路径（非空，如 `/v1/chat/completions`）。
    pub url: String,
}
