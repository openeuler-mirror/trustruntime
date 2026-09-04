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

/// 白名单/黑名单条目：条目内各维度 AND 匹配，未声明维度等同 "*"。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleEntry {
    /// 域名通配（ASCII 大小写不敏感，RFC 4343）：无星精确；单星任意
    /// 位置通配——`*` 匹配任意字符序列含空串（`*.example.com` 不匹配
    /// 裸域 `example.com`——模式含字面 `.` 分隔；`*example.com` 匹配
    /// 裸域）；裸 `*` 全匹配；多星非法（K10）。
    pub domain: String,
    /// HTTP 方法（大小写敏感，RFC 9110）：无星精确；单星任意位置
    /// 通配（`GET*`/`*ET`/`G*T`）；裸 `*` 全匹配；多星非法（K10）。
    pub method: String,
    /// URI 可选维度（大小写敏感；匹配路径部分不含 query string）：
    /// 无星精确；单星任意位置通配（`/one/box/*/v1` 的 `*` 匹配任意
    /// 序列含 `/` 与空串）；裸 `*` 全匹配；多星非法（K10）；缺省 "*"。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    /// binary 可选维度：进程二进制路径精确（与 Resolver 输出的
    /// `binary_path` 全等比较——如 `/usr/bin/python3`）；缺省 "*"。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary: Option<String>,
    /// 目标 IP 可选维度（2026-09-09）：CIDR 网段（`10.0.0.0/8`）或
    /// 精确 IP（`1.2.3.4`，等同 /32；IPv4/IPv6 均支持）。求值输入 =
    /// 请求域名经 DNS 预解析的全部 IP——**任一命中即命中**（deny
    /// 保守：CDN 多 IP 场景任一 IP 在黑名单则拒）。缺省 "*" 全匹配。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_ip: Option<String>,
    /// 目标端口可选维度（2026-09-09）：精确（`8443`）或范围
    ///（`8000-9000`，含两端）。求值输入：明文路径 = Host 头端口
    ///（无则 80）；TLS 路径 = 443。缺省 "*" 全匹配。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_port: Option<String>,
}

/// 过滤策略配置（单份结构，交付通道区分两场景）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterConfig {
    /// 无规则匹配时默认策略。
    pub default_policy: Policy,
    /// 白名单：任一条目命中即 allow。
    #[serde(default)]
    pub whitelist: Vec<RuleEntry>,
    /// 黑名单：白名单未命中后评估，任一条目命中即 deny。
    #[serde(default)]
    pub blacklist: Vec<RuleEntry>,
}

impl FilterConfig {
    /// 是否存在 binary 维度条件（任一白/黑名单条目声明 binary）。
    ///
    /// 服务管道的条件性判定点（说明书 4.4.2：无 binary 条件不触发
    /// binary_not_found fail-closed）：调用方以本方法决定 binary 维度
    /// 未解析时是否拒绝。
    pub fn has_binary_condition(&self) -> bool {
        self.whitelist
            .iter()
            .chain(self.blacklist.iter())
            .any(|e| e.binary.is_some())
    }

    /// 是否存在目标 IP 维度条件（任一条目声明 target_ip）。
    ///
    /// 服务管道的条件性判定点（与 binary 维度同模式——2026-09-09）：
    /// 仅含 IP 条件的配置才触发 DNS 预解析（无 IP 条件零解析开销）；
    /// 解析失败 fail-closed（`Reason::DnsResolveError`）。
    pub fn has_ip_condition(&self) -> bool {
        self.whitelist
            .iter()
            .chain(self.blacklist.iter())
            .any(|e| e.target_ip.is_some())
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

    fn entry(binary: Option<&str>) -> RuleEntry {        RuleEntry {
            domain: "api.example.com".to_string(),
            method: "*".to_string(),
            uri: None,
            binary: binary.map(str::to_string),
            target_ip: None,
            target_port: None,
        }
    }

    // has_binary_condition 判定面（4.4.2 条件性触发的生产判定点）。
    #[test]
    fn has_binary_condition_across_lists() {
        let none = FilterConfig {
            default_policy: Policy::Deny,
            whitelist: vec![entry(None)],
            blacklist: vec![entry(None)],
        };
        assert!(!none.has_binary_condition());

        let empty = FilterConfig {
            default_policy: Policy::Deny,
            whitelist: vec![],
            blacklist: vec![],
        };
        assert!(!empty.has_binary_condition());

        let in_whitelist = FilterConfig {
            default_policy: Policy::Deny,
            whitelist: vec![entry(Some("python3"))],
            blacklist: vec![],
        };
        assert!(in_whitelist.has_binary_condition());

        let in_blacklist = FilterConfig {
            default_policy: Policy::Deny,
            whitelist: vec![],
            blacklist: vec![entry(Some("curl"))],
        };
        assert!(in_blacklist.has_binary_condition());
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
