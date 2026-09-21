use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterConfig {
    pub default_policy: String,
    #[serde(default = "default_true")]
    pub audit_enabled: bool,
    #[serde(default = "default_drain")]
    pub policy_change_strategy: String,
    /// 规则集列表（`[[proxy.ruleset]]` 数组；按 host.prio 降序求值——
    /// 2026-09-16 结构重设计，替代原 whitelist/blacklist）。
    #[serde(default, rename = "ruleset")]
    pub rule_list: Vec<RuleSetConfig>,
}

/// 规则集（TOML 形态——传递给 proxy 侧结构转换）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSetConfig {
    pub name: String,
    pub host: HostRuleConfig,
    #[serde(default)]
    pub targetrules: Vec<TargetRuleConfig>,
    #[serde(default)]
    pub binaryrules: Vec<BinaryRuleConfig>,
    /// 目标端口（**预留**——不参与匹配，透传保留）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

/// 主机匹配条件（`{type, addr?, context?, prio}`）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostRuleConfig {
    #[serde(rename = "type")]
    pub host_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    pub prio: u32,
}

impl HostRuleConfig {
    /// type=ip 时的 addr（校验辅助——缺失返回 None）。
    pub fn addr_host(&self) -> Option<&str> {
        self.addr.as_deref()
    }
}

/// 目标规则（method + path → action）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetRuleConfig {
    pub method: String,
    pub path: String,
    pub action: String,
}

/// binary 规则（path → action）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryRuleConfig {
    pub path: String,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelRoute {
    pub container_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPolicy {
    pub enforcement_mode: String,
    #[serde(default = "default_action")]
    pub default_action: String,
    #[serde(default)]
    pub privilege_escalation_rules: Vec<CapabilityRule>,
    #[serde(default)]
    pub filesystem_access_rules: Vec<FilesystemRule>,
    #[serde(default)]
    pub network_rules: Vec<NetworkRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityRule {
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub path_pattern: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemRule {
    pub path_prefix: String,
    #[serde(default)]
    pub attrs: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkRule {
    pub operation: String,
    pub target: String,
    pub port: String,
    pub protocol: String,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TomlConfig {
    pub version: u32,
    #[serde(default)]
    pub proxy: Option<FilterConfig>,
    #[serde(default)]
    pub model_route: Option<ModelRoute>,
    #[serde(default)]
    pub security: Option<SecurityPolicy>,
}

fn default_true() -> bool {
    true
}

fn default_drain() -> String {
    "drain".to_string()
}

fn default_action() -> String {
    "block".to_string()
}

/// Container identity. Currently only carries cgroup_id; designed for
/// future extension (e.g. namespace, pod_uid) without breaking serialization.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContainerId {
    pub cgroup_id: u64,
}

impl ContainerId {
    pub fn new(cgroup_id: u64) -> Self { Self { cgroup_id } }
    pub fn as_key(&self) -> String { self.cgroup_id.to_string() }
}

impl std::fmt::Display for ContainerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.cgroup_id)
    }
}
