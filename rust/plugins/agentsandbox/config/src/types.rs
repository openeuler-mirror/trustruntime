use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterConfig {
    pub default_policy: String,
    #[serde(default = "default_true")]
    pub audit_enabled: bool,
    #[serde(default = "default_drain")]
    pub policy_change_strategy: String,
    pub whitelist: Vec<MatchRule>,
    pub blacklist: Vec<MatchRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchRule {
    pub domain: String,
    pub method: String,
    #[serde(default = "default_star")]
    pub uri: String,
    #[serde(default = "default_star")]
    pub binary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelRoute {
    pub listen_port: u16,
    pub container_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPolicy {
    pub enforcement_mode: String,
    #[serde(default)]
    pub privilege_escalation_rules: Vec<CapabilityRule>,
    #[serde(default)]
    pub filesystem_access_rules: Vec<FilesystemRule>,
    #[serde(default)]
    pub network_rules: Vec<NetworkRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityRule {
    pub capability: String,
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

fn default_star() -> String {
    "*".to_string()
}
