use agentsandbox_config::SecurityPolicy;
use agentsandbox_log::SecurityEvent;
use thiserror::Error;
use std::collections::HashMap;
use std::sync::Mutex;

use crate::bytecode;

const ENFORCEMENT_MODE_BLOCK: u8 = 0;
const ENFORCEMENT_MODE_ALERT: u8 = 1;

pub const MAX_CAP_PATH_RULES: usize = 32;
pub const MAX_FS_PATH_RULES: usize = 32;
pub const MAX_NETWORK_RULES: usize = 32;
pub const MAX_PATH_PATTERN_LEN: usize = 256;

pub const PATH_MATCH_EXACT: u8 = 0;
pub const PATH_MATCH_PREFIX: u8 = 1;

pub const FS_PERM_READ: u8 = 1 << 0;
pub const FS_PERM_WRITE: u8 = 1 << 1;
pub const FS_PERM_EXEC: u8 = 1 << 2;

pub const NET_ACTION_ALLOW: u8 = 0;
pub const NET_ACTION_BLOCK: u8 = 1;
pub const NET_ACTION_REDIRECT: u8 = 2;

pub const NET_PROTOCOL_ANY: u8 = 0;
pub const NET_PROTOCOL_TCP: u8 = 6;
pub const NET_PROTOCOL_UDP: u8 = 17;

/// BPF map value: compact policy summary for kernel-side enforcement.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[repr(C)]
pub struct PolicyValue {
    pub enforcement_mode: u8,
    pub rule_count: u8,
    pub cap_mask: u64,
    pub has_path_rules: u8,
    pub default_action: u8,
    pub container_port: u16,
}

unsafe impl aya::Pod for PolicyValue {}

/// A single capability+path rule for kernel-side matching.
/// `cap_mask`: bitmask of allowed capabilities for this path.
/// `match_type`: PATH_MATCH_EXACT or PATH_MATCH_PREFIX.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct CapPathRule {
    pub cap_mask: u64,
    pub match_type: u8,
    pub path: [u8; MAX_PATH_PATTERN_LEN],
}

unsafe impl aya::Pod for CapPathRule {}

/// Container for path-conditioned capability rules belonging to one cgroup.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct CapPathRules {
    pub count: u8,
    pub rules: [CapPathRule; MAX_CAP_PATH_RULES],
}

unsafe impl aya::Pod for CapPathRules {}

impl Default for CapPathRules {
    fn default() -> Self {
        Self { count: 0, rules: [CapPathRule::default(); MAX_CAP_PATH_RULES] }
    }
}

impl Default for CapPathRule {
    fn default() -> Self {
        Self { cap_mask: 0, match_type: 0, path: [0u8; MAX_PATH_PATTERN_LEN] }
    }
}

impl CapPathRule {
    pub fn new(cap_bit: u32, path_pattern: &str) -> Option<Self> {
        let (match_type, cleaned) = compile_glob(path_pattern);
        let bytes = cleaned.as_bytes();
        debug_assert!(bytes.len() < MAX_PATH_PATTERN_LEN, "path exceeds MAX_PATH_PATTERN_LEN");
        let mut path = [0u8; MAX_PATH_PATTERN_LEN];
        path[..bytes.len()].copy_from_slice(bytes);
        Some(Self { cap_mask: 1u64 << cap_bit, match_type, path })
    }

    pub fn path_str(&self) -> &str {
        let end = self.path.iter().position(|&b| b == 0).unwrap_or(MAX_PATH_PATTERN_LEN);
        std::str::from_utf8(&self.path[..end]).unwrap_or("")
    }
}

/// A single filesystem path permission rule for kernel-side matching.
/// `perm_mask`: bitmask of allowed permissions (FS_PERM_READ/WRITE/EXEC).
/// `match_type`: PATH_MATCH_EXACT or PATH_MATCH_PREFIX.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FsPathRule {
    pub perm_mask: u8,
    pub match_type: u8,
    pub path: [u8; MAX_PATH_PATTERN_LEN],
}

unsafe impl aya::Pod for FsPathRule {}

impl Default for FsPathRule {
    fn default() -> Self {
        Self { perm_mask: 0, match_type: 0, path: [0u8; MAX_PATH_PATTERN_LEN] }
    }
}

/// Container for filesystem path permission rules belonging to one cgroup.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FsPathRules {
    pub count: u8,
    pub rules: [FsPathRule; MAX_FS_PATH_RULES],
}

unsafe impl aya::Pod for FsPathRules {}

impl FsPathRule {
    pub fn new(attrs: &str, path_pattern: &str) -> Option<Self> {
        let (match_type, cleaned) = compile_glob(path_pattern);
        let bytes = cleaned.as_bytes();
        debug_assert!(bytes.len() < MAX_PATH_PATTERN_LEN, "path exceeds MAX_PATH_PATTERN_LEN");
        let mut path = [0u8; MAX_PATH_PATTERN_LEN];
        path[..bytes.len()].copy_from_slice(bytes);
        let perm_mask = attrs_to_perm_mask(attrs);
        Some(Self { perm_mask, match_type, path })
    }

    pub fn path_str(&self) -> &str {
        let end = self.path.iter().position(|&b| b == 0).unwrap_or(MAX_PATH_PATTERN_LEN);
        std::str::from_utf8(&self.path[..end]).unwrap_or("")
    }
}

impl Default for FsPathRules {
    fn default() -> Self {
        Self { count: 0, rules: [FsPathRule::default(); MAX_FS_PATH_RULES] }
    }
}

fn attrs_to_perm_mask(attrs: &str) -> u8 {
    let mut mask = 0u8;
    for c in attrs.chars() {
        match c {
            'r' | 'R' => mask |= FS_PERM_READ,
            'w' | 'W' => mask |= FS_PERM_WRITE,
            'x' | 'X' => mask |= FS_PERM_EXEC,
            _ => {}
        }
    }
    mask
}

/// A single network rule for kernel-side matching.
/// `target_ip` / `target_mask`: CIDR-style IP matching (wildcard = 0.0.0.0/0).
/// `port`: 0 = match any port.
/// `protocol`: NET_PROTOCOL_ANY = match any.
/// `action`: NET_ACTION_ALLOW / BLOCK / REDIRECT.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct NetworkRuleBpf {
    pub target_ip: u32,
    pub target_mask: u32,
    pub port: u16,
    pub protocol: u8,
    pub action: u8,
}

unsafe impl aya::Pod for NetworkRuleBpf {}

impl Default for NetworkRuleBpf {
    fn default() -> Self {
        Self { target_ip: 0, target_mask: 0, port: 0, protocol: 0, action: 0 }
    }
}

impl NetworkRuleBpf {
    pub fn from_rule(rule: &agentsandbox_config::NetworkRule) -> Result<Self, EbpfError> {
        if rule.operation != "connect" {
            return Err(EbpfError::MapError(format!("unsupported operation: {}", rule.operation)));
        }
        let (target_ip, target_mask) = parse_target(&rule.target)?;
        let port = parse_port(&rule.port)?;
        let protocol = parse_protocol(&rule.protocol)?;
        let action = match rule.action.as_str() {
            "allow" => NET_ACTION_ALLOW,
            "block" => NET_ACTION_BLOCK,
            "redirect_to_proxy" => NET_ACTION_REDIRECT,
            _ => NET_ACTION_BLOCK,
        };
        Ok(Self { target_ip, target_mask, port, protocol, action })
    }
}

/// Container for network rules belonging to one cgroup.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct NetworkRulesBpf {
    pub count: u8,
    pub rules: [NetworkRuleBpf; MAX_NETWORK_RULES],
}

unsafe impl aya::Pod for NetworkRulesBpf {}

impl Default for NetworkRulesBpf {
    fn default() -> Self {
        Self { count: 0, rules: [NetworkRuleBpf::default(); MAX_NETWORK_RULES] }
    }
}

fn parse_target(target: &str) -> Result<(u32, u32), EbpfError> {
    if target == "*" || target.is_empty() {
        return Ok((0, 0));
    }
    if let Some((ip_part, mask_part)) = target.split_once('/') {
        let ip = parse_ip(ip_part)?;
        let bits: u32 = mask_part.parse().map_err(|_| EbpfError::MapError(format!("invalid cidr mask: {}", mask_part)))?;
        if bits > 32 {
            return Err(EbpfError::MapError(format!("invalid cidr mask bits: {}", bits)));
        }
        if bits == 0 {
            return Ok((0, 0));
        }
        let mask = if bits >= 32 { 0xFFFFFFFF } else { ((1u32 << bits) - 1) << (32 - bits) };
        return Ok((ip & mask, mask));
    }
    let ip = parse_ip(target)?;
    Ok((ip, 0xFFFFFFFF))
}

fn parse_ip(s: &str) -> Result<u32, EbpfError> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return Err(EbpfError::MapError(format!("invalid ip: {}", s)));
    }
    let mut ip: u32 = 0;
    for part in parts {
        let octet: u32 = part.parse().map_err(|_| EbpfError::MapError(format!("invalid ip octet: {}", part)))?;
        if octet > 255 {
            return Err(EbpfError::MapError(format!("ip octet out of range: {}", octet)));
        }
        ip = (ip << 8) | octet;
    }
    Ok(ip)
}

fn parse_port(port: &str) -> Result<u16, EbpfError> {
    if port == "*" || port.is_empty() {
        return Ok(0);
    }
    port.parse().map_err(|_| EbpfError::MapError(format!("invalid port: {}", port)))
}

fn parse_protocol(protocol: &str) -> Result<u8, EbpfError> {
    match protocol.to_lowercase().as_str() {
        "tcp" => Ok(NET_PROTOCOL_TCP),
        "udp" => Ok(NET_PROTOCOL_UDP),
        "*" | "" => Ok(NET_PROTOCOL_ANY),
        _ => Err(EbpfError::MapError(format!("invalid protocol: {}", protocol))),
    }
}

fn compile_glob(pattern: &str) -> (u8, String) {
    if pattern.is_empty() || pattern == "*" {
        return (PATH_MATCH_EXACT, String::new());
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return (PATH_MATCH_PREFIX, prefix.to_string());
    }
    if pattern.contains('*') {
        let prefix = &pattern[..pattern.find('*').unwrap()];
        return (PATH_MATCH_PREFIX, prefix.to_string());
    }
    (PATH_MATCH_EXACT, pattern.to_string())
}

impl PolicyValue {
    /// Converts a SecurityPolicy into a compact PolicyValue for BPF map storage.
    pub fn from_policy(policy: &SecurityPolicy, container_port: u16) -> Self {
        let enforcement_mode = match policy.enforcement_mode.as_str() {
            "block" => ENFORCEMENT_MODE_BLOCK,
            "alert" => ENFORCEMENT_MODE_ALERT,
            _ => ENFORCEMENT_MODE_BLOCK,
        };
        let default_action = match policy.default_action.as_str() {
            "allow" => NET_ACTION_ALLOW,
            _ => NET_ACTION_BLOCK,
        };
        let rule_count = policy.privilege_escalation_rules.len().min(255) as u8;

        let mut cap_mask = 0u64;
        let mut has_path_rules = false;
        for r in &policy.privilege_escalation_rules {
            let has_path = r.path_pattern.as_ref()
                .map(|p| !p.is_empty() && p != "*")
                .unwrap_or(false);
            for cap in &r.capabilities {
                if let Some(bit) = cap_name_to_bit(cap) {
                    if !has_path {
                        cap_mask |= 1u64 << bit;
                    } else {
                        has_path_rules = true;
                    }
                }
            }
        }
        Self {
            enforcement_mode,
            rule_count,
            cap_mask,
            has_path_rules: has_path_rules as u8,
            default_action,
            container_port,
        }
    }

    /// Returns true if the given capability bit is set in cap_mask.
    pub fn has_capability(&self, cap: u32) -> bool {
        cap < 64 && (self.cap_mask & (1u64 << cap)) != 0
    }

    /// Returns true if enforcement mode is block (deny on match).
    pub fn is_block_mode(&self) -> bool {
        self.enforcement_mode == ENFORCEMENT_MODE_BLOCK
    }

    /// Returns true if enforcement mode is alert (log but allow).
    pub fn is_alert_mode(&self) -> bool {
        self.enforcement_mode == ENFORCEMENT_MODE_ALERT
    }
}

/// Maps a Linux capability name (e.g. "cap_sys_admin") to its bit number.
/// Returns None for unrecognized names.
fn cap_name_to_bit(name: &str) -> Option<u32> {
    let bit = match name.to_lowercase().as_str() {
        "cap_chown" => 0,
        "cap_dac_override" => 1,
        "cap_dac_read_search" => 2,
        "cap_fowner" => 3,
        "cap_fsetid" => 4,
        "cap_kill" => 5,
        "cap_setgid" => 6,
        "cap_setuid" => 7,
        "cap_setpcap" => 8,
        "cap_linux_immutable" => 9,
        "cap_net_bind_service" => 10,
        "cap_net_broadcast" => 11,
        "cap_net_admin" => 12,
        "cap_net_raw" => 13,
        "cap_ipc_lock" => 14,
        "cap_ipc_owner" => 15,
        "cap_sys_module" => 16,
        "cap_sys_rawio" => 17,
        "cap_sys_chroot" => 18,
        "cap_sys_ptrace" => 19,
        "cap_sys_pacct" => 20,
        "cap_sys_admin" => 21,
        "cap_sys_boot" => 22,
        "cap_sys_nice" => 23,
        "cap_sys_resource" => 24,
        "cap_sys_time" => 25,
        "cap_sys_tty_config" => 26,
        "cap_mknod" => 27,
        "cap_lease" => 28,
        "cap_audit_write" => 29,
        "cap_audit_control" => 30,
        "cap_setfcap" => 31,
        "cap_mac_override" => 32,
        "cap_mac_admin" => 33,
        "cap_syslog" => 34,
        "cap_wake_alarm" => 35,
        "cap_block_suspend" => 36,
        "cap_audit_read" => 37,
        "cap_perfmon" => 38,
        "cap_bpf" => 39,
        "cap_checkpoint_restore" => 40,
        _ => return None,
    };
    Some(bit)
}

/// HiController sock block entry written to BPF hash map after container registration.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SockBlockEntry {
    pub path: [u8; MAX_PATH_PATTERN_LEN],
}

unsafe impl aya::Pod for SockBlockEntry {}

impl Default for SockBlockEntry {
    fn default() -> Self {
        Self { path: [0u8; MAX_PATH_PATTERN_LEN] }
    }
}

/// Global proxy configuration written to BPF array map at startup.
/// All IPs are in network byte order (big-endian), same as ctx->user_ip4.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ProxyConfig {
    pub proxy_ip: u32,
    pub proxy_port: u16,
    pub model_route_port: u16,
    pub container_ip: u32,
}

/// Full policy snapshot for a cgroup, used for rollback.
#[derive(Debug, Clone)]
pub struct PolicySnapshot {
    pub policy_value: Option<PolicyValue>,
    pub cap_path_rules: Option<CapPathRules>,
    pub fs_path_rules: Option<FsPathRules>,
    pub network_rules: Option<NetworkRulesBpf>,
}

unsafe impl aya::Pod for ProxyConfig {}

/// eBPF loader errors.
#[derive(Debug, Error)]
pub enum EbpfError {
    #[error("eBPF program load failed: {0}")]
    LoadError(String),
    #[error("BPF map operation failed: {0}")]
    MapError(String),
    #[error("ring buffer read failed: {0}")]
    RingBufferError(String),
    #[error("cgroup_id not found in policy map")]
    NotFoundError,
    #[error("eBPF programs not loaded")]
    NotLoadedError,
}

/// Manages eBPF program lifecycle and BPF map operations.
pub struct EbpfLoader {
    bpf: Mutex<Vec<aya::Ebpf>>,
    policy_map: Mutex<HashMap<u64, PolicyValue>>,
    cap_path_rules_map: Mutex<HashMap<u64, CapPathRules>>,
    fs_path_rules_map: Mutex<HashMap<u64, FsPathRules>>,
    network_rules_map: Mutex<HashMap<u64, NetworkRulesBpf>>,
    sock_block_map: Mutex<HashMap<u64, SockBlockEntry>>,
    proxy_config: Mutex<Option<ProxyConfig>>,
    loaded: Mutex<bool>,
}

impl EbpfLoader {
    /// Creates a new EbpfLoader with empty policy map.
    pub fn new() -> Self {
        Self {
            bpf: Mutex::new(Vec::new()),
            policy_map: Mutex::new(HashMap::new()),
            cap_path_rules_map: Mutex::new(HashMap::new()),
            fs_path_rules_map: Mutex::new(HashMap::new()),
            network_rules_map: Mutex::new(HashMap::new()),
            sock_block_map: Mutex::new(HashMap::new()),
            proxy_config: Mutex::new(None),
            loaded: Mutex::new(false),
        }
    }

    /// Loads eBPF programs (LSM + cgroup/connect4) into the kernel.
    /// Bytecode is compiled at build time from src/bpf/*.bpf.c and embedded via include_bytes!.
    /// Only removes previously loaded programs that conflict by name; others are kept.
    /// Falls back to stub mode if bytecode is empty (e.g. clang unavailable at build time).
    pub fn load_programs(&self) -> Result<(), EbpfError> {
        let mut bpf_guard = self.bpf.lock()
            .map_err(|e| EbpfError::LoadError(e.to_string()))?;

        let new_names: Vec<&str> = bytecode::all_programs().iter().map(|(n, _)| *n).collect();
        bpf_guard.retain(|b| {
            b.programs().all(|(n, _)| !new_names.contains(&n))
        });

        for (name, bytecode) in bytecode::all_programs() {
            if bytecode.is_empty() {
                continue;
            }
            let bpf = aya::Ebpf::load(bytecode)
                .map_err(|e| EbpfError::LoadError(format!("{}: {}", name, e)))?;
            bpf_guard.push(bpf);
        }
        drop(bpf_guard);

        let mut loaded = self.loaded.lock()
            .map_err(|e| EbpfError::LoadError(e.to_string()))?;
        *loaded = true;
        Ok(())
    }

    /// Sets the global proxy address (IP + proxy port + model route port) for network redirect.
    /// Writes to the kernel BPF proxy_config_map (ARRAY map, key=0).
    /// Must be called after load_programs, before any connect4 triggers.
    pub fn set_proxy(&self, ip: u32, proxy_port: u16, model_route_port: u16, container_ip: u32) -> Result<(), EbpfError> {
        if !self.is_loaded() { return Err(EbpfError::NotLoadedError); }

        let cfg = ProxyConfig { proxy_ip: ip, proxy_port, model_route_port, container_ip };

        let mut bpf_guard = self.bpf.lock()
            .map_err(|e| EbpfError::MapError(e.to_string()))?;
        for bpf in bpf_guard.iter_mut() {
            if let Some(map) = bpf.map_mut("proxy_config_map") {
                let mut arr = aya::maps::Array::<_, ProxyConfig>::try_from(map)
                    .map_err(|e| EbpfError::MapError(e.to_string()))?;
                arr.set(0, cfg, 0)
                    .map_err(|e| EbpfError::MapError(e.to_string()))?;
            }
        }
        drop(bpf_guard);

        let mut stored = self.proxy_config.lock()
            .map_err(|e| EbpfError::MapError(e.to_string()))?;
        *stored = Some(cfg);
        Ok(())
    }

    /// Returns the currently configured proxy (ip, proxy_port, model_route_port, container_ip), or None.
    pub fn get_proxy(&self) -> Option<(u32, u16, u16, u32)> {
        self.proxy_config.lock().ok()?.as_ref()
            .map(|c| (c.proxy_ip, c.proxy_port, c.model_route_port, c.container_ip))
    }

    /// Updates both policy_map and cap_path_rules_map from a SecurityPolicy.
    pub fn update_from_security_policy(&self, cgroup_id: u64, policy: &SecurityPolicy, container_port: u16) -> Result<(), EbpfError> {
        if !self.is_loaded() { return Err(EbpfError::NotLoadedError); }

        let cap_path_count = policy.privilege_escalation_rules.iter()
            .filter(|r| r.path_pattern.as_ref().map(|p| !p.is_empty() && p != "*").unwrap_or(false))
            .map(|r| r.path_pattern.as_ref().unwrap().clone())
            .collect::<std::collections::HashSet<_>>()
            .len();
        if cap_path_count > MAX_CAP_PATH_RULES {
            return Err(EbpfError::MapError(format!("cap_path_rules exceed max {} entries", MAX_CAP_PATH_RULES)));
        }
        if policy.filesystem_access_rules.len() > MAX_FS_PATH_RULES {
            return Err(EbpfError::MapError(format!("fs_path_rules exceed max {} entries", MAX_FS_PATH_RULES)));
        }
        if policy.network_rules.len() > MAX_NETWORK_RULES {
            return Err(EbpfError::MapError(format!("network_rules exceed max {} entries", MAX_NETWORK_RULES)));
        }

        for r in &policy.privilege_escalation_rules {
            if let Some(p) = &r.path_pattern {
                if p.is_empty() || p == "*" { continue; }
                if p.len() >= MAX_PATH_PATTERN_LEN {
                    return Err(EbpfError::MapError(format!("path_pattern exceeds max {} bytes: {}", MAX_PATH_PATTERN_LEN, p)));
                }
            }
        }
        for r in &policy.filesystem_access_rules {
            if r.path_prefix.len() >= MAX_PATH_PATTERN_LEN {
                return Err(EbpfError::MapError(format!("path_prefix exceeds max {} bytes: {}", MAX_PATH_PATTERN_LEN, r.path_prefix)));
            }
        }

        let pv = PolicyValue::from_policy(policy, container_port);
        self.write_kernel_hash("policy_map", cgroup_id, pv)?;
        let mut m = self.policy_map.lock()
            .map_err(|e| EbpfError::MapError(e.to_string()))?;
        m.insert(cgroup_id, pv);
        drop(m);

        self.update_cap_path_rules(cgroup_id, policy)?;
        self.update_fs_path_rules(cgroup_id, policy)?;
        self.update_network_rules(cgroup_id, policy)?;

        Ok(())
    }

    fn write_kernel_hash<V: aya::Pod + Copy>(&self, map_name: &str, key: u64, value: V) -> Result<(), EbpfError> {
        let mut bpf_guard = self.bpf.lock().map_err(|e| EbpfError::MapError(e.to_string()))?;
        for bpf in bpf_guard.iter_mut() {
            if let Some(map) = bpf.map_mut(map_name) {
                let mut hm = aya::maps::HashMap::<_, u64, V>::try_from(map).map_err(|e| EbpfError::MapError(e.to_string()))?;
                hm.insert(key, value, 0).map_err(|e| EbpfError::MapError(e.to_string()))?;
            }
        }
        drop(bpf_guard);
        Ok(())
    }

    fn delete_kernel_hash<V: aya::Pod + Copy>(&self, map_name: &str, key: u64) -> Result<(), EbpfError> {
        let mut bpf_guard = self.bpf.lock().map_err(|e| EbpfError::MapError(e.to_string()))?;
        for bpf in bpf_guard.iter_mut() {
            if let Some(map) = bpf.map_mut(map_name) {
                let mut hm = aya::maps::HashMap::<_, u64, V>::try_from(map).map_err(|e| EbpfError::MapError(e.to_string()))?;
                let _ = hm.remove(&key);
            }
        }
        drop(bpf_guard);
        Ok(())
    }

    fn update_cap_path_rules(&self, cgroup_id: u64, policy: &SecurityPolicy) -> Result<(), EbpfError> {
        let (path_order, path_to_mask) = Self::aggregate_cap_path_rules(policy);
        let rules = Self::build_cap_path_rules(&path_order, &path_to_mask)?;
        self.apply_cap_path_rules(cgroup_id, rules)
    }

    fn aggregate_cap_path_rules(policy: &SecurityPolicy) -> (Vec<String>, std::collections::HashMap<String, u64>) {
        use std::collections::HashMap;
        let mut path_to_mask: HashMap<String, u64> = HashMap::new();
        let mut path_order: Vec<String> = Vec::new();
        for r in &policy.privilege_escalation_rules {
            let has_path = r.path_pattern.as_ref()
                .map(|p| !p.is_empty() && p != "*")
                .unwrap_or(false);
            if !has_path {
                continue;
            }
            if let Some(pattern) = &r.path_pattern {
                let entry = path_to_mask.entry(pattern.clone()).or_insert(0);
                for cap in &r.capabilities {
                    if let Some(bit) = cap_name_to_bit(cap) {
                        *entry |= 1u64 << bit;
                    }
                }
                if !path_order.contains(pattern) {
                    path_order.push(pattern.clone());
                }
            }
        }
        (path_order, path_to_mask)
    }

    fn build_cap_path_rules(path_order: &[String], path_to_mask: &std::collections::HashMap<String, u64>) -> Result<CapPathRules, EbpfError> {
        let mut rules = CapPathRules::default();
        for pattern in path_order {
            if let Some(mask) = path_to_mask.get(pattern) {
                let (match_type, cleaned) = compile_glob(pattern);
                let bytes = cleaned.as_bytes();
                debug_assert!(bytes.len() < MAX_PATH_PATTERN_LEN, "path exceeds MAX_PATH_PATTERN_LEN");
                let mut path = [0u8; MAX_PATH_PATTERN_LEN];
                path[..bytes.len()].copy_from_slice(bytes);
                rules.rules[rules.count as usize] = CapPathRule { cap_mask: *mask, match_type, path };
                rules.count += 1;
            }
        }
        Ok(rules)
    }

    fn apply_cap_path_rules(&self, cgroup_id: u64, rules: CapPathRules) -> Result<(), EbpfError> {
        if rules.count > 0 {
            self.write_kernel_hash("cap_path_rules_map", cgroup_id, rules)?;
            let mut rm = self.cap_path_rules_map.lock().map_err(|e| EbpfError::MapError(e.to_string()))?;
            rm.insert(cgroup_id, rules);
            drop(rm);
        } else {
            self.delete_kernel_hash::<CapPathRules>("cap_path_rules_map", cgroup_id)?;
            let mut rm = self.cap_path_rules_map.lock().map_err(|e| EbpfError::MapError(e.to_string()))?;
            rm.remove(&cgroup_id);
            drop(rm);
        }
        Ok(())
    }

    fn update_fs_path_rules(&self, cgroup_id: u64, policy: &SecurityPolicy) -> Result<(), EbpfError> {
        let mut fs_rules = FsPathRules::default();
        for r in &policy.filesystem_access_rules {
            if let Some(rule) = FsPathRule::new(&r.attrs, &r.path_prefix) {
                fs_rules.rules[fs_rules.count as usize] = rule;
                fs_rules.count += 1;
            }
        }
        if fs_rules.count > 0 {
            self.write_kernel_hash("fs_path_rules_map", cgroup_id, fs_rules)?;
            let mut fm = self.fs_path_rules_map.lock().map_err(|e| EbpfError::MapError(e.to_string()))?;
            fm.insert(cgroup_id, fs_rules);
            drop(fm);
        } else {
            self.delete_kernel_hash::<FsPathRules>("fs_path_rules_map", cgroup_id)?;
            let mut fm = self.fs_path_rules_map.lock().map_err(|e| EbpfError::MapError(e.to_string()))?;
            fm.remove(&cgroup_id);
            drop(fm);
        }
        Ok(())
    }

    fn update_network_rules(&self, cgroup_id: u64, policy: &SecurityPolicy) -> Result<(), EbpfError> {
        let mut net_rules = NetworkRulesBpf::default();
        for r in &policy.network_rules {
            let rule = NetworkRuleBpf::from_rule(r)?;
            net_rules.rules[net_rules.count as usize] = rule;
            net_rules.count += 1;
        }
        if net_rules.count > 0 {
            self.write_kernel_hash("network_rules_map", cgroup_id, net_rules)?;
            let mut nm = self.network_rules_map.lock().map_err(|e| EbpfError::MapError(e.to_string()))?;
            nm.insert(cgroup_id, net_rules);
            drop(nm);
        } else {
            self.delete_kernel_hash::<NetworkRulesBpf>("network_rules_map", cgroup_id)?;
            let mut nm = self.network_rules_map.lock().map_err(|e| EbpfError::MapError(e.to_string()))?;
            nm.remove(&cgroup_id);
            drop(nm);
        }
        Ok(())
    }

    /// Returns the cap path rules for a cgroup_id, or None if not set.
    pub fn get_cap_path_rules(&self, cgroup_id: u64) -> Option<CapPathRules> {
        self.cap_path_rules_map.lock().ok()?.get(&cgroup_id).cloned()
    }

    /// Returns the fs path rules for a cgroup_id, or None if not set.
    pub fn get_fs_path_rules(&self, cgroup_id: u64) -> Option<FsPathRules> {
        self.fs_path_rules_map.lock().ok()?.get(&cgroup_id).cloned()
    }

    /// Returns the network rules for a cgroup_id, or None if not set.
    pub fn get_network_rules(&self, cgroup_id: u64) -> Option<NetworkRulesBpf> {
        self.network_rules_map.lock().ok()?.get(&cgroup_id).cloned()
    }

    /// Returns the current PolicyValue for a cgroup_id, or None if not set.
    pub fn get_policy(&self, cgroup_id: u64) -> Option<PolicyValue> {
        self.policy_map.lock().ok()?.get(&cgroup_id).copied()
    }

    /// Blocks a cgroup's access to the HiController socket path via dedicated sock_block_map.
    pub fn block_sock_access(&self, cgroup_id: u64, sock_path: &str) -> Result<(), EbpfError> {
        if !self.is_loaded() { return Err(EbpfError::NotLoadedError); }
        if sock_path.len() >= MAX_PATH_PATTERN_LEN {
            return Err(EbpfError::MapError(format!("sock path exceeds max {} bytes", MAX_PATH_PATTERN_LEN)));
        }

        let bytes = sock_path.as_bytes();
        let mut path = [0u8; MAX_PATH_PATTERN_LEN];
        path[..bytes.len()].copy_from_slice(bytes);
        let entry = SockBlockEntry { path };

        self.write_kernel_hash("sock_block_map", cgroup_id, entry)?;
        let mut sm = self.sock_block_map.lock().map_err(|e| EbpfError::MapError(e.to_string()))?;
        sm.insert(cgroup_id, entry);
        drop(sm);
        Ok(())
    }

    /// Removes the sock block for a cgroup (called on container destruction).
    pub fn unblock_sock_access(&self, cgroup_id: u64) -> Result<(), EbpfError> {
        if !self.is_loaded() { return Err(EbpfError::NotLoadedError); }
        self.delete_kernel_hash::<SockBlockEntry>("sock_block_map", cgroup_id)?;
        let mut sm = self.sock_block_map.lock().map_err(|e| EbpfError::MapError(e.to_string()))?;
        sm.remove(&cgroup_id);
        drop(sm);
        Ok(())
    }

    /// Takes a full snapshot of all policy maps for a cgroup_id (for rollback).
    pub fn snapshot_policy(&self, cgroup_id: u64) -> PolicySnapshot {
        let policy_value = self.policy_map.lock().ok()
            .and_then(|m| m.get(&cgroup_id).copied());
        let cap_path_rules = self.cap_path_rules_map.lock().ok()
            .and_then(|m| m.get(&cgroup_id).copied());
        let fs_path_rules = self.fs_path_rules_map.lock().ok()
            .and_then(|m| m.get(&cgroup_id).copied());
        let network_rules = self.network_rules_map.lock().ok()
            .and_then(|m| m.get(&cgroup_id).copied());
        PolicySnapshot { policy_value, cap_path_rules, fs_path_rules, network_rules }
    }

    /// Restores a full policy snapshot for a cgroup_id (rollback).
    pub fn restore_snapshot(&self, cgroup_id: u64, snapshot: PolicySnapshot) -> Result<(), EbpfError> {
        if !self.is_loaded() { return Err(EbpfError::NotLoadedError); }

        match snapshot.policy_value {
            Some(pv) => {
                self.write_kernel_hash("policy_map", cgroup_id, pv)?;
                let mut m = self.policy_map.lock()
                    .map_err(|e| EbpfError::MapError(e.to_string()))?;
                m.insert(cgroup_id, pv);
                drop(m);
            }
            None => {
                self.delete_kernel_hash::<PolicyValue>("policy_map", cgroup_id)?;
                let mut m = self.policy_map.lock()
                    .map_err(|e| EbpfError::MapError(e.to_string()))?;
                m.remove(&cgroup_id);
                drop(m);
            }
        }

        self.restore_rules("cap_path_rules_map", cgroup_id, snapshot.cap_path_rules)?;
        self.restore_rules("fs_path_rules_map", cgroup_id, snapshot.fs_path_rules)?;
        self.restore_rules("network_rules_map", cgroup_id, snapshot.network_rules)?;

        Ok(())
    }

    fn restore_rules<V: aya::Pod + Copy>(
        &self, map_name: &str, cgroup_id: u64, rules: Option<V>,
    ) -> Result<(), EbpfError> {
        match rules {
            Some(r) => {
                self.write_kernel_hash(map_name, cgroup_id, r)?;
            }
            None => {
                self.delete_kernel_hash::<V>(map_name, cgroup_id)?;
            }
        }
        Ok(())
    }

    /// Removes a cgroup_id entry from BPF map (called on container destruction).
    pub fn remove_policy(&self, cgroup_id: u64) -> Result<(), EbpfError> {
        if !self.is_loaded() { return Err(EbpfError::NotLoadedError); }

        self.delete_kernel_hash::<PolicyValue>("policy_map", cgroup_id)?;
        let mut m = self.policy_map.lock().map_err(|e| EbpfError::MapError(e.to_string()))?;
        m.remove(&cgroup_id);
        drop(m);

        self.delete_kernel_hash::<CapPathRules>("cap_path_rules_map", cgroup_id)?;
        let mut rm = self.cap_path_rules_map.lock().map_err(|e| EbpfError::MapError(e.to_string()))?;
        rm.remove(&cgroup_id);
        drop(rm);

        self.delete_kernel_hash::<FsPathRules>("fs_path_rules_map", cgroup_id)?;
        let mut fm = self.fs_path_rules_map.lock().map_err(|e| EbpfError::MapError(e.to_string()))?;
        fm.remove(&cgroup_id);
        drop(fm);

        self.delete_kernel_hash::<NetworkRulesBpf>("network_rules_map", cgroup_id)?;
        let mut nm = self.network_rules_map.lock().map_err(|e| EbpfError::MapError(e.to_string()))?;
        nm.remove(&cgroup_id);
        drop(nm);

        self.delete_kernel_hash::<SockBlockEntry>("sock_block_map", cgroup_id)?;
        let mut sm = self.sock_block_map.lock().map_err(|e| EbpfError::MapError(e.to_string()))?;
        sm.remove(&cgroup_id);
        drop(sm);

        Ok(())
    }

    /// Polls ring buffer for security events from eBPF programs in kernel.
    pub fn poll_events(&self) -> Result<Vec<SecurityEvent>, EbpfError> {
        if !self.is_loaded() { return Err(EbpfError::NotLoadedError); }
        Ok(Vec::new())
    }

    /// Returns the number of active policy entries (active containers).
    pub fn policy_count(&self) -> usize {
        self.policy_map.lock().map(|m| m.len()).unwrap_or(0)
    }

    /// Unloads eBPF programs from the kernel and clears policy map.
    pub fn unload_programs(&self) -> Result<(), EbpfError> {
        let mut bpf_guard = self.bpf.lock()
            .map_err(|e| EbpfError::LoadError(e.to_string()))?;
        bpf_guard.clear();
        drop(bpf_guard);

        if let Ok(mut m) = self.policy_map.lock() {
            m.clear();
        }
        if let Ok(mut rm) = self.cap_path_rules_map.lock() {
            rm.clear();
        }
        if let Ok(mut fm) = self.fs_path_rules_map.lock() {
            fm.clear();
        }
        if let Ok(mut nm) = self.network_rules_map.lock() {
            nm.clear();
        }
        if let Ok(mut sm) = self.sock_block_map.lock() {
            sm.clear();
        }
        if let Ok(mut cfg) = self.proxy_config.lock() {
            *cfg = None;
        }

        let mut loaded = self.loaded.lock()
            .map_err(|e| EbpfError::LoadError(e.to_string()))?;
        *loaded = false;
        Ok(())
    }

    /// Returns true if eBPF programs are currently loaded.
    pub fn is_loaded(&self) -> bool {
        self.loaded.lock().map(|l| *l).unwrap_or(false)
    }
}

impl Default for EbpfLoader {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentsandbox_config::{CapabilityRule, FilesystemRule, NetworkRule, SecurityPolicy};

    fn policy_with_caps(caps: &[&str]) -> SecurityPolicy {
        SecurityPolicy {
            enforcement_mode: "block".to_string(),
            default_action: "allow".to_string(),
            privilege_escalation_rules: caps.iter()
                .map(|c| CapabilityRule { capabilities: vec![c.to_string()], path_pattern: None })
                .collect(),
            filesystem_access_rules: vec![],
            network_rules: vec![],
        }
    }

    fn policy_with_cap_paths(caps: &[(&str, Option<&str>)]) -> SecurityPolicy {
        SecurityPolicy {
            enforcement_mode: "block".to_string(),
            default_action: "allow".to_string(),
            privilege_escalation_rules: caps.iter()
                .map(|(c, p)| CapabilityRule {
                    capabilities: vec![c.to_string()],
                    path_pattern: p.map(|s| s.to_string()),
                })
                .collect(),
            filesystem_access_rules: vec![],
            network_rules: vec![],
        }
    }

    #[test]
    fn test_cap_mask_single_cap() {
        let pv = PolicyValue::from_policy(&policy_with_caps(&["cap_sys_admin"]), 0);
        assert!(pv.has_capability(21));
        assert!(!pv.has_capability(12));
        assert_eq!(pv.rule_count, 1);
        assert_eq!(pv.has_path_rules, 0);
    }

    #[test]
    fn test_cap_mask_multiple_caps() {
        let pv = PolicyValue::from_policy(&policy_with_caps(&["cap_sys_admin", "cap_net_admin"]), 0);
        assert!(pv.has_capability(21));
        assert!(pv.has_capability(12));
        assert!(!pv.has_capability(0));
    }

    #[test]
    fn test_cap_mask_empty_rules() {
        let pv = PolicyValue::from_policy(&policy_with_caps(&[]), 0);
        assert_eq!(pv.cap_mask, 0);
        assert!(!pv.has_capability(21));
    }

    #[test]
    fn test_cap_mask_unknown_cap_ignored() {
        let pv = PolicyValue::from_policy(&policy_with_caps(&["cap_sys_admin", "cap_unknown"]), 0);
        assert!(pv.has_capability(21));
        assert_eq!(pv.rule_count, 2);
    }

    #[test]
    fn test_cap_mask_case_insensitive() {
        let pv = PolicyValue::from_policy(&policy_with_caps(&["CAP_SYS_ADMIN"]), 0);
        assert!(pv.has_capability(21));
    }

    #[test]
    fn test_has_capability_out_of_range() {
        let pv = PolicyValue::from_policy(&policy_with_caps(&["cap_sys_admin"]), 0);
        assert!(!pv.has_capability(64));
        assert!(!pv.has_capability(100));
    }

    #[test]
    fn test_path_rule_sets_has_path_rules() {
        let pv = PolicyValue::from_policy(&policy_with_cap_paths(&[
            ("cap_sys_admin", Some("/usr/bin/curl")),
        ]), 0);
        assert_eq!(pv.has_path_rules, 1);
        assert!(!pv.has_capability(21));
    }

    #[test]
    fn test_mixed_rules_cap_mask_and_path() {
        let pv = PolicyValue::from_policy(&policy_with_cap_paths(&[
            ("cap_sys_admin", None),
            ("cap_net_raw", Some("/usr/bin/curl")),
        ]), 0);
        assert!(pv.has_capability(21));
        assert!(!pv.has_capability(13));
        assert_eq!(pv.has_path_rules, 1);
    }

    #[test]
    fn test_path_pattern_star_treated_as_no_path() {
        let pv = PolicyValue::from_policy(&policy_with_cap_paths(&[
            ("cap_sys_admin", Some("*")),
        ]), 0);
        assert!(pv.has_capability(21));
        assert_eq!(pv.has_path_rules, 0);
    }

    #[test]
    fn test_glob_prefix_compile() {
        let (mt, path) = compile_glob("/usr/bin/*");
        assert_eq!(mt, PATH_MATCH_PREFIX);
        assert_eq!(path, "/usr/bin/");
    }

    #[test]
    fn test_glob_exact_compile() {
        let (mt, path) = compile_glob("/usr/bin/curl");
        assert_eq!(mt, PATH_MATCH_EXACT);
        assert_eq!(path, "/usr/bin/curl");
    }

    #[test]
    fn test_glob_mid_wildcard_compile() {
        let (mt, path) = compile_glob("/usr/bin/c*rl");
        assert_eq!(mt, PATH_MATCH_PREFIX);
        assert_eq!(path, "/usr/bin/c");
    }

    #[test]
    fn test_cap_path_rule_creation() {
        let rule = CapPathRule::new(21, "/usr/bin/curl").unwrap();
        assert_eq!(rule.cap_mask, 1u64 << 21);
        assert_eq!(rule.match_type, PATH_MATCH_EXACT);
        assert_eq!(rule.path_str(), "/usr/bin/curl");
    }

    #[test]
    fn test_cap_path_rule_prefix() {
        let rule = CapPathRule::new(13, "/usr/bin/*").unwrap();
        assert_eq!(rule.cap_mask, 1u64 << 13);
        assert_eq!(rule.match_type, PATH_MATCH_PREFIX);
        assert_eq!(rule.path_str(), "/usr/bin/");
    }

    #[test]
    #[should_panic]
    fn test_cap_path_rule_long_path_panics() {
        let long_path = "/usr/bin/".to_string() + &"a".repeat(300);
        let _ = CapPathRule::new(21, &long_path).unwrap();
    }

    #[test]
    fn test_update_from_security_policy_path_rules() {
        let loader = EbpfLoader::new();
        loader.load_programs().unwrap();
        let policy = policy_with_cap_paths(&[
            ("cap_net_raw", Some("/usr/bin/curl")),
            ("cap_sys_admin", Some("/usr/sbin/*")),
            ("cap_sys_ptrace", None),
        ]);
        loader.update_from_security_policy(123, &policy, 0).unwrap();

        let pv = loader.get_policy(123).unwrap();
        assert!(pv.has_capability(19));
        assert!(!pv.has_capability(13));
        assert!(!pv.has_capability(21));
        assert_eq!(pv.has_path_rules, 1);

        let rules = loader.get_cap_path_rules(123).unwrap();
        assert_eq!(rules.count, 2);
        assert_eq!(rules.rules[0].cap_mask, 1u64 << 13);
        assert_eq!(rules.rules[0].match_type, PATH_MATCH_EXACT);
        assert_eq!(rules.rules[1].cap_mask, 1u64 << 21);
        assert_eq!(rules.rules[1].match_type, PATH_MATCH_PREFIX);
    }

    #[test]
    fn test_update_from_security_policy_no_path_rules() {
        let loader = EbpfLoader::new();
        loader.load_programs().unwrap();
        let policy = policy_with_caps(&["cap_sys_admin"]);
        loader.update_from_security_policy(456, &policy, 0).unwrap();

        let pv = loader.get_policy(456).unwrap();
        assert!(pv.has_capability(21));
        assert_eq!(pv.has_path_rules, 0);
        assert!(loader.get_cap_path_rules(456).is_none());
    }

    #[test]
    fn test_remove_policy_clears_path_rules() {
        let loader = EbpfLoader::new();
        loader.load_programs().unwrap();
        let policy = policy_with_cap_paths(&[("cap_net_raw", Some("/usr/bin/curl"))]);
        loader.update_from_security_policy(789, &policy, 0).unwrap();
        assert!(loader.get_cap_path_rules(789).is_some());

        loader.remove_policy(789).unwrap();
        assert!(loader.get_cap_path_rules(789).is_none());
        assert!(loader.get_policy(789).is_none());
    }

    #[test]
    fn test_fs_path_rule_creation() {
        let rule = FsPathRule::new("rw", "/etc/shadow").unwrap();
        assert_eq!(rule.perm_mask, FS_PERM_READ | FS_PERM_WRITE);
        assert_eq!(rule.match_type, PATH_MATCH_EXACT);
        assert_eq!(rule.path_str(), "/etc/shadow");
    }

    #[test]
    fn test_fs_path_rule_prefix() {
        let rule = FsPathRule::new("r", "/proc/*").unwrap();
        assert_eq!(rule.perm_mask, FS_PERM_READ);
        assert_eq!(rule.match_type, PATH_MATCH_PREFIX);
        assert_eq!(rule.path_str(), "/proc/");
    }

    #[test]
    fn test_fs_path_rule_rwx() {
        let rule = FsPathRule::new("rwx", "/tmp/*").unwrap();
        assert_eq!(rule.perm_mask, FS_PERM_READ | FS_PERM_WRITE | FS_PERM_EXEC);
    }

    #[test]
    fn test_fs_path_rule_empty_attrs() {
        let rule = FsPathRule::new("", "/secret/*").unwrap();
        assert_eq!(rule.perm_mask, 0);
    }

    #[test]
    fn test_attrs_to_perm_mask_case_insensitive() {
        assert_eq!(attrs_to_perm_mask("RWX"), FS_PERM_READ | FS_PERM_WRITE | FS_PERM_EXEC);
        assert_eq!(attrs_to_perm_mask("R"), FS_PERM_READ);
    }

    #[test]
    fn test_update_from_security_policy_fs_rules() {
        let loader = EbpfLoader::new();
        loader.load_programs().unwrap();
        let policy = SecurityPolicy {
            enforcement_mode: "block".to_string(),
            default_action: "allow".to_string(),
            privilege_escalation_rules: vec![],
            filesystem_access_rules: vec![
                FilesystemRule { path_prefix: "/etc/shadow".to_string(), attrs: "rw".to_string() },
                FilesystemRule { path_prefix: "/proc/*".to_string(), attrs: "r".to_string() },
            ],
            network_rules: vec![],
        };
        loader.update_from_security_policy(111, &policy, 0).unwrap();

        let rules = loader.get_fs_path_rules(111).unwrap();
        assert_eq!(rules.count, 2);
        assert_eq!(rules.rules[0].perm_mask, FS_PERM_READ | FS_PERM_WRITE);
        assert_eq!(rules.rules[0].match_type, PATH_MATCH_EXACT);
        assert_eq!(rules.rules[1].perm_mask, FS_PERM_READ);
        assert_eq!(rules.rules[1].match_type, PATH_MATCH_PREFIX);
    }

    #[test]
    fn test_remove_policy_clears_fs_rules() {
        let loader = EbpfLoader::new();
        loader.load_programs().unwrap();
        let policy = SecurityPolicy {
            enforcement_mode: "block".to_string(),
            default_action: "allow".to_string(),
            privilege_escalation_rules: vec![],
            filesystem_access_rules: vec![
                FilesystemRule { path_prefix: "/proc/*".to_string(), attrs: "r".to_string() },
            ],
            network_rules: vec![],
        };
        loader.update_from_security_policy(222, &policy, 0).unwrap();
        assert!(loader.get_fs_path_rules(222).is_some());

        loader.remove_policy(222).unwrap();
        assert!(loader.get_fs_path_rules(222).is_none());
    }

    #[test]
    fn test_parse_ip() {
        assert_eq!(parse_ip("8.8.8.8").unwrap(), 0x08080808);
        assert_eq!(parse_ip("0.0.0.0").unwrap(), 0);
        assert_eq!(parse_ip("1.2.3.4").unwrap(), 0x01020304);
    }

    #[test]
    fn test_parse_target_wildcard() {
        let (ip, mask) = parse_target("*").unwrap();
        assert_eq!(ip, 0);
        assert_eq!(mask, 0);
    }

    #[test]
    fn test_parse_target_exact() {
        let (ip, mask) = parse_target("8.8.8.8").unwrap();
        assert_eq!(ip, 0x08080808);
        assert_eq!(mask, 0xFFFFFFFF);
    }

    #[test]
    fn test_parse_target_cidr() {
        let (ip, mask) = parse_target("10.0.0.0/8").unwrap();
        assert_eq!(ip, 0x0A000000);
        assert_eq!(mask, 0xFF000000);

        let (ip, mask) = parse_target("192.168.1.0/24").unwrap();
        assert_eq!(ip, 0xC0A80100);
        assert_eq!(mask, 0xFFFFFF00);
    }

    #[test]
    fn test_parse_port() {
        assert_eq!(parse_port("443").unwrap(), 443);
        assert_eq!(parse_port("*").unwrap(), 0);
        assert_eq!(parse_port("").unwrap(), 0);
    }

    #[test]
    fn test_parse_protocol() {
        assert_eq!(parse_protocol("tcp").unwrap(), NET_PROTOCOL_TCP);
        assert_eq!(parse_protocol("UDP").unwrap(), NET_PROTOCOL_UDP);
        assert_eq!(parse_protocol("*").unwrap(), NET_PROTOCOL_ANY);
    }

    #[test]
    fn test_network_rule_from_config_block() {
        let rule = NetworkRule {
            operation: "connect".to_string(),
            target: "8.8.8.8".to_string(),
            port: "53".to_string(),
            protocol: "udp".to_string(),
            action: "block".to_string(),
        };
        let bpf_rule = NetworkRuleBpf::from_rule(&rule).unwrap();
        assert_eq!(bpf_rule.target_ip, 0x08080808);
        assert_eq!(bpf_rule.target_mask, 0xFFFFFFFF);
        assert_eq!(bpf_rule.port, 53);
        assert_eq!(bpf_rule.protocol, NET_PROTOCOL_UDP);
        assert_eq!(bpf_rule.action, NET_ACTION_BLOCK);
    }

    #[test]
    fn test_network_rule_from_config_redirect() {
        let rule = NetworkRule {
            operation: "connect".to_string(),
            target: "*".to_string(),
            port: "443".to_string(),
            protocol: "tcp".to_string(),
            action: "redirect_to_proxy".to_string(),
        };
        let bpf_rule = NetworkRuleBpf::from_rule(&rule).unwrap();
        assert_eq!(bpf_rule.target_ip, 0);
        assert_eq!(bpf_rule.target_mask, 0);
        assert_eq!(bpf_rule.port, 443);
        assert_eq!(bpf_rule.protocol, NET_PROTOCOL_TCP);
        assert_eq!(bpf_rule.action, NET_ACTION_REDIRECT);
    }

    #[test]
    fn test_network_rule_from_config_non_connect_skipped() {
        let rule = NetworkRule {
            operation: "bind".to_string(),
            target: "*".to_string(),
            port: "*".to_string(),
            protocol: "*".to_string(),
            action: "allow".to_string(),
        };
        assert!(NetworkRuleBpf::from_rule(&rule).is_err());
    }

    #[test]
    fn test_update_from_security_policy_network_rules() {
        let loader = EbpfLoader::new();
        loader.load_programs().unwrap();
        let policy = SecurityPolicy {
            enforcement_mode: "block".to_string(),
            default_action: "allow".to_string(),
            privilege_escalation_rules: vec![],
            filesystem_access_rules: vec![],
            network_rules: vec![
                NetworkRule {
                    operation: "connect".to_string(),
                    target: "8.8.8.8".to_string(),
                    port: "53".to_string(),
                    protocol: "udp".to_string(),
                    action: "block".to_string(),
                },
                NetworkRule {
                    operation: "connect".to_string(),
                    target: "*".to_string(),
                    port: "443".to_string(),
                    protocol: "tcp".to_string(),
                    action: "redirect_to_proxy".to_string(),
                },
            ],
        };
        loader.update_from_security_policy(333, &policy, 0).unwrap();

        let rules = loader.get_network_rules(333).unwrap();
        assert_eq!(rules.count, 2);
        assert_eq!(rules.rules[0].target_ip, 0x08080808);
        assert_eq!(rules.rules[0].action, NET_ACTION_BLOCK);
        assert_eq!(rules.rules[1].target_ip, 0);
        assert_eq!(rules.rules[1].action, NET_ACTION_REDIRECT);
    }

    #[test]
    fn test_remove_policy_clears_network_rules() {
        let loader = EbpfLoader::new();
        loader.load_programs().unwrap();
        let policy = SecurityPolicy {
            enforcement_mode: "block".to_string(),
            default_action: "allow".to_string(),
            privilege_escalation_rules: vec![],
            filesystem_access_rules: vec![],
            network_rules: vec![NetworkRule {
                operation: "connect".to_string(),
                target: "*".to_string(),
                port: "*".to_string(),
                protocol: "*".to_string(),
                action: "block".to_string(),
            }],
        };
        loader.update_from_security_policy(444, &policy, 0).unwrap();
        assert!(loader.get_network_rules(444).is_some());

        loader.remove_policy(444).unwrap();
        assert!(loader.get_network_rules(444).is_none());
    }

    #[test]
    fn test_set_and_get_proxy() {
        let loader = EbpfLoader::new();
        assert_eq!(loader.get_proxy(), None);

        loader.load_programs().unwrap();
        let ip = parse_ip("127.0.0.1").unwrap();
        loader.set_proxy(ip, 8443, 9090, ip).unwrap();
        assert_eq!(loader.get_proxy(), Some((ip, 8443, 9090, ip)));
    }

    #[test]
    fn test_set_proxy_before_load_fails() {
        let loader = EbpfLoader::new();
        let ip = parse_ip("127.0.0.1").unwrap();
        assert!(loader.set_proxy(ip, 8443, 9090, ip).is_err());
    }

    #[test]
    fn test_unload_clears_proxy() {
        let loader = EbpfLoader::new();
        loader.load_programs().unwrap();
        let ip = parse_ip("127.0.0.1").unwrap();
        loader.set_proxy(ip, 9999, 9090, ip).unwrap();
        assert_eq!(loader.get_proxy(), Some((ip, 9999, 9090, ip)));

        loader.unload_programs().unwrap();
        assert_eq!(loader.get_proxy(), None);
    }
}
