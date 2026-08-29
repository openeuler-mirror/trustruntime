use agentsandbox_config::CapabilityRule;

/// Evaluates whether a process capability should be blocked.
/// Returns true if capability matches a rule in privilege_escalation_rules.
pub fn should_block(capability: &str, rules: &[CapabilityRule]) -> bool {
    rules.iter().any(|r| r.capability == capability)
}
