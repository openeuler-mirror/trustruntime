use agentsandbox_config::FilesystemRule;

/// Evaluates whether a filesystem access should be blocked.
/// Returns true if path_prefix matches and access attributes are in the rule's attrs.
pub fn should_block(path: &str, access_attr: char, rules: &[FilesystemRule]) -> bool {
    rules.iter().any(|r| {
        if r.path_prefix.ends_with('*') {
            let prefix = &r.path_prefix[..r.path_prefix.len() - 1];
            path.starts_with(prefix) && r.attrs.contains(access_attr)
        } else {
            path == r.path_prefix && r.attrs.contains(access_attr)
        }
    })
}
