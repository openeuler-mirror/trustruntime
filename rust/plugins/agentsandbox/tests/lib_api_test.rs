use agentsandbox_proxy::ProxyLib;
use agentsandbox_proxy::ca::CaProvider;
use agentsandbox_config::FilterConfig;
use agentsandbox_proxy::{Phase, Target, HandlerResult};

#[test]
fn test_lib_api_filter_config() {
    let _ca = CaProvider::from_pem(b"-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n");
}

#[test]
fn test_filter_config_set_get_remove() {
    let _ca = CaProvider::from_pem(b"-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n");
    let lib = ProxyLib::new(_ca);
    let fc = FilterConfig {
        default_policy: "deny".to_string(),
        audit_enabled: true,
        policy_change_strategy: "drain".to_string(),
        whitelist: vec![],
        blacklist: vec![],
    };
    lib.set_filter_config("grp-001", fc.clone());
    assert!(lib.forward_request("grp-001", "test.com", "GET", "/").is_ok());
    lib.remove_filter_config("grp-001");
    assert!(lib.forward_request("grp-001", "test.com", "GET", "/").is_err());
}
