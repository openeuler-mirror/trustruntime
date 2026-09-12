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

//! lib 门面契约测试（容器端点模型：TC1/TC2/TC3/TC5/TC9 重构版 +
//! proxy_init 校验）。

use std::sync::{Arc, Mutex};

use agentsandbox_proxy::error::{CaError, ConfigError};
use agentsandbox_proxy::facade::testing::{self, InstalledRuntime};
use agentsandbox_proxy::facade::RuntimeRegistry;
use agentsandbox_proxy::logging::{LogEvent, LogSink, LogSinkError};
    use agentsandbox_proxy::model::{CaCert, FilterConfig, InferenceRoute, Policy, RuleEntry};
use agentsandbox_proxy::registry::Resolver;

/// fake 记录的委托调用（入参摘要）。
#[derive(Debug, Clone, PartialEq)]
enum Call {
    SetConfig(String),
    RemovePolicy(String),
    SetCa(String),
    RegisterBinaryResolver,
    RegisterLogSink,
}

/// fake 运行态（记录委托序列与配置状态）。
struct FakeRegistry {
    calls: Mutex<Vec<Call>>,
    config: Mutex<Option<(String, FilterConfig)>>,
    ca: Mutex<Option<String>>,
}

impl FakeRegistry {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::new(Vec::new()),
            config: Mutex::new(None),
            ca: Mutex::new(None),
        })
    }

    fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }
}

impl RuntimeRegistry for FakeRegistry {
    fn set_container_config(
        &self,
        container_id: &str,
        fc: FilterConfig,
    ) -> Result<(), ConfigError> {
        self.calls
            .lock()
            .unwrap()
            .push(Call::SetConfig(container_id.to_string()));
        *self.config.lock().unwrap() = Some((container_id.to_string(), fc));
        Ok(())
    }

    fn remove_container_policy(&self, container_id: &str) -> Result<(), ConfigError> {
        self.calls
            .lock()
            .unwrap()
            .push(Call::RemovePolicy(container_id.to_string()));
        let mut config = self.config.lock().unwrap();
        match config.take() {
            Some((existing, _)) if existing == container_id => Ok(()),
            _ => Err(ConfigError::NotFound),
        }
    }

    fn set_container_ca(&self, container_id: &str, _ca: CaCert) -> Result<(), CaError> {
        self.calls
            .lock()
            .unwrap()
            .push(Call::SetCa(container_id.to_string()));
        *self.ca.lock().unwrap() = Some(container_id.to_string());
        Ok(())
    }

    fn register_binary_resolver(&self, _resolver: Resolver) {
        self.calls
            .lock()
            .unwrap()
            .push(Call::RegisterBinaryResolver);
    }

    fn register_log_sink(&self, _sink: LogSink) {
        self.calls.lock().unwrap().push(Call::RegisterLogSink);
    }
}

fn valid_fc(domain: &str) -> FilterConfig {
    FilterConfig {
        default_policy: Policy::Deny,
        whitelist: vec![RuleEntry {
            domain: domain.to_string(),
            method: "*".to_string(),
            uri: Some("/v1/*".to_string()),
            binary: None,
            target_ip: None,
            target_port: None,
        }],
        blacklist: vec![],
    }
}

/// uri 非法（首尾同 `*`）的 fc（K10 非法结构）。
fn invalid_fc() -> FilterConfig {
    FilterConfig {
        default_policy: Policy::Deny,
        whitelist: vec![RuleEntry {
            domain: "a.com".to_string(),
            method: "*".to_string(),
            uri: Some("*v1*".to_string()),
            binary: None,
            target_ip: None,
            target_port: None,
        }],
        blacklist: vec![],
    }
}

fn noop_sink() -> LogSink {
    Arc::new(|_event: &LogEvent| Ok::<(), LogSinkError>(()))
}

fn noop_resolver() -> Resolver {
    Arc::new(|_src, _dst, _proto| {
        Some(agentsandbox_proxy::model::ResolverOutput {
            container_id: "c-001".to_string(),
            binary_path: "/usr/bin/python3".to_string(),
        })
    })
}

fn ca() -> CaCert {
    CaCert {
        cert_pem: vec![0x30, 0x82],
        key_pem: vec![0x30, 0x82],
    }
}

// TC1（重构版）：完整初始化序列——set_container_config → set_container_ca
// → register_log_sink → register_binary_resolver，fake 收到对应委托。
#[test]
fn tc1_container_api_delegation() {
    let fake = FakeRegistry::new();
    let _rt: InstalledRuntime = testing::install(fake.clone());

    agentsandbox_proxy::set_container_config("c-001", valid_fc("api.example.com")).unwrap();
    agentsandbox_proxy::set_container_ca("c-001", ca()).unwrap();
    agentsandbox_proxy::register_log_sink(noop_sink());
    agentsandbox_proxy::register_binary_resolver(noop_resolver());

    assert_eq!(
        fake.calls(),
        vec![
            Call::SetConfig("c-001".to_string()),
            Call::SetCa("c-001".to_string()),
            Call::RegisterLogSink,
            Call::RegisterBinaryResolver,
        ],
        "委托序列与入参一致"
    );
    let (container, _fc) = fake.config.lock().unwrap().clone().unwrap();
    assert_eq!(container, "c-001");
}

// TC2：门面参数校验——非法入参在门面拦截（不触达内部注册面）。
#[test]
fn tc2_facade_parameter_validation() {
    let fake = FakeRegistry::new();
    let _rt = testing::install(fake.clone());

    // container_id 空串 → Format。
    assert_eq!(
        agentsandbox_proxy::set_container_config("", valid_fc("a.com")),
        Err(ConfigError::Format)
    );
    // K10 结构非法 → Format（门面拦截）。
    assert_eq!(
        agentsandbox_proxy::set_container_config("c-001", invalid_fc()),
        Err(ConfigError::Format)
    );
    // 委托未发生。
    assert!(fake.calls().is_empty(), "facade 校验应先于委托");
}

// TC3：set 结构非法 → Err(Format)，旧配置保持（委托不发生）。
#[test]
fn tc3_set_invalid_structure_keeps_old() {
    let fake = FakeRegistry::new();
    // 预置旧配置（fake 直接置态）。
    *fake.config.lock().unwrap() = Some(("c-001".to_string(), valid_fc("old.com")));
    let _rt = testing::install(fake.clone());

    assert_eq!(
        agentsandbox_proxy::set_container_config("c-002", invalid_fc()),
        Err(ConfigError::Format)
    );
    // 委托未发生（无 SetConfig 调用）。
    assert!(fake.calls().is_empty());
    // 旧配置保持。
    let (container, fc) = fake.config.lock().unwrap().clone().unwrap();
    assert_eq!(container, "c-001");
    assert_eq!(fc.whitelist[0].domain, "old.com");
}

// TC5（重构版）：remove 无该容器配置 → Err(NotFound)。
#[test]
fn tc5_remove_missing_container_policy() {
    let fake = FakeRegistry::new();
    let _rt = testing::install(fake.clone());

    assert_eq!(
        agentsandbox_proxy::remove_container_policy("c-none"),
        Err(ConfigError::NotFound)
    );
    // 已注册容器 remove 成功。
    agentsandbox_proxy::set_container_config("c-001", valid_fc("a.com")).unwrap();
    assert!(agentsandbox_proxy::remove_container_policy("c-001").is_ok());
    assert_eq!(
        agentsandbox_proxy::remove_container_policy("c-001"),
        Err(ConfigError::NotFound)
    );
}

// TC9：惰性初始化时序——未显式初始化时首次调用 API 自动初始化生产
// 运行态（不 panic，委托成功——生产 Registry 路径）。
#[test]
fn tc9_lazy_initialization() {
    let _rt = testing::clear();
    // 首次调用：惰性初始化（生产 Registry）+ 委托成功。
    assert!(agentsandbox_proxy::set_container_config("c-001", valid_fc("a.com")).is_ok());
    assert!(agentsandbox_proxy::remove_container_policy("c-001").is_ok());
    assert_eq!(
        agentsandbox_proxy::remove_container_policy("c-001"),
        Err(ConfigError::NotFound)
    );
}

// proxy_init 契约：参数校验（container_id 空 / 端口 0 → InvalidEndpoint）。
// （真实绑定路径归 e2e——本测试仅校验前置校验，避免端口资源依赖。）
#[tokio::test]
async fn proxy_init_validates_endpoints() {
    use agentsandbox_proxy::model::{ContainerEndpoint, ProxyConfig};
    use std::net::IpAddr;

    let mk = |port: u16| ContainerEndpoint {
        ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
        port,
    };
    let cfg = |f: &ContainerEndpoint, routes: Vec<InferenceRoute>| ProxyConfig {
        forwarding: f.clone(),
        inference_routes: routes,
    };
    let route = |host: &str, url: &str| InferenceRoute {
        host: host.to_string(),
        url: url.to_string(),
    };

    // forwarding 端口 0。
    assert!(matches!(
        agentsandbox_proxy::proxy_init(&cfg(&mk(0), vec![])),
        Err(agentsandbox_proxy::ProxyInitError::InvalidEndpoint)
    ));
    // 推理路由条目 host 空。
    assert!(matches!(
        agentsandbox_proxy::proxy_init(&cfg(&mk(19443), vec![route("", "/v1/chat")])),
        Err(agentsandbox_proxy::ProxyInitError::InvalidEndpoint)
    ));
    // 推理路由条目 url 空。
    assert!(matches!(
        agentsandbox_proxy::proxy_init(&cfg(&mk(19443), vec![route("api.example.com", "")])),
        Err(agentsandbox_proxy::ProxyInitError::InvalidEndpoint)
    ));
}
