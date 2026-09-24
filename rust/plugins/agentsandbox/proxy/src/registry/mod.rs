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

//! 运行态注册面（容器键控，2026-09-01 API 重设计：单容器实现 + 多容器扩展预留）。
//!
//! 配置与 CA 均按 `container_id` 键控存储（`HashMap<container_id, ...>`——
//! 多容器语义就绪）；当前单容器模型下仅一个条目。容器身份由**监听端点静态
//! 绑定**（[`crate::facade::proxy_init`] 的 forwarding 端点）——服务管道按
//! 端点关联的 container_id 查表，零运行时身份反查。
//!
//! 监听绑定职责已移至 facade（proxy_init 直管 TcpListener）；本模块只持有
//! 配置、CA、binary resolver 三类运行态。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use crate::error::{CaError, ConfigError};
use crate::model::{CaCert, FilterConfig, Protocol, ResolverOutput};

/// 连接身份解析回调（K7，2026-09-05 重定义）：入参
/// `(source, target, protocol)`——发起方地址、本地监听地址、连接协议；
/// 输出 [`ResolverOutput`]（容器身份 + 进程二进制路径）。
///
/// 调用语义：**每连接一次**（accept 后同步调用，连接级缓存）；
/// 返回 `None` / container_id 空串 = 身份不可解析——该连接 fail-closed
///（配置查表 miss → 503；TLS 侧 CA 查表 miss → 拒绝握手）。
pub type Resolver = Arc<dyn Fn(SocketAddr, SocketAddr, Protocol) -> Option<ResolverOutput> + Send + Sync>;

/// filter_config 结构校验器（K10，AR-002 实现；本模块经注入消费以保持边界）。
pub type ConfigValidator = Arc<dyn Fn(&FilterConfig) -> Result<(), ConfigError> + Send + Sync>;
/// CA 格式校验器（rustls/X.509 解析，cert 子模块实现；经注入消费）。
pub type CaValidator = Arc<dyn Fn(&CaCert) -> Result<(), CaError> + Send + Sync>;

/// 运行态注册面：按 container_id 键控的配置与 CA 唯一持有方。
pub struct Registry {
    /// 容器过滤配置（container_id → FilterConfig；同 id 覆盖）。
    configs: RwLock<HashMap<String, FilterConfig>>,
    /// 容器 CA 材料（container_id → CaCert；同 id 覆盖）。
    cas: RwLock<HashMap<String, CaCert>>,
    /// binary 解析回调（进程级单份；重复注册覆盖）。
    resolver: RwLock<Option<Resolver>>,
    config_validator: Option<ConfigValidator>,
    ca_validator: Option<CaValidator>,
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

impl Registry {
    /// 创建注册面。
    pub fn new() -> Self {
        Self {
            configs: RwLock::new(HashMap::new()),
            cas: RwLock::new(HashMap::new()),
            resolver: RwLock::new(None),
            config_validator: None,
            ca_validator: None,
        }
    }

    /// 注入 filter_config 结构校验器（未注入时不校验，供测试使用）。
    pub fn with_config_validator(mut self, v: ConfigValidator) -> Self {
        self.config_validator = Some(v);
        self
    }

    /// 注入 CA 格式校验器。
    pub fn with_ca_validator(mut self, v: CaValidator) -> Self {
        self.ca_validator = Some(v);
        self
    }

    /// 设置容器过滤配置（按 container_id 键控，同 id 覆盖）。
    ///
    /// 语义：结构非法拒绝并保持该容器旧配置（fail-closed）；**存储前
    /// 归一化排序**（2026-09-16）——rule_list 按 host.prio 降序（稳定
    /// 排序）、各规则集内 targetrules/binaryrules 按 action rank
    ///（deny>alert>allow）排序——evaluate 的有序前置条件由本存储层
    /// 单点保证（任意注入路径生效）。
    pub fn set_container_config(
        &self,
        container_id: &str,
        mut fc: FilterConfig,
    ) -> Result<(), ConfigError> {
        if container_id.is_empty() {
            return Err(ConfigError::Format);
        }
        match &self.config_validator {
            Some(validate) => validate(&fc)?,
            None => crate::log_warn!(
                "registry",
                "config validator not injected; filter_config accepted without structure validation"
            ),
        }
        normalize_rule_order(&mut fc);
        // 配置热更新落地确认（info——release 可见；HC 推送结果可观测）。
        crate::log_info!(
            "registry",
            "container config updated: container={} rulesets={}",
            container_id,
            fc.rule_list.len()
        );
        let mut configs = crate::lock_util::recovered(self.configs.write(), "registry");
        configs.insert(container_id.to_string(), fc);
        Ok(())
    }

    /// 清除容器过滤配置：无该容器配置返回 `ConfigError::NotFound`；
    /// 清除后该容器流量 fail-closed（config_not_found）。
    pub fn remove_container_policy(&self, container_id: &str) -> Result<(), ConfigError> {
        let mut configs = crate::lock_util::recovered(self.configs.write(), "registry");
        configs
            .remove(container_id)
            .map(|_| ())
            .ok_or(ConfigError::NotFound)
    }

    /// 取容器过滤配置快照（服务管道按端点绑定的 container_id 查询）。
    pub fn config_for(&self, container_id: &str) -> Option<FilterConfig> {
        let configs = crate::lock_util::recovered(self.configs.read(), "registry");
        configs.get(container_id).cloned()
    }

    /// 设置容器 CA（按 container_id 键控，同 id 覆盖；校验经注入 validator）。
    pub fn set_container_ca(&self, container_id: &str, ca: CaCert) -> Result<(), CaError> {
        if container_id.is_empty() {
            // container_id 空属调用方程序错误——Err 收敛（CaError 单变体）。
            return Err(CaError::Invalid);
        }
        match &self.ca_validator {
            Some(validate) => validate(&ca)?,
            None => crate::log_warn!(
                "registry",
                "ca validator not injected; ca material accepted without format validation"
            ),
        }
        let mut cas = crate::lock_util::recovered(self.cas.write(), "registry");
        cas.insert(container_id.to_string(), ca);
        Ok(())
    }

    /// 取容器 CA 材料快照（MITM 动态证书签发的 CA 来源）。
    pub fn ca_for(&self, container_id: &str) -> Option<CaCert> {
        let cas = crate::lock_util::recovered(self.cas.read(), "registry");
        cas.get(container_id).cloned()
    }

    /// 注册 binary 解析回调（K7）：重复注册覆盖。
    pub fn register_binary_resolver(&self, resolver: Resolver) {
        let mut slot = crate::lock_util::recovered(self.resolver.write(), "registry");
        *slot = Some(resolver);
    }

    /// 取当前 binary 解析回调。
    pub fn binary_resolver(&self) -> Option<Resolver> {
        crate::lock_util::recovered(self.resolver.read(), "registry").clone()
    }
}

/// 规则顺序归一化（存储前——2026-09-16）：
/// - rule_list 按 `host.prio` **降序**（稳定排序——同 prio 保持配置序）；
/// - 各规则集内 targetrules/binaryrules 按 action rank（deny=0 > alert=1
///   > allow=2）稳定排序——黑名单类规则先于白名单类评估。
///
/// evaluate 依赖该序实现"首个命中即决策"（匹配效率）。
fn normalize_rule_order(fc: &mut FilterConfig) {
    fn action_rank(a: crate::model::RuleAction) -> u8 {
        match a {
            crate::model::RuleAction::Deny => 0,
            crate::model::RuleAction::Alert => 1,
            crate::model::RuleAction::Allow => 2,
        }
    }
    fc.rule_list.sort_by_key(|rs| std::cmp::Reverse(rs.host.prio));
    for rs in &mut fc.rule_list {
        rs.targetrules.sort_by_key(|t| action_rank(t.action));
        rs.binaryrules.sort_by_key(|b| action_rank(b.action));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CaError;
    use crate::model::{FilterConfig, HostRule, HostType, Policy, RuleAction, RuleSet, TargetRule};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn fc(domain: &str) -> FilterConfig {
        FilterConfig {
            default_policy: Policy::Deny,
            rule_list: vec![RuleSet {
                rule_id: None,
                name: "test-rs".to_string(),
                host: HostRule {
                    host_type: HostType::Host,
                    addr: None,
                    context: Some(domain.to_string()),
                    prio: 100,
                },
                targetrules: vec![TargetRule {
                    method: "*".to_string(),
                    path: "*".to_string(),
                    action: RuleAction::Allow,
                }],
                binaryrules: vec![],
                port: None,
            }],
        }
    }

    fn ca() -> CaCert {
        CaCert {
            cert_pem: vec![1, 2, 3],
            key_pem: vec![4, 5, 6],
        }
    }

    // 容器配置：set 覆盖 / config_for 查询 / remove NotFound。
    //（串行锁：无 validator 路径发出全局 log_warn——与 logging 计数
    // 测试互斥，防回调断言交叉污染。）
    #[test]
    fn container_config_set_query_remove() {
        let _serial = crate::logging::testing::serial_guard();
        let reg = Registry::new();
        assert_eq!(reg.config_for("c1"), None);
        reg.set_container_config("c1", fc("a.com")).unwrap();
        assert_eq!(reg.config_for("c1"), Some(fc("a.com")));
        // 同容器覆盖。
        reg.set_container_config("c1", fc("b.com")).unwrap();
        assert_eq!(reg.config_for("c1"), Some(fc("b.com")));
        // 多容器隔离（扩展预留语义验证）。
        reg.set_container_config("c2", fc("c.com")).unwrap();
        assert_eq!(reg.config_for("c1"), Some(fc("b.com")));
        assert_eq!(reg.config_for("c2"), Some(fc("c.com")));
        // remove。
        reg.remove_container_policy("c1").unwrap();
        assert_eq!(reg.config_for("c1"), None);
        assert_eq!(reg.config_for("c2"), Some(fc("c.com")));
        assert_eq!(
            reg.remove_container_policy("c1"),
            Err(ConfigError::NotFound)
        );
    }

    // 空容器 ID 拒绝。
    #[test]
    fn empty_container_id_rejected() {
        let reg = Registry::new();
        assert_eq!(
            reg.set_container_config("", fc("a.com")),
            Err(ConfigError::Format)
        );
        assert_eq!(reg.set_container_ca("", ca()), Err(CaError::Invalid));
    }

    // 容器配置：结构非法拒绝并保持旧配置。
    #[test]
    fn invalid_config_rejected_keeps_old() {
        let reg = Registry::new().with_config_validator(Arc::new(|fc| {
            if fc
                .rule_list
                .iter()
                .any(|rs| rs.host.context.as_deref() == Some("b.com"))
            {
                Err(ConfigError::Format)
            } else {
                Ok(())
            }
        }));
        reg.set_container_config("c1", fc("a.com")).unwrap();
        assert_eq!(
            reg.set_container_config("c1", fc("b.com")),
            Err(ConfigError::Format)
        );
        assert_eq!(reg.config_for("c1"), Some(fc("a.com")));
    }

    // 容器 CA：set 覆盖 / ca_for 查询 / 多容器隔离。
    //（串行锁：无 validator 路径发出全局 log_warn——同上互斥。）
    #[test]
    fn container_ca_set_query() {
        let _serial = crate::logging::testing::serial_guard();
        let reg = Registry::new();
        assert!(reg.ca_for("c1").is_none());
        let first = ca();
        reg.set_container_ca("c1", first.clone()).unwrap();
        let got = reg.ca_for("c1").expect("ca exists");
        assert_eq!(got.cert_pem, first.cert_pem);
        assert_eq!(got.key_pem, first.key_pem);
        // 覆盖。
        let second = CaCert {
            cert_pem: vec![7],
            key_pem: vec![8],
        };
        reg.set_container_ca("c1", second.clone()).unwrap();
        let got = reg.ca_for("c1").expect("ca exists");
        assert_eq!(got.cert_pem, second.cert_pem);
        assert_eq!(got.key_pem, second.key_pem);
        // 多容器隔离（c2 有 CA、c1 不受影响——经各自 cert_pem 断言）。
        reg.set_container_ca("c2", ca()).unwrap();
        assert!(reg.ca_for("c2").is_some());
        assert_eq!(reg.ca_for("c1").unwrap().cert_pem, second.cert_pem);
    }

    // CA 校验器：非法拒绝并保持旧 CA。
    #[test]
    fn ca_validator_rejects_keeps_old() {
        let reg = Registry::new().with_ca_validator(Arc::new(|c| {
            if c.cert_pem == [9u8] {
                Err(CaError::Invalid)
            } else {
                Ok(())
            }
        }));
        let good = ca();
        reg.set_container_ca("c1", good.clone()).unwrap();
        let bad = CaCert {
            cert_pem: vec![9],
            key_pem: vec![9],
        };
        assert_eq!(
            reg.set_container_ca("c1", bad),
            Err(CaError::Invalid)
        );
        let kept = reg.ca_for("c1").expect("old ca kept");
        assert_eq!(kept.cert_pem, good.cert_pem);
    }

    // resolver 注册覆盖与未注册语义（新签名：source/target/protocol →
    // 容器身份 + binary_path）。
    #[test]
    fn resolver_registration() {
        let reg = Registry::new();
        assert!(reg.binary_resolver().is_none());
        let mk = |id: &str| -> Resolver {
            let id = id.to_string();
            Arc::new(move |_src, _dst, _proto| {
                Some(ResolverOutput {
                    container_id: id.clone(),
                    binary_path: "/usr/bin/test".to_string(),
                })
            })
        };
        reg.register_binary_resolver(mk("first"));
        reg.register_binary_resolver(mk("second"));
        let r = reg.binary_resolver().expect("resolver registered");
        let src: SocketAddr = "10.0.0.1:40000".parse().unwrap();
        let dst: SocketAddr = "10.0.0.2:443".parse().unwrap();
        let out = r(src, dst, Protocol::Tcp).expect("resolved");
        assert_eq!(out.container_id, "second");
        assert_eq!(out.binary_path, "/usr/bin/test");
    }

    // 覆盖语义原子计数（并发安全形态简化验证）。
    #[test]
    fn set_overwrite_count() {
        let reg = Registry::new();
        let count = Arc::new(AtomicUsize::new(0));
        let c = count.clone();
        let reg = reg.with_config_validator(Arc::new(move |_| {
            c.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }));
        reg.set_container_config("c1", fc("a.com")).unwrap();
        reg.set_container_config("c1", fc("b.com")).unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    // 归一化排序（2026-09-16）：rule_list 按 prio 降序；规则集内
    // targetrules/binaryrules 按 deny>alert>allow——evaluate 有序前置
    // 条件的存储层单点保证。
    #[test]
    fn rule_order_normalized_on_store() {
        let reg = Registry::new();
        let fc = FilterConfig {
            default_policy: Policy::Deny,
            rule_list: vec![
                RuleSet {
                    rule_id: None,
                    name: "low".to_string(),
                    host: HostRule {
                        host_type: HostType::Host,
                        addr: None,
                        context: Some("low.com".to_string()),
                        prio: 10,
                    },
                    targetrules: vec![TargetRule {
                        method: "*".to_string(),
                        path: "*".to_string(),
                        action: RuleAction::Allow,
                    }],
                    binaryrules: vec![],
                    port: None,
                },
                RuleSet {
                    rule_id: None,
                    name: "high".to_string(),
                    host: HostRule {
                        host_type: HostType::Host,
                        addr: None,
                        context: Some("high.com".to_string()),
                        prio: 999,
                    },
                    // 乱序 action：allow → deny → alert（存储后应归一
                    // deny → alert → allow）。
                    targetrules: vec![
                        TargetRule {
                            method: "*".to_string(),
                            path: "*".to_string(),
                            action: RuleAction::Allow,
                        },
                        TargetRule {
                            method: "GET".to_string(),
                            path: "/x".to_string(),
                            action: RuleAction::Deny,
                        },
                        TargetRule {
                            method: "POST".to_string(),
                            path: "/y".to_string(),
                            action: RuleAction::Alert,
                        },
                    ],
                    binaryrules: vec![],
                    port: None,
                },
            ],
        };
        reg.set_container_config("c1", fc.clone()).unwrap();
        let stored = reg.config_for("c1").expect("stored");
        // prio 降序：high(999) 在前。
        assert_eq!(stored.rule_list[0].name, "high");
        assert_eq!(stored.rule_list[1].name, "low");
        // action rank：deny → alert → allow。
        let actions: Vec<RuleAction> =
            stored.rule_list[0].targetrules.iter().map(|t| t.action).collect();
        assert_eq!(
            actions,
            vec![RuleAction::Deny, RuleAction::Alert, RuleAction::Allow]
        );
        // 原 fc 不被修改（归一化发生在存储副本上）。
        assert_eq!(fc.rule_list[0].name, "low");
    }
}
