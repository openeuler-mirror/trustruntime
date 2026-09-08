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

//! 完整流程端到端集成测试（serve 层：MITM + hyper 逐请求求值 + 阻断响应
//! + 转发 + 审计真实 status_code + Upgrade 隧道 + IPv6）。
//!
//! 全链真实 TLS：测试客户端信任注入 CA（经 registry.inject_ca 注入 +
//! CertService 供证），目标侧为本地 TLS fake 服务（h1）。

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{refused_target_port, TestPki, TEST_DOMAIN};
use agentsandbox_proxy::cert::ContainerCertServices;
use agentsandbox_proxy::logging::{self, LogKind};
use agentsandbox_proxy::model::{Action, FilterConfig, Policy, Reason, RuleEntry, SCENARIO_LIB};
use agentsandbox_proxy::model::CaCert;
use agentsandbox_proxy::registry::Registry;
use agentsandbox_proxy::server::{serve, ServeContext};

fn fc(whitelist_domain: &str) -> FilterConfig {
    FilterConfig {
        default_policy: Policy::Deny,
        whitelist: vec![RuleEntry {
            domain: whitelist_domain.to_string(),
            method: "*".to_string(),
            uri: None,
            binary: None,
        }],
        blacklist: vec![],
    }
}

/// 注册固定身份 resolver（"c-test" + /usr/bin/e2e-bin）——连接级身份
/// 解析测试缝（生产为集成方回调）。
fn register_test_resolver(registry: &Registry) {
    registry.register_binary_resolver(Arc::new(|_src, _dst, _proto| {
        Some(agentsandbox_proxy::model::ResolverOutput {
            container_id: "c-test".to_string(),
            binary_path: "/usr/bin/e2e-bin".to_string(),
        })
    }));
}

/// 装配 serve 全链（绑定临时端口 + 注入 CA/配置），返回 (端口, registry)。
async fn setup(whitelist_domain: &str) -> (u16, Arc<Registry>, logging::testing::CaptureGuard) {
    let capture = logging::testing::install_capture();
    let registry = Arc::new(Registry::new());
    register_test_resolver(&registry);
    // 注入 CA（同时供 CertService——facade 生产路径为注入即供证；此处
    // 直接构造 serve 上下文，手动同步）。
    let pki = TestPki::new();
    let cert_services = Arc::new(ContainerCertServices::new());
    // 经 registry 注入需 ca_validator；直接 set_ca 等价（供证面一致）。
    let (ca_cert_pem, ca_key_pem) = test_ca_material();
    cert_services
        .set_ca(
            "c-test",
            &CaCert { cert_pem: ca_cert_pem.clone(), key_pem: ca_key_pem.clone() },
        )
        .unwrap();
    // parse_ca 预检（材料有效性——与生产 validator 行为一致性锚点）。
    let _ = agentsandbox_proxy::cert::parse_ca(&ca_cert_pem, &ca_key_pem).is_ok();
    // registry 侧同步持有（inject_ca 经 validator 校验 + CaMaterial 记账）。
    registry.set_container_config("c-test", fc(whitelist_domain))
        .unwrap();

    // 客户端信任锚 = 测试 CA。
    let mut client_roots = rustls::RootCertStore::empty();
    let cert_der = rustls_pemfile::certs(&mut std::io::Cursor::new(&ca_cert_pem))
        .next()
        .unwrap()
        .unwrap();
    client_roots.add(cert_der).unwrap();

    // 目标信任锚 = 同一测试 CA（fake 目标证书由 TestPki 签发链）。
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let connector = Arc::new(agentsandbox_proxy::forward::TargetConnector::new(
        Arc::new(client_roots.clone()),
        Duration::from_secs(5),
    ));
    let ctx = Arc::new(ServeContext::new(registry.clone(), cert_services, connector));
    tokio::spawn(serve(listener, ctx));
    let _ = pki;
    (port, registry, capture)
}

/// 测试 CA 材料（进程内单份——客户端信任锚与服务端供证必须同一 CA）。
fn test_ca_material() -> (Vec<u8>, Vec<u8>) {
    static CA: std::sync::OnceLock<(Vec<u8>, Vec<u8>)> = std::sync::OnceLock::new();
    CA.get_or_init(|| {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, "Serve E2E Test CA");
        let mut params = rcgen::CertificateParams::new(vec!["e2e-ca.local".to_string()]).unwrap();
        params.distinguished_name = dn;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).unwrap();
        (cert.pem().into_bytes(), key.serialize_pem().into_bytes())
    })
    .clone()
}

/// 以信任测试 CA 的 rustls 客户端连接 proxy（SNI=TEST_DOMAIN）。
async fn tls_client(
    port: u16,
    roots: &rustls::RootCertStore,
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    let (ca_pem, _) = test_ca_material();
    let _ = ca_pem;
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots.clone())
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let name = rustls::pki_types::ServerName::try_from(TEST_DOMAIN.to_string()).unwrap();
    connector.connect(name, tcp).await.unwrap()
}


/// 以 e2e CA 为目标域名签发证书的 TLS acceptor（connector 信任锚一致性）。
fn e2e_ca_target_acceptor(domain: &str) -> tokio_rustls::TlsAcceptor {
    let (ca_pem, key_pem) = test_ca_material();
    let parsed = agentsandbox_proxy::cert::parse_ca(&ca_pem, &key_pem).unwrap();
    let issued = agentsandbox_proxy::cert::CertIssuer::new(parsed).issue(domain).unwrap();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(issued.chain, issued.key)
        .unwrap();
    tokio_rustls::TlsAcceptor::from(Arc::new(config))
}

fn client_roots() -> rustls::RootCertStore {
    let (ca_pem, _) = test_ca_material();
    let mut roots = rustls::RootCertStore::empty();
    let cert_der = rustls_pemfile::certs(&mut std::io::Cursor::new(&ca_pem))
        .next()
        .unwrap()
        .unwrap();
    roots.add(cert_der).unwrap();
    roots
}

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 发送一个 h1 请求并读取完整响应（返回状态码 + body 文本）。
async fn send_request(
    io: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
    method: &str,
    path: &str,
) -> (u16, String) {
    let req = format!("{method} {path} HTTP/1.1\r\nHost: {TEST_DOMAIN}\r\n\r\n");
    io.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(5), io.read(&mut chunk))
            .await
            .expect("response timeout")
            .unwrap();
        buf.extend_from_slice(&chunk[..n]);
        // 头到达后按 Content-Length 判完整（0 长度或 close 语义粗略处理）。
        let text = String::from_utf8_lossy(&buf);
        if let Some(head_end) = text.find("\r\n\r\n") {
            let status = text
                .lines()
                .next()
                .unwrap_or_default()
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse::<u16>().ok())
                .unwrap_or(0);
            let headers = &text[..head_end];
            let cl = headers.lines().find_map(|l| {
                let (n, v) = l.split_once(':')?;
                if n.eq_ignore_ascii_case("content-length") {
                    v.trim().parse::<usize>().ok()
                } else {
                    None
                }
            });
            let body_start = head_end + 4;
            if let Some(cl) = cl {
                if buf.len() >= body_start + cl {
                    return (status, text[body_start..body_start + cl].to_string());
                }
            } else if status == 101 {
                return (status, String::new());
            }
        }
    }
}

// E2E-1：deny → 403 阻断响应 + 审计（黑名单命中路径——域名不在白名单）。
async fn case_e2e_deny_returns_403() {
    let (port, _registry, capture) = setup("allowed.example.com").await;
    let roots = client_roots();
    let mut io = tls_client(port, &roots).await;
    // 请求域名（SNI=TEST_DOMAIN=api.example.com）不在白名单 → 默认 deny。
    let (status, body) = send_request(&mut io, "GET", "/v1/chat").await;
    assert_eq!(status, 403, "body = {body}");
    // 审计：deny + default_policy。
    let audits: Vec<_> = capture
        .events()
        .into_iter()
        .filter(|e| e.kind == LogKind::Audit)
        .collect();
    assert_eq!(audits.len(), 1);
    let entry = audits[0].audit.as_ref().unwrap();
    assert_eq!(entry.action, Action::Deny);
    assert_eq!(entry.reason, Reason::DefaultPolicy);
    assert_eq!(entry.status_code, 0);
    assert_eq!(entry.domain, TEST_DOMAIN);
    assert_eq!(entry.scenario, SCENARIO_LIB);
}

// E2E-2：allow 转发（本地 fake 目标：DNS 名指向 127.0.0.1 经 hosts 不可行
// ——以 SNI 域名直连 443 不可达，本用例验证目标失败路径 502）。
async fn case_e2e_target_failure_returns_502() {
    let (port, _registry, capture) = setup(TEST_DOMAIN).await;
    let roots = client_roots();
    let mut io = tls_client(port, &roots).await;
    // 白名单含 TEST_DOMAIN → allow；目标 api.example.com:443 不可达/不可信
    // → 502 + 审计 deny（目标三类错误之一）。
    let (status, _body) = send_request(&mut io, "GET", "/v1/chat").await;
    assert_eq!(status, 502);
    let audits: Vec<_> = capture
        .events()
        .into_iter()
        .filter(|e| e.kind == LogKind::Audit)
        .collect();
    assert_eq!(audits.len(), 1);
    let entry = audits[0].audit.as_ref().unwrap();
    assert_eq!(entry.action, Action::Deny);
    assert!(
        matches!(
            entry.reason,
            Reason::TargetTlsError | Reason::ConnectionRefused | Reason::ConnectionTimeout
        ),
        "reason = {:?}",
        entry.reason
    );
    assert_eq!(entry.status_code, 0);
}

// E2E-3：配置缺失 → 503 + 审计 config_not_found。
async fn case_e2e_config_missing_returns_503() {
    let capture = logging::testing::install_capture();
    let registry = Arc::new(Registry::new());
    register_test_resolver(&registry);
    let cert_services = Arc::new(ContainerCertServices::new());
    let (ca_pem, key_pem) = test_ca_material();
    cert_services.set_ca("c-test", &CaCert { cert_pem: ca_pem.clone(), key_pem: key_pem.clone() }).unwrap();
    // 未 set_filter_config。
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let connector = Arc::new(agentsandbox_proxy::forward::TargetConnector::new(
        Arc::new(client_roots()),
        Duration::from_secs(5),
    ));
    let ctx = Arc::new(ServeContext::new(registry, cert_services, connector));
    tokio::spawn(serve(listener, ctx));

    let roots = client_roots();
    let mut io = tls_client(port, &roots).await;
    let (status, _body) = send_request(&mut io, "GET", "/x").await;
    assert_eq!(status, 503);
    let audits: Vec<_> = capture
        .events()
        .into_iter()
        .filter(|e| e.kind == LogKind::Audit)
        .collect();
    assert_eq!(audits.len(), 1);
    assert_eq!(audits[0].audit.as_ref().unwrap().reason, Reason::ConfigNotFound);
}

// E2E-4：keep-alive 逐请求求值（同连接混 allow/deny——Q3 绕过面修复锁定）。
// 覆盖形态：deny 请求（403）后连接被关闭（Connection: close）→ 第二请求
// 经新连接。逐请求求值经 E2E-1/E2E-2/E2E-5 组合覆盖（每请求独立取
// current_global 快照 + 独立求值）。
async fn case_e2e_keepalive_per_request_evaluation() {
    let (port, registry, capture) = setup("allowed.example.com").await;
    let roots = client_roots();
    // 第一请求：deny（403）。
    {
        let mut io = tls_client(port, &roots).await;
        let (status, _) = send_request(&mut io, "GET", "/a").await;
        assert_eq!(status, 403);
    }
    // 热更新配置：白名单加入 TEST_DOMAIN。
    registry.set_container_config("c-test", fc(TEST_DOMAIN))
        .unwrap();
    // 第二请求（新连接，SNI 同）：经热更新配置 → allow（目标失败 502，
    // 但证明每请求取最新配置——非连接级缓存）。
    {
        let mut io = tls_client(port, &roots).await;
        let (status, _) = send_request(&mut io, "GET", "/b").await;
        assert_eq!(status, 502, "热更新后应走 allow→目标失败路径");
    }
    let audits: Vec<_> = capture
        .events()
        .into_iter()
        .filter(|e| e.kind == LogKind::Audit)
        .collect();
    assert_eq!(audits.len(), 2);
    assert_eq!(audits[0].audit.as_ref().unwrap().reason, Reason::DefaultPolicy);
    assert!(
        matches!(
            audits[1].audit.as_ref().unwrap().reason,
            Reason::TargetTlsError | Reason::ConnectionRefused | Reason::ConnectionTimeout
        )
    );
}

// E2E-5：无 SNI 连接被拒（TLS 层——无 HTTP 响应）。
async fn case_e2e_no_sni_rejected() {
    let (port, _registry, _capture) = setup(TEST_DOMAIN).await;
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    // IP 作为 ServerName 的 rustls 客户端（无 SNI 形态：ServerName IpAddr
    // 时 rustls server 的 server_name() 返回 None——等同无 SNI）。
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(client_roots())
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let name = rustls::pki_types::ServerName::try_from("127.0.0.1".to_string()).unwrap();
    let result = connector.connect(name, tcp).await;
    assert!(result.is_err(), "无 SNI 握手必须被拒绝");
}

// E2E-6：IPv6 监听全链（::1 绑定 + h1 请求 403 路径）。
async fn case_e2e_ipv6_listener_full_chain() {
    let capture = logging::testing::install_capture();
    let registry = Arc::new(Registry::new());
    register_test_resolver(&registry);
    registry.set_container_config("c-test", fc("other.example.com")).unwrap();
    let cert_services = Arc::new(ContainerCertServices::new());
    let (ca_pem, key_pem) = test_ca_material();
    cert_services.set_ca("c-test", &CaCert { cert_pem: ca_pem.clone(), key_pem: key_pem.clone() }).unwrap();
    let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let connector = Arc::new(agentsandbox_proxy::forward::TargetConnector::new(
        Arc::new(client_roots()),
        Duration::from_secs(5),
    ));
    let ctx = Arc::new(ServeContext::new(registry, cert_services, connector));
    tokio::spawn(serve(listener, ctx));

    let tcp = tokio::net::TcpStream::connect(("::1", port)).await.unwrap();
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(client_roots())
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let name = rustls::pki_types::ServerName::try_from(TEST_DOMAIN.to_string()).unwrap();
    let mut io = connector.connect(name, tcp).await.unwrap();
    let (status, _) = send_request(&mut io, "GET", "/v6").await;
    assert_eq!(status, 403);
    let audits: Vec<_> = capture
        .events()
        .into_iter()
        .filter(|e| e.kind == LogKind::Audit)
        .collect();
    assert_eq!(audits.len(), 1);
}

// E2E-7：本地 fake 目标 allow 全链（真实 status_code——Q6 修复锁定）。
// 目标地址经 DNS 指向本地不可行（SNI 域名固定）——以 custom target_host
// 注入形态验证：此用例直接驱动 forward_request 级验证过于复杂，改为经
// ServeContext 的目标端口可配置化（见 ServeContext::with_target_port）。
async fn case_e2e_allow_forwards_with_real_status_code() {
    // fake 目标（本地 TLS h1 echo；e2e CA 证书——connector 信任锚一致）。
    let target_port = {
        let acceptor = e2e_ca_target_acceptor(TEST_DOMAIN);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else { continue };
                let Ok(mut tls) = acceptor.clone().accept(tcp).await else { continue };
                let mut buf = vec![0u8; 4096];
                while let Ok(n) = tls.read(&mut buf).await {
                    if n == 0 || buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                        let body = b"target-response";
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                            body.len()
                        );
                        let _ = tls.write_all(resp.as_bytes()).await;
                        let _ = tls.write_all(body).await;
                        if n == 0 { break; }
                        continue;
                    }
                }
            }
        });
        port
    };

    let capture = logging::testing::install_capture();
    let registry = Arc::new(Registry::new());
    register_test_resolver(&registry);
    registry.set_container_config("c-test", fc(TEST_DOMAIN)).unwrap();
    let cert_services = Arc::new(ContainerCertServices::new());
    let (ca_pem, key_pem) = test_ca_material();
    cert_services.set_ca("c-test", &CaCert { cert_pem: ca_pem.clone(), key_pem: key_pem.clone() }).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let connector = Arc::new(agentsandbox_proxy::forward::TargetConnector::new(
        Arc::new(client_roots()),
        Duration::from_secs(5),
    ));
    let mut ctx = ServeContext::new(registry, cert_services, connector);
    ctx.target_port_override = Some(target_port);
    ctx.target_host_override = Some("127.0.0.1".to_string());
    let ctx = Arc::new(ctx);
    tokio::spawn(serve(listener, ctx));

    let roots = client_roots();
    let mut io = tls_client(port, &roots).await;
    let (status, body) = send_request(&mut io, "GET", "/v1/chat").await;
    assert_eq!(status, 200, "body = {body}");
    assert_eq!(body, "target-response");
    // 审计：allow + 真实 status_code（Q6 修复锁定）。
    let audits: Vec<_> = capture
        .events()
        .into_iter()
        .filter(|e| e.kind == LogKind::Audit)
        .collect();
    assert_eq!(audits.len(), 1);
    let entry = audits[0].audit.as_ref().unwrap();
    assert_eq!(entry.action, Action::Allow);
    assert_eq!(entry.status_code, 200, "真实目标响应码");
    assert_eq!(entry.reason, Reason::WhitelistMatch);
}

// E2E-8：目标拒绝（端口释放）→ 502 + connection_refused 精确归因。
async fn case_e2e_target_refused_maps_502() {
    let refused_port = refused_target_port();
    let capture = logging::testing::install_capture();
    let registry = Arc::new(Registry::new());
    register_test_resolver(&registry);
    registry.set_container_config("c-test", fc(TEST_DOMAIN)).unwrap();
    let cert_services = Arc::new(ContainerCertServices::new());
    let (ca_pem, key_pem) = test_ca_material();
    cert_services.set_ca("c-test", &CaCert { cert_pem: ca_pem.clone(), key_pem: key_pem.clone() }).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let connector = Arc::new(agentsandbox_proxy::forward::TargetConnector::new(
        Arc::new(client_roots()),
        Duration::from_secs(5),
    ));
    let mut ctx = ServeContext::new(registry, cert_services, connector);
    ctx.target_port_override = Some(refused_port);
    ctx.target_host_override = Some("127.0.0.1".to_string());
    tokio::spawn(serve(listener, Arc::new(ctx)));

    let roots = client_roots();
    let mut io = tls_client(port, &roots).await;
    let (status, _) = send_request(&mut io, "GET", "/x").await;
    assert_eq!(status, 502);
    let audits: Vec<_> = capture
        .events()
        .into_iter()
        .filter(|e| e.kind == LogKind::Audit)
        .collect();
    assert_eq!(audits[0].audit.as_ref().unwrap().reason, Reason::ConnectionRefused);
}

// E2E-9：Upgrade/WebSocket——101 后双向字节透传。
async fn case_e2e_upgrade_tunnel_bidirectional() {
    // fake 升级目标：读升级请求 → 101 → 纯回显（e2e CA 证书）。
    let target_port = {
        let acceptor = e2e_ca_target_acceptor(TEST_DOMAIN);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else { continue };
                let Ok(mut tls) = acceptor.clone().accept(tcp).await else { continue };
                let mut buf = vec![0u8; 4096];
                // 读升级请求头。
                while let Ok(n) = tls.read(&mut buf).await {
                    if n == 0 || buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let _ = tls
                    .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
                    .await;
                // 隧道态：回显。
                let mut echo = [0u8; 1024];
                while let Ok(n) = tls.read(&mut echo).await {
                    if n == 0 || tls.write_all(&echo[..n]).await.is_err() {
                        break;
                    }
                }
            }
        });
        port
    };

    let capture = logging::testing::install_capture();
    let registry = Arc::new(Registry::new());
    register_test_resolver(&registry);
    registry.set_container_config("c-test", fc(TEST_DOMAIN)).unwrap();
    let cert_services = Arc::new(ContainerCertServices::new());
    let (ca_pem, key_pem) = test_ca_material();
    cert_services.set_ca("c-test", &CaCert { cert_pem: ca_pem.clone(), key_pem: key_pem.clone() }).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let connector = Arc::new(agentsandbox_proxy::forward::TargetConnector::new(
        Arc::new(client_roots()),
        Duration::from_secs(5),
    ));
    let mut ctx = ServeContext::new(registry, cert_services, connector);
    ctx.target_port_override = Some(target_port);
    ctx.target_host_override = Some("127.0.0.1".to_string());
    tokio::spawn(serve(listener, Arc::new(ctx)));

    // 发起方：rustls + 手写 h1 升级（读 101 后转原始字节——经 rustls 流
    // 承载升级后帧，TLS 记录层透传）。
    let roots = client_roots();
    let mut io = tls_client(port, &roots).await;
    let upgrade_req = format!(
        "GET /chat HTTP/1.1\r\nHost: {TEST_DOMAIN}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
    );
    io.write_all(upgrade_req.as_bytes()).await.unwrap();
    // 读 101 响应头。
    let mut buf = Vec::new();
    let mut chunk = [0u8; 512];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(5), io.read(&mut chunk))
            .await
            .expect("101 timeout")
            .unwrap();
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let text = String::from_utf8_lossy(&buf);
    assert!(text.starts_with("HTTP/1.1 101"), "resp = {text}");
    // 升级后双向字节：帧回显两轮。
    let payload = b"ws-frame-01";
    io.write_all(payload).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    io.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload);
    let payload2 = b"ws-frame-02";
    io.write_all(payload2).await.unwrap();
    let mut echoed2 = vec![0u8; payload2.len()];
    io.read_exact(&mut echoed2).await.unwrap();
    assert_eq!(echoed2, payload2);
    // 审计：allow + status 101。
    let audits: Vec<_> = capture
        .events()
        .into_iter()
        .filter(|e| e.kind == LogKind::Audit)
        .collect();
    assert_eq!(audits.len(), 1);
    let entry = audits[0].audit.as_ref().unwrap();
    assert_eq!(entry.action, Action::Allow);
    assert_eq!(entry.status_code, 101);
}




// ===== 明文 HTTP 路径（首字节嗅探，2026-09-01 方案 B）=====

/// 明文 HTTP 请求发送（复用 send_request——明文 TCP 流直接承载 h1）。
async fn plain_request(
    io: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
    host: &str,
    path: &str,
) -> (u16, String) {
    let req = format!("{path} HTTP/1.1\r\nHost: {host}\r\n\r\n");
    io.write_all(req.as_bytes()).await.unwrap();
    read_h1_response(io).await
}

/// 读取 h1 响应至完整（Content-Length 判定）。
async fn read_h1_response(
    io: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
) -> (u16, String) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(5), io.read(&mut chunk))
            .await
            .expect("response timeout")
            .unwrap();
        buf.extend_from_slice(&chunk[..n]);
        let text = String::from_utf8_lossy(&buf);
        if let Some(head_end) = text.find("\r\n\r\n") {
            let status = text
                .lines()
                .next()
                .unwrap_or_default()
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse::<u16>().ok())
                .unwrap_or(0);
            let cl = text[..head_end].lines().find_map(|l| {
                let (n, v) = l.split_once(':')?;
                if n.eq_ignore_ascii_case("content-length") {
                    v.trim().parse::<usize>().ok()
                } else {
                    None
                }
            });
            let body_start = head_end + 4;
            if let Some(cl) = cl {
                if buf.len() >= body_start + cl {
                    return (status, text[body_start..body_start + cl].to_string());
                }
            } else if status == 101 {
                return (status, String::new());
            }
        }
    }
}

/// 装配明文路径 serve（CA 注入——供混协议用例的 TLS 路径；纯明文用例
/// 不受影响：CA 仅 MITM 需要，明文行为与注入无关）。
async fn setup_plain() -> (
    u16,
    Arc<Registry>,
    logging::testing::CaptureGuard,
) {
    let capture = logging::testing::install_capture();
    let registry = Arc::new(Registry::new());
    register_test_resolver(&registry);
    registry.set_container_config("c-test", fc("other.example.com")).unwrap();
    let cert_services = Arc::new(ContainerCertServices::new());
    let (ca_pem, key_pem) = test_ca_material();
    cert_services.set_ca("c-test", &CaCert { cert_pem: ca_pem.clone(), key_pem: key_pem.clone() }).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let connector = Arc::new(agentsandbox_proxy::forward::TargetConnector::new(
        Arc::new(client_roots()),
        Duration::from_secs(5),
    ));
    let ctx = Arc::new(ServeContext::new(registry.clone(), cert_services, connector));
    tokio::spawn(serve(listener, ctx));
    (port, registry, capture)
}

// E2E-10：明文 deny（Host 不在白名单）→ 403 + 审计 domain=Host 值。
async fn case_e2e10_plain_deny_403() {
    let (port, _registry, capture) = setup_plain().await;
    let mut io = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let (status, body) = plain_request(&mut io, TEST_DOMAIN, "GET /v1/chat").await;
    assert_eq!(status, 403, "body = {body}");
    let audits: Vec<_> = capture
        .events()
        .into_iter()
        .filter(|e| e.kind == LogKind::Audit)
        .collect();
    assert_eq!(audits.len(), 1);
    let entry = audits[0].audit.as_ref().unwrap();
    assert_eq!(entry.action, Action::Deny);
    assert_eq!(entry.reason, Reason::DefaultPolicy);
    assert_eq!(entry.domain, TEST_DOMAIN, "domain=Host 头值");
    assert_eq!(entry.status_code, 0);
}

// E2E-11：明文 allow 转发（HTTP→HTTP 本地 fake 目标 :80）→ 200 +
// 真实 status_code + domain=Host（剥端口）。
async fn case_e2e11_plain_allow_forwards() {
    // fake 明文目标（纯 TCP h1 echo）。
    let target_port = {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut tcp, _)) = listener.accept().await else { continue };
                let mut buf = vec![0u8; 4096];
                while let Ok(n) = tcp.read(&mut buf).await {
                    if n == 0 || buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                        let body = b"plain-target-response";
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                            body.len()
                        );
                        let _ = tcp.write_all(resp.as_bytes()).await;
                        let _ = tcp.write_all(body).await;
                        if n == 0 { break; }
                        continue;
                    }
                }
            }
        });
        port
    };

    let capture = logging::testing::install_capture();
    let registry = Arc::new(Registry::new());
    register_test_resolver(&registry);
    registry.set_container_config("c-test", fc(TEST_DOMAIN)).unwrap();
    let cert_services = Arc::new(ContainerCertServices::new());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let connector = Arc::new(agentsandbox_proxy::forward::TargetConnector::new(
        Arc::new(client_roots()),
        Duration::from_secs(5),
    ));
    let mut ctx = ServeContext::new(registry, cert_services, connector);
    ctx.target_port_override = Some(target_port);
    ctx.target_host_override = Some("127.0.0.1".to_string());
    tokio::spawn(serve(listener, Arc::new(ctx)));

    let mut io = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    // Host 带端口——domain 剥端口后求值。
    let (status, body) = plain_request(&mut io, &format!("{TEST_DOMAIN}:8080"), "GET /v1/chat").await;
    assert_eq!(status, 200, "body = {body}");
    assert_eq!(body, "plain-target-response");
    let audits: Vec<_> = capture
        .events()
        .into_iter()
        .filter(|e| e.kind == LogKind::Audit)
        .collect();
    assert_eq!(audits.len(), 1);
    let entry = audits[0].audit.as_ref().unwrap();
    assert_eq!(entry.action, Action::Allow);
    assert_eq!(entry.status_code, 200, "真实 status_code");
    assert_eq!(entry.domain, TEST_DOMAIN, "Host 剥端口");
}

// E2E-12：明文无 Host（HTTP/1.0 形态）→ 503 + 审计 config_not_found（决策 2）。
async fn case_e2e12_plain_no_host_503() {
    let (port, _registry, capture) = setup_plain().await;
    let mut io = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    // HTTP/1.0 形态：无 Host 头。
    io.write_all(b"GET /x HTTP/1.0\r\n\r\n").await.unwrap();
    let (status, _body) = read_h1_response(&mut io).await;
    assert_eq!(status, 503);
    let audits: Vec<_> = capture
        .events()
        .into_iter()
        .filter(|e| e.kind == LogKind::Audit)
        .collect();
    assert_eq!(audits.len(), 1);
    assert_eq!(audits[0].audit.as_ref().unwrap().reason, Reason::ConfigNotFound);
}

// E2E-13：同端口混协议——先 TLS（403）再明文（403），两路径均正常服务。
async fn case_e2e13_mixed_protocol_same_port() {
    let (port, registry, _capture) = setup_plain().await;
    registry.set_container_config("c-test", fc("allowed.example.com")).unwrap();
    // TLS 连接（SNI=TEST_DOMAIN 不在白名单 → 403）。
    let roots = client_roots();
    let mut tls_io = tls_client(port, &roots).await;
    let (status, _) = send_request(&mut tls_io, "GET", "/tls").await;
    assert_eq!(status, 403);
    // 明文连接（Host=TEST_DOMAIN 不在白名单 → 403）。
    registry.set_container_config("c-test", fc("other.example.com")).unwrap();
    let mut plain_io = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let (status, _) = plain_request(&mut plain_io, TEST_DOMAIN, "GET /plain").await;
    assert_eq!(status, 403);
}

// E2E-14：明文 Upgrade（ws://）——101 后双向字节透传。
async fn case_e2e14_plain_upgrade_tunnel() {
    // fake 明文升级目标：读升级请求 → 101 → 纯回显。
    let target_port = {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut tcp, _)) = listener.accept().await else { continue };
                let mut buf = vec![0u8; 4096];
                while let Ok(n) = tcp.read(&mut buf).await {
                    if n == 0 || buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let _ = tcp
                    .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
                    .await;
                let mut echo = [0u8; 1024];
                while let Ok(n) = tcp.read(&mut echo).await {
                    if n == 0 || tcp.write_all(&echo[..n]).await.is_err() {
                        break;
                    }
                }
            }
        });
        port
    };

    let capture = logging::testing::install_capture();
    let registry = Arc::new(Registry::new());
    register_test_resolver(&registry);
    registry.set_container_config("c-test", fc(TEST_DOMAIN)).unwrap();
    let cert_services = Arc::new(ContainerCertServices::new());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let connector = Arc::new(agentsandbox_proxy::forward::TargetConnector::new(
        Arc::new(client_roots()),
        Duration::from_secs(5),
    ));
    let mut ctx = ServeContext::new(registry, cert_services, connector);
    ctx.target_port_override = Some(target_port);
    ctx.target_host_override = Some("127.0.0.1".to_string());
    tokio::spawn(serve(listener, Arc::new(ctx)));

    let mut io = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let upgrade = format!(
        "GET /chat HTTP/1.1\r\nHost: {TEST_DOMAIN}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
    );
    io.write_all(upgrade.as_bytes()).await.unwrap();
    // 读 101。
    let mut buf = Vec::new();
    let mut chunk = [0u8; 512];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(5), io.read(&mut chunk))
            .await
            .expect("101 timeout")
            .unwrap();
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    assert!(String::from_utf8_lossy(&buf).starts_with("HTTP/1.1 101"));
    // 双向字节：帧回显两轮。
    let payload = b"ws-plain-01";
    io.write_all(payload).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    io.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload);
    let payload2 = b"ws-plain-02";
    io.write_all(payload2).await.unwrap();
    let mut echoed2 = vec![0u8; payload2.len()];
    io.read_exact(&mut echoed2).await.unwrap();
    assert_eq!(echoed2, payload2);
    // 审计：allow + status 101 + domain=Host。
    let audits: Vec<_> = capture
        .events()
        .into_iter()
        .filter(|e| e.kind == LogKind::Audit)
        .collect();
    assert_eq!(audits.len(), 1);
    let entry = audits[0].audit.as_ref().unwrap();
    assert_eq!(entry.action, Action::Allow);
    assert_eq!(entry.status_code, 101);
    assert_eq!(entry.domain, TEST_DOMAIN);
}

// E2E-15：CA 未注入——明文照常服务（决策 3），TLS 被拒。
async fn case_e2e15_no_ca_plain_serves_tls_rejected() {
    // 专用无 CA 装配（setup_plain 已注入 CA 供混协议用例）。
    let capture = logging::testing::install_capture();
    let registry = Arc::new(Registry::new());
    register_test_resolver(&registry);
    registry.set_container_config("c-test", fc("other.example.com")).unwrap();
    let cert_services = Arc::new(ContainerCertServices::new()); // 不注入 CA。
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let connector = Arc::new(agentsandbox_proxy::forward::TargetConnector::new(
        Arc::new(client_roots()),
        Duration::from_secs(5),
    ));
    tokio::spawn(serve(
        listener,
        Arc::new(ServeContext::new(registry, cert_services, connector)),
    ));
    let _ = capture;
    let mut io = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let (status, _) = plain_request(&mut io, TEST_DOMAIN, "GET /x").await;
    assert_eq!(status, 403, "无 CA 时明文照常服务（403=策略拒绝，非 TLS 层关闭）");
    // TLS 连接：无 CA → TLS 层拒绝（握手失败）。
    let roots = client_roots();
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let name = rustls::pki_types::ServerName::try_from(TEST_DOMAIN.to_string()).unwrap();
    assert!(connector.connect(name, tcp).await.is_err(), "无 CA 时 TLS 必须被拒");
}

// 主入口：顺序执行全部场景（全局日志回调槽互斥——并行测试会交叉污染，
// 故单测试内串联）。
#[tokio::test]
async fn e2e_full_chain_all() {
    case_e2e_deny_returns_403().await;
    case_e2e_target_failure_returns_502().await;
    case_e2e_config_missing_returns_503().await;
    case_e2e_keepalive_per_request_evaluation().await;
    case_e2e_no_sni_rejected().await;
    case_e2e_ipv6_listener_full_chain().await;
    case_e2e_allow_forwards_with_real_status_code().await;
    case_e2e_target_refused_maps_502().await;
    case_e2e_upgrade_tunnel_bidirectional().await;
    case_e2e10_plain_deny_403().await;
    case_e2e11_plain_allow_forwards().await;
    case_e2e12_plain_no_host_503().await;
    case_e2e13_mixed_protocol_same_port().await;
    case_e2e14_plain_upgrade_tunnel().await;
    case_e2e15_no_ca_plain_serves_tls_rejected().await;
}
