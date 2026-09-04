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

//! 集成测试共享基建：测试 PKI（目标信任锚 + fake 目标服务端证书）与三类失败目标。

#![allow(dead_code)]

use std::sync::Arc;

use agentsandbox_proxy::cert::{parse_ca, CertIssuer, ParsedCa};
use rustls::RootCertStore;

/// fake 目标域名（连接器 SNI 与服务端证书 SAN 一致）。
pub const TEST_DOMAIN: &str = "api.example.com";

/// 测试 PKI：自签 CA（经 crate parse_ca 校验）→ 目标信任锚 + fake 目标证书签发。
pub struct TestPki {
    ca: ParsedCa,
    /// 目标侧信任锚（注入 TargetConnector 的 RootCertStore）。
    pub roots: Arc<RootCertStore>,
}

impl TestPki {
    pub fn new() -> Self {
        // 具备 CA 扩展（BasicConstraints/KeyCertSign）的自签根，供签发与验证。
        let mut params = rcgen::CertificateParams::new(Vec::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let key = rcgen::KeyPair::generate().unwrap();
        let ca_cert = params.self_signed(&key).unwrap();
        // 复用生产解析路径（PEM → ParsedCa），保证 fake 目标证书与真实签发链同构。
        let parsed =
            parse_ca(ca_cert.pem().as_bytes(), key.serialize_pem().as_bytes()).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(ca_cert.der().clone()).unwrap();
        Self {
            ca: parsed,
            roots: Arc::new(roots),
        }
    }

    /// fake 目标 TLS 接受器（SAN=domain 叶子证书，测试 CA 签发，链含原始 CA DER）。
    pub fn tls_acceptor(&self, domain: &str) -> tokio_rustls::TlsAcceptor {
        let issued = CertIssuer::new(self.ca.clone()).issue(domain).unwrap();
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(issued.chain, issued.key)
            .unwrap();
        tokio_rustls::TlsAcceptor::from(Arc::new(config))
    }
}

/// 拒绝目标端口：取得空闲端口后立即关闭监听（连接该端口 → ECONNREFUSED）。
pub fn refused_target_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    port
}

/// 握手失败目标：接受 TCP 后发送非 TLS 字节并关闭（客户端握手失败 → target_tls_error）。
pub fn handshake_fail_target() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let _ = std::io::Write::write_all(&mut s, b"not-a-tls-record");
            drop(s);
        }
    });
    port
}

/// 超时目标：接受 TCP 后静默不响应（客户端握手等待至 deadline → connection_timeout）。
pub fn silent_target() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        // 持有已接受连接不读写、不关闭（保持 ESTABLISHED 静默直到测试结束）。
        let mut held = Vec::new();
        held.extend(listener.incoming().flatten());
    });
    port
}
