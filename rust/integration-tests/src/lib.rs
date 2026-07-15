//! CMS签名服务集成测试框架
//!
//! 提供端到端集成测试能力，验证trustruntime服务的完整业务流程。
//!
//! ## 模块结构
//! - `vsock_client`: vsock客户端，用于发送签名/验签请求
//! - `test_cert_gen`: 测试证书生成（CA、签名者、过期、吊销等）
//! - `test_helpers`: 测试辅助工具（路径管理、插件测试上下文、断言辅助）
//! - `test_crl_gen`: CRL吊销列表生成
//! - `proc_manager`: 进程管理器，负责启动/停止trustruntime进程
//!
//! ## 测试场景覆盖
//! - **正常场景 (N01-N03)**: 签名、验签、跨节点验签
//! - **错误场景 (E01-E20)**: 证书过期、吊销、自签名、数据篡改等
//! - **边界场景 (B01-B07)**: 空数据、超大数据、并发请求等
//!
//! ## 测试证书目录结构
//! ```text
//! test-certs/
//! ├── cms/
//! │   ├── ca.crt           # CMS CA证书
//! │   ├── cms.crl          # CRL吊销列表
//! │   ├── node1/signer.crt # 节点1签名证书
//! │   ├── node2/signer.crt # 节点2签名证书
//! │   ├── self-signed/     # 自签名证书
//! │   ├── revoked/         # 已吊销证书
//! │   └── expired/         # 已过期证书
//! └── tls/
//!     ├── ca.crt           # TLS CA证书
//!     ├── client/          # 客户端证书
//!     └── server/          # 服务端证书
//! ```

pub mod proc_manager;
pub mod test_cert_gen;
pub mod test_crl_gen;
pub mod test_helpers;
pub mod vsock_client;

/// CMS CA证书相对路径
pub const CMS_CA_CERT: &str = "cms/ca.crt";

/// CMS CRL吊销列表相对路径
pub const CMS_CRL: &str = "cms/cms.crl";

/// TLS CA证书相对路径
pub const TLS_CA_CERT: &str = "tls/ca.crt";

/// TLS客户端证书相对路径
pub const TLS_CLIENT_CERT: &str = "tls/client/client.crt";

/// TLS客户端私钥相对路径
pub const TLS_CLIENT_KEY: &str = "tls/client/client.key";

/// 构造节点CMS签名证书路径
///
/// # Arguments
/// * `node` - 节点名称（如 "node1", "node2"）
///
/// # Returns
/// 相对路径字符串，如 "cms/node1/signer.crt"
pub fn node_cms_cert_path(node: &str) -> String {
    format!("cms/{}/signer.crt", node)
}

/// 构造节点CMS私钥路径
///
/// # Arguments
/// * `node` - 节点名称
///
/// # Returns
/// 相对路径字符串，如 "cms/node1/signer.key"
pub fn node_cms_key_path(node: &str) -> String {
    format!("cms/{}/signer.key", node)
}

/// 构造节点TLS证书路径
///
/// # Arguments
/// * `node` - 节点名称
///
/// # Returns
/// 相对路径字符串，如 "tls/server/node1/node.crt"
pub fn node_tls_cert_path(node: &str) -> String {
    format!("tls/server/{}/node.crt", node)
}

/// 构造节点TLS私钥路径
///
/// # Arguments
/// * `node` - 节点名称
///
/// # Returns
/// 相对路径字符串，如 "tls/server/node1/node.key"
pub fn node_tls_key_path(node: &str) -> String {
    format!("tls/server/{}/node.key", node)
}
