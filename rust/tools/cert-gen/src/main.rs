//! cert-gen: 测试证书生成工具
//!
//! 用于生成 CMS 集成测试和 TLS 测试所需的测试证书、私钥和 CRL 文件。
//!
//! ## 用法
//!
//! ```bash
//! cert-gen --output-dir <OUTPUT_DIR> [--force]
//! ```
//!
//! ## 生成的证书类型
//!
//! ### CMS 证书（用于签名测试）
//! - `cms/ca.crt`, `cms/ca.key`: CA 证书和私钥
//! - `cms/node-{a,b,c}/signer.{crt,key}`: 签名节点证书和私钥
//! - `cms/expired/signer.{crt,key}`: 已过期证书（2000-2010年）
//! - `cms/revoked/signer.{crt,key}`: 已吊销证书
//! - `cms/self-signed/signer.{crt,key}`: 自签名证书
//! - `cms/cms.crl`: CMS CRL（包含已吊销证书）
//!
//! ### TLS 证书（用于 mTLS 测试）
//! - `tls/ca.crt`: TLS CA 证书
//! - `tls/other-ca.crt`: 另一个 CA 证书（用于测试错误的 CA）
//! - `tls/server/node-{a,b,c}/node.{crt,key}`: 服务器证书（私钥已加密）
//! - `tls/client/client.{crt,key}`: 客户端证书（私钥已加密）
//! - `tls/client/revoked.{crt,key}`: 已吊销客户端证书（私钥已加密）
//! - `tls/client/wrong-ca.{crt,key}`: 由错误 CA 签发的客户端证书（私钥已加密）
//! - `tls/client-crl.crt`: TLS 客户端 CRL
//! - `tls/key_pwd.txt`: TLS 私钥加密密码
//!
//! ## 技术规格
//!
//! - 密钥算法：ECC-256（P-256 曲线，Nid::X9_62_PRIME256V1）
//! - 签名算法：SHA256withECDSA
//! - 有效期：3650 天（约 10 年）
//! - Subject Key Identifier（SKI）：公钥 DER 编码的 SHA-1 哈希（20 字节）
//! - 过期证书有效期：2000-01-01 至 2010-01-01
//! - TLS 私钥加密：AES-256-CBC，密码存储于 `tls/key_pwd.txt`

mod certificate;
mod generator;
mod utils;

use clap::Parser;
use openssl::ec::EcGroup;
use openssl::nid::Nid;
use std::fs;
use std::path::Path;

#[derive(Parser)]
#[command(name = "cert-gen")]
#[command(about = "Generate test certificates for CMS integration tests")]
struct Args {
    #[arg(short, long)]
    output_dir: String,

    #[arg(short, long)]
    force: bool,
}

fn main() {
    let args = Args::parse();

    let output_path = Path::new(&args.output_dir);

    if output_path.exists() && !args.force {
        println!("Output directory already exists. Use --force to overwrite.");
        return;
    }

    if args.force && output_path.exists() {
        fs::remove_dir_all(output_path).expect("Failed to remove existing directory");
    }

    fs::create_dir_all(output_path).expect("Failed to create output directory");

    println!("Generating test certificates to: {}", args.output_dir);

    generate_all_certs(output_path);

    println!("Certificate generation complete.");
}

fn generate_all_certs(output_path: &Path) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("Failed to create EC group");

    generator::generate_cms_certificates(output_path, &group);
    generator::generate_tls_certificates(output_path, &group);
}
