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
//! - `cms/ca.crt`, `cms/ca.key`: CA 证书和私钥（根目录，用于兼容）
//! - `cms/cms.crl`: CMS CRL（包含已吊销证书，根目录，用于兼容）
//! - `cms/node-{a,b,c}/`: 签名节点证书目录（自包含）
//!   - `signer.crt`: 签名证书
//!   - `signer.key`: 签名私钥
//!   - `ca.crt`: CA根证书（复制）
//!   - `cms.crl`: CMS CRL（复制）
//! - `cms/expired/`: 已过期证书目录（自包含）
//!   - `signer.{crt,key}`: 已过期证书（2000-2010年）
//!   - `ca.crt`: CA根证书（复制）
//!   - `cms.crl`: CMS CRL（复制）
//! - `cms/revoked/`: 已吊销证书目录（自包含）
//!   - `signer.{crt,key}`: 已吊销证书
//!   - `ca.crt`: CA根证书（复制）
//!   - `cms.crl`: CMS CRL（复制）
//! - `cms/self-signed/signer.{crt,key}`: 自签名证书
//!
//! ### TLS 证书（用于 mTLS 测试）
//! - `tls/ca/ca.crt`, `tls/ca/ca.key`: 统一CA根证书和私钥
//! - `tls/server/node-{a,b,c}/`: trustruntime服务端证书
//!   - `certificate.crt`: 服务端证书
//!   - `private.key`: 服务端私钥（加密）
//!   - `key_pwd.txt`: 私钥密码
//!   - `ca_root.crt`: 根证书
//!   - `cert.crl`: 空CRL文件
//! - `tls/ubse/node-{a,b,c}/`: ubse客户端证书（双用途：serverAuth + clientAuth）
//!   - `server.pem`: ubse证书
//!   - `server_key.pem`: ubse私钥（加密）
//!   - `key_pwd.txt`: 私钥密码
//!   - `trust.pem`: 根证书
//! - `tls/lcne/node-{a,b,c}/`: lcne客户端证书
//!   - `certificate.crt`: lcne证书
//!   - `private.key`: lcne私钥（加密）
//!   - `key_pwd.txt`: 私钥密码
//!   - `ca_root.crt`: 根证书
//!   - `communication.crl`: 空CRL文件
//! - `tls/test-clients/`: 测试用特殊客户端证书
//!   - `revoked.crt`, `revoked.key`: 被吊销的客户端证书
//!   - `wrong-ca.crt`, `wrong-ca.key`: 错误CA签发的客户端证书
//!   - `client-crl.crt`: 客户端CRL（包含被吊销证书）
//!   - `other-ca.crt`: 其他CA证书（用于测试错误CA场景）
//!
//! ## 技术规格
//!
//! - 密钥算法：ECC-256（P-256 曲线，Nid::X9_62_PRIME256V1）
//! - 签名算法：SHA256withECDSA
//! - 有效期：3650 天（约 10 年）
//! - Subject Key Identifier（SKI）：公钥 DER 编码的 SHA-1 哈希（20 字节）
//! - 过期证书有效期：2000-01-01 至 2010-01-01
//! - TLS 私钥加密：AES-256-CBC，密码存储于各节点目录的 `key_pwd.txt`
//! - 统一密码：MyPasswd123（所有节点使用相同密码）

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
