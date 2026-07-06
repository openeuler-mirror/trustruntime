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
//! - `tls/server/node-{a,b,c}/node.{crt,key}`: 服务器证书
//! - `tls/client/client.{crt,key}`: 客户端证书
//! - `tls/client/revoked.{crt,key}`: 已吊销客户端证书
//! - `tls/client/wrong-ca.{crt,key}`: 由错误 CA 签发的客户端证书
//! - `tls/client-crl.crt`: TLS 客户端 CRL
//!
//! ## 技术规格
//!
//! - 密钥算法：ECC-256（P-256 曲线，Nid::X9_62_PRIME256V1）
//! - 签名算法：SHA256withECDSA
//! - 有效期：3650 天（约 10 年）
//! - Subject Key Identifier（SKI）：公钥 DER 编码的 SHA-1 哈希（20 字节）
//! - 过期证书有效期：2000-01-01 至 2010-01-01

use clap::Parser;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, CrlNumber, KeyUsage, SubjectKeyIdentifier,
};
use openssl::x509::{X509Builder, X509CrlBuilder, X509NameBuilder, X509RevokedBuilder, X509};
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

/// 程序入口函数
///
/// ## 执行流程
/// 1. 解析命令行参数
/// 2. 检查输出目录是否存在（使用 --force 标志强制覆盖）
/// 3. 创建输出目录结构
/// 4. 调用 `generate_all_certs` 生成所有证书
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

/// 生成所有测试证书
///
/// 统一生成 CMS 和 TLS 两套证书体系，使用相同的 ECC-256 曲线。
///
/// ## 参数
/// - `output_path`: 输出目录路径
fn generate_all_certs(output_path: &Path) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("Failed to create EC group");

    generate_cms_certificates(output_path, &group);
    generate_tls_certificates(output_path, &group);
}

/// 生成 CMS 签名测试证书
///
/// 生成用于 CMS（Cryptographic Message Syntax）签名测试的证书体系，
/// 包括 CA 证书、节点签名证书、过期证书、吊销证书和自签名证书。
///
/// ## 目录结构
/// ```text
/// cms/
/// ├── ca.crt, ca.key              # CA 证书和私钥
/// ├── cms.crl                     # CRL（吊销列表）
/// ├── node-{a,b,c}/               # 签名节点证书
/// │   ├── signer.crt
/// │   └── signer.key
/// ├── expired/                    # 过期证书
/// │   ├── signer.crt
/// │   └── signer.key
/// ├── revoked/                    # 已吊销证书
/// │   ├── signer.crt
/// │   └── signer.key
/// └── self-signed/                # 自签名证书
///     ├── signer.crt
///     └── signer.key
/// ```
///
/// ## 参数
/// - `output_path`: 输出根目录
/// - `group`: ECC 曲线组（P-256）
fn generate_cms_certificates(output_path: &Path, group: &EcGroup) {
    let cms_dir = output_path.join("cms");
    fs::create_dir_all(&cms_dir).expect("Failed to create cms directory");

    let (ca_cert, ca_pkey, _ca_id) = create_ca_cert(group, "CMS Test CA");
    fs::write(
        cms_dir.join("ca.crt"),
        ca_cert.to_pem().expect("Failed to PEM encode CA cert"),
    )
    .expect("Failed to write CA cert");
    fs::write(
        cms_dir.join("ca.key"),
        ca_pkey
            .private_key_to_pem_pkcs8()
            .expect("Failed to PEM encode CA key"),
    )
    .expect("Failed to write CA key");

    let nodes = ["node-a", "node-b", "node-c"];
    let mut revoked_certs: Vec<(X509, Vec<u8>)> = Vec::new();

    for node in &nodes {
        let node_dir = cms_dir.join(node);
        fs::create_dir_all(&node_dir).expect("Failed to create node directory");

        let (cert, key, _cert_id) =
            create_signer_cert(group, &ca_cert, &ca_pkey, format!("CMS {}", node));
        fs::write(
            node_dir.join("signer.crt"),
            cert.to_pem().expect("Failed to PEM encode cert"),
        )
        .expect("Failed to write cert");
        fs::write(
            node_dir.join("signer.key"),
            key.private_key_to_pem_pkcs8()
                .expect("Failed to PEM encode key"),
        )
        .expect("Failed to write key");

        println!("Generated CMS certificate for {}", node);
    }

    let expired_dir = cms_dir.join("expired");
    fs::create_dir_all(&expired_dir).expect("Failed to create expired directory");
    let (expired_cert, expired_key, _) =
        create_expired_cert(group, &ca_cert, &ca_pkey, "CMS Expired");
    fs::write(
        expired_dir.join("signer.crt"),
        expired_cert.to_pem().expect("Failed to PEM encode"),
    )
    .expect("Failed to write expired cert");
    fs::write(
        expired_dir.join("signer.key"),
        expired_key
            .private_key_to_pem_pkcs8()
            .expect("Failed to PEM encode"),
    )
    .expect("Failed to write expired key");
    println!("Generated expired CMS certificate");

    let revoked_dir = cms_dir.join("revoked");
    fs::create_dir_all(&revoked_dir).expect("Failed to create revoked directory");
    let (revoked_cert, revoked_key, revoked_id) =
        create_signer_cert(group, &ca_cert, &ca_pkey, "CMS Revoked".to_string());
    fs::write(
        revoked_dir.join("signer.crt"),
        revoked_cert.to_pem().expect("Failed to PEM encode"),
    )
    .expect("Failed to write revoked cert");
    fs::write(
        revoked_dir.join("signer.key"),
        revoked_key
            .private_key_to_pem_pkcs8()
            .expect("Failed to PEM encode"),
    )
    .expect("Failed to write revoked key");
    revoked_certs.push((revoked_cert, revoked_id));
    println!("Generated revoked CMS certificate");

    generate_crl(&cms_dir, &ca_cert, &ca_pkey, &revoked_certs);

    let self_signed_dir = cms_dir.join("self-signed");
    fs::create_dir_all(&self_signed_dir).expect("Failed to create self-signed directory");
    let (self_cert, self_key, _) = create_self_signed_cert(group, "CMS Self-Signed");
    fs::write(
        self_signed_dir.join("signer.crt"),
        self_cert.to_pem().expect("Failed to PEM encode"),
    )
    .expect("Failed to write self-signed cert");
    fs::write(
        self_signed_dir.join("signer.key"),
        self_key
            .private_key_to_pem_pkcs8()
            .expect("Failed to PEM encode"),
    )
    .expect("Failed to write self-signed key");
    println!("Generated self-signed CMS certificate");
}

/// 生成 CMS CRL（证书吊销列表）
///
/// 创建 X.509 CRL 文件，包含所有被吊销证书的序列号和吊销时间。
/// CRL 由 CA 私钥签名，有效期 30 天。
///
/// ## 参数
/// - `cms_dir`: CMS 证书目录（用于输出 cms.crl）
/// - `ca_cert`: CA 证书（用于设置签发者和 AKI）
/// - `ca_pkey`: CA 私钥（用于签名 CRL）
/// - `revoked_certs`: 已吊销证书列表（证书和 SKI 元组）
///
/// ## 输出文件
/// - `cms/cms.crl`: DER 编码的 CRL 文件
fn generate_crl(
    cms_dir: &Path,
    ca_cert: &X509,
    ca_pkey: &PKey<openssl::pkey::Private>,
    revoked_certs: &[(X509, Vec<u8>)],
) {
    if revoked_certs.is_empty() {
        return;
    }

    let mut crl_builder = X509CrlBuilder::new().expect("Failed to create CRL builder");

    let this_update = Asn1Time::days_from_now(0).expect("Failed to create this_update");
    let next_update = Asn1Time::days_from_now(30).expect("Failed to create next_update");

    crl_builder
        .set_last_update(&this_update)
        .expect("Failed to set last_update");
    crl_builder
        .set_next_update(&next_update)
        .expect("Failed to set next_update");
    crl_builder
        .set_issuer_name(ca_cert.subject_name())
        .expect("Failed to set issuer");

    let crl_num = CrlNumber::new(BigNum::from_u32(1).expect("Failed to create BN"))
        .expect("Failed to create CRL number")
        .build()
        .expect("Failed to build extension");
    crl_builder
        .append_extension(crl_num)
        .expect("Failed to append CRL number");

    let mut temp_builder = X509Builder::new().expect("Failed to create temp builder");
    temp_builder
        .set_subject_name(ca_cert.subject_name())
        .expect("Failed to set subject");
    let context = temp_builder.x509v3_context(Some(ca_cert.as_ref()), None);
    let aki = AuthorityKeyIdentifier::new()
        .keyid(true)
        .build(&context)
        .expect("Failed to build AKI");
    crl_builder
        .append_extension(aki)
        .expect("Failed to append AKI");

    for (cert, _) in revoked_certs {
        let serial = cert.serial_number();
        let revocation_time = Asn1Time::days_from_now(0).expect("Failed to create revocation_time");
        let mut revoked_builder =
            X509RevokedBuilder::new().expect("Failed to create revoked builder");
        revoked_builder
            .set_serial_number(serial)
            .expect("Failed to set serial");
        revoked_builder
            .set_revocation_date(&revocation_time)
            .expect("Failed to set revocation date");
        let revoked = revoked_builder.build();
        crl_builder
            .add_revoked(revoked)
            .expect("Failed to add revoked cert");
    }

    crl_builder.sort().expect("Failed to sort CRL");

    crl_builder
        .sign(ca_pkey, MessageDigest::sha256())
        .expect("Failed to sign CRL");

    let crl = crl_builder.build().expect("Failed to build CRL");

    fs::write(
        cms_dir.join("cms.crl"),
        crl.to_der().expect("Failed to DER encode CRL"),
    )
    .expect("Failed to write CRL");

    println!(
        "Generated CMS CRL with {} revoked certificates",
        revoked_certs.len()
    );
}

/// 生成 TLS/mTLS 测试证书
///
/// 生成用于 TLS 双向认证（mTLS）测试的证书体系，
/// 包括 CA 证书、服务器证书、客户端证书和吊销证书。
///
/// ## 目录结构
/// ```text
/// tls/
/// ├── ca.crt                       # 主 TLS CA 证书
/// ├── other-ca.crt                 # 另一个 CA（用于测试错误的 CA）
/// ├── client-crl.crt               # 客户端 CRL
/// ├── server/
/// │   └── node-{a,b,c}/
/// │       ├── node.crt
/// │       └── node.key
/// └── client/
///     ├── client.crt, client.key   # 正常客户端证书
///     ├── revoked.crt, revoked.key # 已吊销客户端证书
///     └── wrong-ca.crt, wrong-ca.key # 由错误 CA 签发的客户端证书
/// ```
///
/// ## 参数
/// - `output_path`: 输出根目录
/// - `group`: ECC 曲线组（P-256）
fn generate_tls_certificates(output_path: &Path, group: &EcGroup) {
    let tls_dir = output_path.join("tls");
    fs::create_dir_all(&tls_dir).expect("Failed to create tls directory");

    let (ca_cert, ca_pkey, _) = create_ca_cert(group, "TLS Test CA");
    fs::write(
        tls_dir.join("ca.crt"),
        ca_cert.to_pem().expect("Failed to PEM encode"),
    )
    .expect("Failed to write TLS CA cert");

    let (other_ca_cert, other_ca_pkey, _) = create_ca_cert(group, "TLS Other CA");
    fs::write(
        tls_dir.join("other-ca.crt"),
        other_ca_cert.to_pem().expect("Failed to PEM encode"),
    )
    .expect("Failed to write other TLS CA cert");

    let nodes = ["node-a", "node-b", "node-c"];
    for node in &nodes {
        let server_dir = tls_dir.join("server").join(node);
        fs::create_dir_all(&server_dir).expect("Failed to create server directory");

        let (cert, key, _) =
            create_tls_server_cert(group, &ca_cert, &ca_pkey, "localhost".to_string());
        fs::write(
            server_dir.join("node.crt"),
            cert.to_pem().expect("Failed to PEM encode"),
        )
        .expect("Failed to write cert");
        fs::write(
            server_dir.join("node.key"),
            key.private_key_to_pem_pkcs8()
                .expect("Failed to PEM encode"),
        )
        .expect("Failed to write key");

        println!("Generated TLS certificate for {}", node);
    }

    let client_dir = tls_dir.join("client");
    fs::create_dir_all(&client_dir).expect("Failed to create client directory");

    let (client_cert, client_key, _) =
        create_tls_client_cert(group, &ca_cert, &ca_pkey, "TLS Test Client");
    fs::write(
        client_dir.join("client.crt"),
        client_cert.to_pem().expect("Failed to PEM encode"),
    )
    .expect("Failed to write client cert");
    fs::write(
        client_dir.join("client.key"),
        client_key
            .private_key_to_pem_pkcs8()
            .expect("Failed to PEM encode"),
    )
    .expect("Failed to write client key");
    println!("Generated TLS client certificate");

    let (revoked_client_cert, revoked_client_key, _) =
        create_tls_client_cert(group, &ca_cert, &ca_pkey, "TLS Revoked Client");
    fs::write(
        client_dir.join("revoked.crt"),
        revoked_client_cert.to_pem().expect("Failed to PEM encode"),
    )
    .expect("Failed to write revoked client cert");
    fs::write(
        client_dir.join("revoked.key"),
        revoked_client_key
            .private_key_to_pem_pkcs8()
            .expect("Failed to PEM encode"),
    )
    .expect("Failed to write revoked client key");
    println!("Generated TLS revoked client certificate");

    let (wrong_ca_client_cert, wrong_ca_client_key, _) =
        create_tls_client_cert(group, &other_ca_cert, &other_ca_pkey, "TLS Wrong CA Client");
    fs::write(
        client_dir.join("wrong-ca.crt"),
        wrong_ca_client_cert.to_pem().expect("Failed to PEM encode"),
    )
    .expect("Failed to write wrong-ca client cert");
    fs::write(
        client_dir.join("wrong-ca.key"),
        wrong_ca_client_key
            .private_key_to_pem_pkcs8()
            .expect("Failed to PEM encode"),
    )
    .expect("Failed to write wrong-ca client key");
    println!("Generated TLS wrong-ca client certificate");

    generate_tls_client_crl(&tls_dir, &ca_cert, &ca_pkey, &[revoked_client_cert]);
}

/// 创建 CA（证书颁发机构）证书
///
/// 生成自签名的 CA 证书，包含 BasicConstraints（CA:TRUE）扩展。
/// CA 证书用于签发终端实体证书（签名证书、服务器证书、客户端证书）。
///
/// ## 参数
/// - `group`: ECC 曲线组（P-256）
/// - `cn`: Common Name（证书主题名称）
///
/// ## 返回值
/// 元组包含：
/// - `X509`: CA 证书
/// - `PKey<Private>`: CA 私钥
/// - `Vec<u8>`: Subject Key Identifier（SKI，20 字节 SHA-1 哈希）
///
/// ## 证书属性
/// - 版本：X.509 v3
/// - 有效期：3650 天（约 10 年）
/// - 序列号：1
/// - 扩展：BasicConstraints (CA:TRUE), SubjectKeyIdentifier
fn create_ca_cert(group: &EcGroup, cn: &str) -> (X509, PKey<openssl::pkey::Private>, Vec<u8>) {
    let ca_key = EcKey::generate(group).expect("Failed to generate CA key");
    let ca_pkey = PKey::from_ec_key(ca_key.clone()).expect("Failed to create CA PKey");

    let mut name = X509NameBuilder::new().expect("Failed to create name builder");
    name.append_entry_by_text("CN", cn)
        .expect("Failed to append CN");
    let name = name.build();

    let mut builder = X509Builder::new().expect("Failed to create builder");
    builder.set_version(2).expect("Failed to set version");
    builder
        .set_subject_name(&name)
        .expect("Failed to set subject");
    builder
        .set_issuer_name(&name)
        .expect("Failed to set issuer");
    builder.set_pubkey(&ca_pkey).expect("Failed to set pubkey");

    let not_before = Asn1Time::days_from_now(0).expect("Failed to create not_before");
    let not_after = Asn1Time::days_from_now(3650).expect("Failed to create not_after");
    builder
        .set_not_before(&not_before)
        .expect("Failed to set not_before");
    builder
        .set_not_after(&not_after)
        .expect("Failed to set not_after");

    let serial = BigNum::from_u32(1).expect("Failed to create serial");
    builder
        .set_serial_number(&serial.to_asn1_integer().expect("Failed to convert serial"))
        .expect("Failed to set serial");

    let bc = BasicConstraints::new()
        .critical()
        .ca()
        .build()
        .expect("Failed to build BC");
    builder.append_extension(bc).expect("Failed to append BC");

    let context = builder.x509v3_context(None, None);
    let ski = SubjectKeyIdentifier::new()
        .build(&context)
        .expect("Failed to build SKI");
    builder.append_extension(ski).expect("Failed to append SKI");

    builder
        .sign(&ca_pkey, MessageDigest::sha256())
        .expect("Failed to sign CA cert");
    let cert = builder.build();

    let cert_id = get_subject_key_id(&cert);

    (cert, ca_pkey, cert_id)
}

/// 创建签名者证书
///
/// 生成用于 CMS 签名的终端实体证书，由 CA 签发。
/// 包含数字签名密钥用法扩展。
///
/// ## 参数
/// - `group`: ECC 曲线组（P-256）
/// - `ca_cert`: 签发 CA 证书
/// - `ca_pkey`: 签发 CA 私钥
/// - `cn`: Common Name（证书主题名称）
///
/// ## 返回值
/// 元组包含：
/// - `X509`: 签名者证书
/// - `PKey<Private>`: 签名者私钥
/// - `Vec<u8>`: Subject Key Identifier（SKI）
///
/// ## 证书属性
/// - 版本：X.509 v3
/// - 有效期：3650 天（约 10 年）
/// - 序列号：基于时间戳的随机值
/// - 扩展：SubjectKeyIdentifier, AuthorityKeyIdentifier, KeyUsage (digitalSignature)
fn create_signer_cert(
    group: &EcGroup,
    ca_cert: &X509,
    ca_pkey: &PKey<openssl::pkey::Private>,
    cn: String,
) -> (X509, PKey<openssl::pkey::Private>, Vec<u8>) {
    let signer_key = EcKey::generate(group).expect("Failed to generate signer key");
    let signer_pkey = PKey::from_ec_key(signer_key.clone()).expect("Failed to create signer PKey");

    let mut name = X509NameBuilder::new().expect("Failed to create name builder");
    name.append_entry_by_text("CN", &cn)
        .expect("Failed to append CN");
    let name = name.build();

    let ca_name = ca_cert.subject_name();

    let mut builder = X509Builder::new().expect("Failed to create builder");
    builder.set_version(2).expect("Failed to set version");
    builder
        .set_subject_name(&name)
        .expect("Failed to set subject");
    builder
        .set_issuer_name(ca_name)
        .expect("Failed to set issuer");
    builder
        .set_pubkey(&signer_pkey)
        .expect("Failed to set pubkey");

    let not_before = Asn1Time::days_from_now(0).expect("Failed to create not_before");
    let not_after = Asn1Time::days_from_now(3650).expect("Failed to create not_after");
    builder
        .set_not_before(&not_before)
        .expect("Failed to set not_before");
    builder
        .set_not_after(&not_after)
        .expect("Failed to set not_after");

    let serial = BigNum::from_u32(rand_serial()).expect("Failed to create serial");
    builder
        .set_serial_number(&serial.to_asn1_integer().expect("Failed to convert serial"))
        .expect("Failed to set serial");

    let context = builder.x509v3_context(Some(ca_cert), None);
    let ski = SubjectKeyIdentifier::new()
        .build(&context)
        .expect("Failed to build SKI");
    let aki = AuthorityKeyIdentifier::new()
        .keyid(true)
        .build(&context)
        .expect("Failed to build AKI");

    builder.append_extension(ski).expect("Failed to append SKI");
    builder.append_extension(aki).expect("Failed to append AKI");

    let ku = KeyUsage::new()
        .digital_signature()
        .build()
        .expect("Failed to build KU");
    builder.append_extension(ku).expect("Failed to append KU");

    builder
        .sign(ca_pkey, MessageDigest::sha256())
        .expect("Failed to sign cert");
    let cert = builder.build();

    let cert_id = get_subject_key_id(&cert);

    (cert, signer_pkey, cert_id)
}

/// 创建已过期证书
///
/// 生成一个已过期的签名证书，用于测试证书有效期验证。
/// 有效期设置为 2000-01-01 至 2010-01-01。
///
/// ## 参数
/// - `group`: ECC 曲线组（P-256）
/// - `ca_cert`: 签发 CA 证书
/// - `ca_pkey`: 签发 CA 私钥
/// - `cn`: Common Name（证书主题名称）
///
/// ## 返回值
/// 元组包含：
/// - `X509`: 已过期证书
/// - `PKey<Private>`: 私钥
/// - `Vec<u8>`: Subject Key Identifier（SKI）
///
/// ## 证书属性
/// - 版本：X.509 v3
/// - 有效期：2000-01-01 00:00:00 UTC 至 2010-01-01 00:00:00 UTC
/// - 扩展：SubjectKeyIdentifier
fn create_expired_cert(
    group: &EcGroup,
    ca_cert: &X509,
    ca_pkey: &PKey<openssl::pkey::Private>,
    cn: &str,
) -> (X509, PKey<openssl::pkey::Private>, Vec<u8>) {
    let signer_key = EcKey::generate(group).expect("Failed to generate signer key");
    let signer_pkey = PKey::from_ec_key(signer_key.clone()).expect("Failed to create signer PKey");

    let mut name = X509NameBuilder::new().expect("Failed to create name builder");
    name.append_entry_by_text("CN", cn)
        .expect("Failed to append CN");
    let name = name.build();

    let ca_name = ca_cert.subject_name();

    let mut builder = X509Builder::new().expect("Failed to create builder");
    builder.set_version(2).expect("Failed to set version");
    builder
        .set_subject_name(&name)
        .expect("Failed to set subject");
    builder
        .set_issuer_name(ca_name)
        .expect("Failed to set issuer");
    builder
        .set_pubkey(&signer_pkey)
        .expect("Failed to set pubkey");

    let not_before = Asn1Time::from_str("20000101000000Z").expect("Failed to create not_before");
    let not_after = Asn1Time::from_str("20100101000000Z").expect("Failed to create not_after");
    builder
        .set_not_before(&not_before)
        .expect("Failed to set not_before");
    builder
        .set_not_after(&not_after)
        .expect("Failed to set not_after");

    let serial = BigNum::from_u32(rand_serial()).expect("Failed to create serial");
    builder
        .set_serial_number(&serial.to_asn1_integer().expect("Failed to convert serial"))
        .expect("Failed to set serial");

    let context = builder.x509v3_context(Some(ca_cert), None);
    let ski = SubjectKeyIdentifier::new()
        .build(&context)
        .expect("Failed to build SKI");
    builder.append_extension(ski).expect("Failed to append SKI");

    builder
        .sign(ca_pkey, MessageDigest::sha256())
        .expect("Failed to sign cert");
    let cert = builder.build();

    let cert_id = get_subject_key_id(&cert);

    (cert, signer_pkey, cert_id)
}

/// 创建自签名证书
///
/// 生成一个自签名证书（不受信任的证书），用于测试证书链验证。
/// 此证书由自身签发，不包含 AuthorityKeyIdentifier 扩展。
///
/// ## 参数
/// - `group`: ECC 曲线组（P-256）
/// - `cn`: Common Name（证书主题名称）
///
/// ## 返回值
/// 元组包含：
/// - `X509`: 自签名证书
/// - `PKey<Private>`: 私钥
/// - `Vec<u8>`: Subject Key Identifier（SKI）
///
/// ## 证书属性
/// - 版本：X.509 v3
/// - 有效期：3650 天（约 10 年）
/// - 签发者：等于主题（自签名）
/// - 扩展：SubjectKeyIdentifier
fn create_self_signed_cert(
    group: &EcGroup,
    cn: &str,
) -> (X509, PKey<openssl::pkey::Private>, Vec<u8>) {
    let key = EcKey::generate(group).expect("Failed to generate key");
    let pkey = PKey::from_ec_key(key.clone()).expect("Failed to create PKey");

    let mut name = X509NameBuilder::new().expect("Failed to create name builder");
    name.append_entry_by_text("CN", cn)
        .expect("Failed to append CN");
    let name = name.build();

    let mut builder = X509Builder::new().expect("Failed to create builder");
    builder.set_version(2).expect("Failed to set version");
    builder
        .set_subject_name(&name)
        .expect("Failed to set subject");
    builder
        .set_issuer_name(&name)
        .expect("Failed to set issuer");
    builder.set_pubkey(&pkey).expect("Failed to set pubkey");

    let not_before = Asn1Time::days_from_now(0).expect("Failed to create not_before");
    let not_after = Asn1Time::days_from_now(3650).expect("Failed to create not_after");
    builder
        .set_not_before(&not_before)
        .expect("Failed to set not_before");
    builder
        .set_not_after(&not_after)
        .expect("Failed to set not_after");

    let serial = BigNum::from_u32(rand_serial()).expect("Failed to create serial");
    builder
        .set_serial_number(&serial.to_asn1_integer().expect("Failed to convert serial"))
        .expect("Failed to set serial");

    let context = builder.x509v3_context(None, None);
    let ski = SubjectKeyIdentifier::new()
        .build(&context)
        .expect("Failed to build SKI");
    builder.append_extension(ski).expect("Failed to append SKI");

    builder
        .sign(&pkey, MessageDigest::sha256())
        .expect("Failed to sign cert");
    let cert = builder.build();

    let cert_id = get_subject_key_id(&cert);

    (cert, pkey, cert_id)
}

/// 创建 TLS 服务器证书
///
/// 生成用于 TLS 服务器认证的证书。
/// 当前实现复用 `create_signer_cert`，未来可添加 SAN（Subject Alternative Name）扩展。
///
/// ## 参数
/// - `group`: ECC 曲线组（P-256）
/// - `ca_cert`: 签发 CA 证书
/// - `ca_pkey`: 签发 CA 私钥
/// - `cn`: Common Name（服务器域名，如 "localhost"）
///
/// ## 返回值
/// 元组包含：
/// - `X509`: 服务器证书
/// - `PKey<Private>`: 服务器私钥
/// - `Vec<u8>`: Subject Key Identifier（SKI）
fn create_tls_server_cert(
    group: &EcGroup,
    ca_cert: &X509,
    ca_pkey: &PKey<openssl::pkey::Private>,
    cn: String,
) -> (X509, PKey<openssl::pkey::Private>, Vec<u8>) {
    create_signer_cert(group, ca_cert, ca_pkey, cn)
}

/// 创建 TLS 客户端证书
///
/// 生成用于 mTLS（双向 TLS）客户端认证的证书。
/// 包含 SKI 和 AKI 扩展，用于证书链验证。
///
/// ## 参数
/// - `group`: ECC 曲线组（P-256）
/// - `ca_cert`: 签发 CA 证书
/// - `ca_pkey`: 签发 CA 私钥
/// - `cn`: Common Name（客户端标识）
///
/// ## 返回值
/// 元组包含：
/// - `X509`: 客户端证书
/// - `PKey<Private>`: 客户端私钥
/// - `Vec<u8>`: Subject Key Identifier（SKI）
///
/// ## 证书属性
/// - 版本：X.509 v3
/// - 有效期：3650 天（约 10 年）
/// - 扩展：SubjectKeyIdentifier, AuthorityKeyIdentifier
fn create_tls_client_cert(
    group: &EcGroup,
    ca_cert: &X509,
    ca_pkey: &PKey<openssl::pkey::Private>,
    cn: &str,
) -> (X509, PKey<openssl::pkey::Private>, Vec<u8>) {
    let key = EcKey::generate(group).expect("Failed to generate key");
    let pkey = PKey::from_ec_key(key.clone()).expect("Failed to create PKey");

    let mut name = X509NameBuilder::new().expect("Failed to create name builder");
    name.append_entry_by_text("CN", cn)
        .expect("Failed to append CN");
    let name = name.build();

    let ca_name = ca_cert.subject_name();

    let mut builder = X509Builder::new().expect("Failed to create builder");
    builder.set_version(2).expect("Failed to set version");
    builder
        .set_subject_name(&name)
        .expect("Failed to set subject");
    builder
        .set_issuer_name(ca_name)
        .expect("Failed to set issuer");
    builder.set_pubkey(&pkey).expect("Failed to set pubkey");

    let not_before = Asn1Time::days_from_now(0).expect("Failed to create not_before");
    let not_after = Asn1Time::days_from_now(3650).expect("Failed to create not_after");
    builder
        .set_not_before(&not_before)
        .expect("Failed to set not_before");
    builder
        .set_not_after(&not_after)
        .expect("Failed to set not_after");

    let serial = BigNum::from_u32(rand_serial()).expect("Failed to create serial");
    builder
        .set_serial_number(&serial.to_asn1_integer().expect("Failed to convert serial"))
        .expect("Failed to set serial");

    let context = builder.x509v3_context(Some(ca_cert), None);
    let ski = SubjectKeyIdentifier::new()
        .build(&context)
        .expect("Failed to build SKI");
    let aki = AuthorityKeyIdentifier::new()
        .keyid(true)
        .build(&context)
        .expect("Failed to build AKI");

    builder.append_extension(ski).expect("Failed to append SKI");
    builder.append_extension(aki).expect("Failed to append AKI");

    builder
        .sign(ca_pkey, MessageDigest::sha256())
        .expect("Failed to sign cert");
    let cert = builder.build();

    let cert_id = get_subject_key_id(&cert);

    (cert, pkey, cert_id)
}

/// 计算证书的 Subject Key Identifier（SKI）
///
/// SKI 是证书公钥的唯一标识符，用于证书链验证和 AKI 扩展。
/// 根据 RFC 5280，SKI 是公钥 DER 编码的 SHA-1 哈希值（20 字节）。
///
/// ## 参数
/// - `cert`: X.509 证书
///
/// ## 返回值
/// - `Vec<u8>`: 20 字节的 SHA-1 哈希值
fn get_subject_key_id(cert: &X509) -> Vec<u8> {
    let pubkey_der = cert
        .public_key()
        .expect("Failed to get public key")
        .public_key_to_der()
        .expect("Failed to DER encode public key");
    openssl::hash::hash(MessageDigest::sha1(), &pubkey_der)
        .expect("Failed to hash public key")
        .to_vec()
}

/// 生成随机证书序列号
///
/// 基于当前时间戳生成伪随机序列号，用于终端实体证书。
/// 使用秒数和纳秒数的异或值，确保唯一性。
///
/// ## 返回值
/// - `u32`: 随机序列号
fn rand_serial() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    (duration.as_secs() as u32) ^ (duration.subsec_nanos())
}

/// 生成 TLS 客户端 CRL（证书吊销列表）
///
/// 创建用于 mTLS 客户端认证的 CRL 文件，包含已吊销客户端证书的序列号。
/// CRL 由 TLS CA 私钥签名，有效期 30 天。
///
/// ## 参数
/// - `tls_dir`: TLS 证书目录（用于输出 client-crl.crt）
/// - `ca_cert`: TLS CA 证书（用于设置签发者和 AKI）
/// - `ca_pkey`: TLS CA 私钥（用于签名 CRL）
/// - `revoked_clients`: 已吊销的客户端证书列表
///
/// ## 输出文件
/// - `tls/client-crl.crt`: DER 编码的客户端 CRL 文件
fn generate_tls_client_crl(
    tls_dir: &Path,
    ca_cert: &X509,
    ca_pkey: &PKey<openssl::pkey::Private>,
    revoked_clients: &[X509],
) {
    if revoked_clients.is_empty() {
        return;
    }

    let mut crl_builder = X509CrlBuilder::new().expect("Failed to create CRL builder");

    let this_update = Asn1Time::days_from_now(0).expect("Failed to create this_update");
    let next_update = Asn1Time::days_from_now(30).expect("Failed to create next_update");

    crl_builder
        .set_last_update(&this_update)
        .expect("Failed to set last_update");
    crl_builder
        .set_next_update(&next_update)
        .expect("Failed to set next_update");
    crl_builder
        .set_issuer_name(ca_cert.subject_name())
        .expect("Failed to set issuer");

    let crl_num = CrlNumber::new(BigNum::from_u32(1).expect("Failed to create BN"))
        .expect("Failed to create CRL number")
        .build()
        .expect("Failed to build extension");
    crl_builder
        .append_extension(crl_num)
        .expect("Failed to append CRL number");

    let mut temp_builder = X509Builder::new().expect("Failed to create temp builder");
    temp_builder
        .set_subject_name(ca_cert.subject_name())
        .expect("Failed to set subject");
    let context = temp_builder.x509v3_context(Some(ca_cert.as_ref()), None);
    let aki = AuthorityKeyIdentifier::new()
        .keyid(true)
        .build(&context)
        .expect("Failed to build AKI");
    crl_builder
        .append_extension(aki)
        .expect("Failed to append AKI");

    for cert in revoked_clients {
        let serial = cert.serial_number();
        let revocation_time = Asn1Time::days_from_now(0).expect("Failed to create revocation_time");
        let mut revoked_builder =
            X509RevokedBuilder::new().expect("Failed to create revoked builder");
        revoked_builder
            .set_serial_number(serial)
            .expect("Failed to set serial");
        revoked_builder
            .set_revocation_date(&revocation_time)
            .expect("Failed to set revocation date");
        let revoked = revoked_builder.build();
        crl_builder
            .add_revoked(revoked)
            .expect("Failed to add revoked cert");
    }

    crl_builder.sort().expect("Failed to sort CRL");

    crl_builder
        .sign(ca_pkey, MessageDigest::sha256())
        .expect("Failed to sign CRL");

    let crl = crl_builder.build().expect("Failed to build CRL");

    fs::write(
        tls_dir.join("client-crl.crt"),
        crl.to_der().expect("Failed to DER encode CRL"),
    )
    .expect("Failed to write TLS client CRL");

    println!(
        "Generated TLS client CRL with {} revoked certificates",
        revoked_clients.len()
    );
}
