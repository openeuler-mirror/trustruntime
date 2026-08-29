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

use openssl::ec::EcGroup;
use openssl::symm::Cipher;
use openssl::x509::X509;
use std::fs;
use std::path::Path;

use crate::certificate::{
    create_ca_cert, create_cert_with_usage, create_crl_with_revoked, create_empty_crl,
    create_expired_cert, create_self_signed_cert, create_signer_cert, create_tls_server_cert,
    generate_crl, KeyUsageFlags,
};

pub fn generate_cms_certificates(output_path: &Path, group: &EcGroup) {
    let cms_dir = output_path.join("cms");
    fs::create_dir_all(&cms_dir).expect("Failed to create cms directory");

    let (ca_cert, ca_pkey, _ca_id) = create_ca_cert(group, "localhost");
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

    let ca_cert_pem = ca_cert.to_pem().expect("Failed to PEM encode CA cert");

    for node in &nodes {
        let node_dir = cms_dir.join(node);
        fs::create_dir_all(&node_dir).expect("Failed to create node directory");

        let (cert, key, _cert_id) =
            create_signer_cert(group, &ca_cert, &ca_pkey, "localhost".to_string());
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

        fs::write(node_dir.join("ca.crt"), &ca_cert_pem)
            .expect("Failed to write CA cert to node directory");

        println!("Generated CMS certificate for {}", node);
    }

    let expired_dir = cms_dir.join("expired");
    fs::create_dir_all(&expired_dir).expect("Failed to create expired directory");
    let (expired_cert, expired_key, _) =
        create_expired_cert(group, &ca_cert, &ca_pkey, "localhost");
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
    fs::write(expired_dir.join("ca.crt"), &ca_cert_pem)
        .expect("Failed to write CA cert to expired directory");
    println!("Generated expired CMS certificate");

    let revoked_dir = cms_dir.join("revoked");
    fs::create_dir_all(&revoked_dir).expect("Failed to create revoked directory");
    let (revoked_cert, revoked_key, revoked_id) =
        create_signer_cert(group, &ca_cert, &ca_pkey, "localhost".to_string());
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
    fs::write(revoked_dir.join("ca.crt"), &ca_cert_pem)
        .expect("Failed to write CA cert to revoked directory");
    revoked_certs.push((revoked_cert, revoked_id));
    println!("Generated revoked CMS certificate");

    generate_crl(&cms_dir, &ca_cert, &ca_pkey, &revoked_certs);

    let cms_crl_path = cms_dir.join("cms.crl");
    let cms_crl_content = fs::read(&cms_crl_path).expect("Failed to read CMS CRL");

    for node in &nodes {
        let node_dir = cms_dir.join(node);
        fs::write(node_dir.join("cms.crl"), &cms_crl_content)
            .expect("Failed to write CRL to node directory");
    }

    fs::write(cms_dir.join("expired/cms.crl"), &cms_crl_content)
        .expect("Failed to write CRL to expired directory");
    fs::write(cms_dir.join("revoked/cms.crl"), &cms_crl_content)
        .expect("Failed to write CRL to revoked directory");

    let self_signed_dir = cms_dir.join("self-signed");
    fs::create_dir_all(&self_signed_dir).expect("Failed to create self-signed directory");
    let (self_cert, self_key, _) = create_self_signed_cert(group, "localhost");
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

pub fn generate_tls_certificates(output_path: &Path, group: &EcGroup) {
    let tls_dir = output_path.join("tls");
    fs::create_dir_all(&tls_dir).expect("Failed to create tls directory");

    let key_password = b"MyPasswd123";

    let (ca_cert, ca_pkey, _) = create_ca_cert(group, "localhost");
    let ca_dir = tls_dir.join("ca");
    fs::create_dir_all(&ca_dir).expect("Failed to create CA directory");
    fs::write(
        ca_dir.join("ca.crt"),
        ca_cert.to_pem().expect("Failed to PEM encode CA cert"),
    )
    .expect("Failed to write CA cert");
    fs::write(
        ca_dir.join("ca.key"),
        ca_pkey
            .private_key_to_pem_pkcs8()
            .expect("Failed to PEM encode CA key"),
    )
    .expect("Failed to write CA key");
    println!("Generated unified TLS CA certificate");

    let nodes = ["node-a", "node-b", "node-c"];
    for node in &nodes {
        generate_server_cert(&tls_dir, group, &ca_cert, &ca_pkey, node, key_password);
        generate_ubse_cert(&tls_dir, group, &ca_cert, &ca_pkey, node, key_password);
        generate_lcne_cert(&tls_dir, group, &ca_cert, &ca_pkey, node, key_password);
    }

    // 生成测试用的特殊客户端证书
    generate_test_client_certs(&tls_dir, group, &ca_cert, &ca_pkey, key_password);
}

#[allow(clippy::too_many_arguments)]
fn write_cert_files(
    dir: &Path,
    cert: &X509,
    key: &openssl::pkey::PKey<openssl::pkey::Private>,
    key_password: &[u8],
    ca_cert: &X509,
    cert_filename: &str,
    key_filename: &str,
    ca_filename: &str,
) {
    fs::create_dir_all(dir).expect("Failed to create directory");

    fs::write(
        dir.join(cert_filename),
        cert.to_pem().expect("Failed to PEM encode cert"),
    )
    .expect("Failed to write cert");

    fs::write(
        dir.join(key_filename),
        key.private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), key_password)
            .expect("Failed to encrypt and PEM encode key"),
    )
    .expect("Failed to write key");

    fs::write(dir.join("key_pwd.txt"), key_password).expect("Failed to write key password");

    fs::write(
        dir.join(ca_filename),
        ca_cert.to_pem().expect("Failed to PEM encode CA cert"),
    )
    .expect("Failed to write CA cert");
}

fn generate_server_cert(
    tls_dir: &Path,
    group: &EcGroup,
    ca_cert: &X509,
    ca_pkey: &openssl::pkey::PKey<openssl::pkey::Private>,
    node: &str,
    key_password: &[u8],
) {
    let server_dir = tls_dir.join("server").join(node);
    let (cert, key, _) = create_tls_server_cert(group, ca_cert, ca_pkey, "localhost".to_string());

    write_cert_files(
        &server_dir,
        &cert,
        &key,
        key_password,
        ca_cert,
        "certificate.crt",
        "private.key",
        "ca_root.crt",
    );

    let crl = create_empty_crl(ca_cert, ca_pkey);
    fs::write(server_dir.join("cert.crl"), crl).expect("Failed to write CRL");

    println!("Generated TLS server certificate for {}", node);
}

fn generate_ubse_cert(
    tls_dir: &Path,
    group: &EcGroup,
    ca_cert: &X509,
    ca_pkey: &openssl::pkey::PKey<openssl::pkey::Private>,
    node: &str,
    key_password: &[u8],
) {
    let ubse_dir = tls_dir.join("ubse").join(node);
    let (cert, key, _) = create_cert_with_usage(
        group,
        ca_cert,
        ca_pkey,
        "localhost",
        KeyUsageFlags::DIGITAL_SIGNATURE | KeyUsageFlags::KEY_ENCIPHERMENT,
        Some(&["serverAuth", "clientAuth"]),
    );

    write_cert_files(
        &ubse_dir,
        &cert,
        &key,
        key_password,
        ca_cert,
        "server.pem",
        "server_key.pem",
        "trust.pem",
    );

    println!("Generated TLS ubse certificate for {}", node);
}

fn generate_lcne_cert(
    tls_dir: &Path,
    group: &EcGroup,
    ca_cert: &X509,
    ca_pkey: &openssl::pkey::PKey<openssl::pkey::Private>,
    node: &str,
    key_password: &[u8],
) {
    let lcne_dir = tls_dir.join("lcne").join(node);
    let (cert, key, _) = create_cert_with_usage(
        group,
        ca_cert,
        ca_pkey,
        "localhost",
        KeyUsageFlags::DIGITAL_SIGNATURE | KeyUsageFlags::KEY_ENCIPHERMENT,
        Some(&["serverAuth", "clientAuth"]),
    );

    write_cert_files(
        &lcne_dir,
        &cert,
        &key,
        key_password,
        ca_cert,
        "certificate.crt",
        "private.key",
        "ca_root.crt",
    );

    let crl = create_empty_crl(ca_cert, ca_pkey);
    fs::write(lcne_dir.join("communication.crl"), crl).expect("Failed to write CRL");

    println!("Generated TLS lcne certificate for {}", node);
}

fn generate_test_client_certs(
    tls_dir: &Path,
    group: &EcGroup,
    ca_cert: &X509,
    ca_pkey: &openssl::pkey::PKey<openssl::pkey::Private>,
    key_password: &[u8],
) {
    let test_clients_dir = tls_dir.join("test-clients");
    fs::create_dir_all(&test_clients_dir).expect("Failed to create test-clients directory");

    // 生成另一个CA（用于测试错误CA场景）
    let (other_ca_cert, other_ca_pkey, _) = create_ca_cert(group, "localhost");
    fs::write(
        test_clients_dir.join("other-ca.crt"),
        other_ca_cert.to_pem().expect("Failed to PEM encode"),
    )
    .expect("Failed to write other CA cert");
    println!("Generated TLS test other CA certificate");

    // 生成被吊销的客户端证书
    let (revoked_cert, revoked_key, _) = create_cert_with_usage(
        group,
        ca_cert,
        ca_pkey,
        "localhost",
        KeyUsageFlags::DIGITAL_SIGNATURE | KeyUsageFlags::KEY_ENCIPHERMENT,
        Some(&["clientAuth"]),
    );
    fs::write(
        test_clients_dir.join("revoked.crt"),
        revoked_cert.to_pem().expect("Failed to PEM encode"),
    )
    .expect("Failed to write revoked client cert");
    fs::write(
        test_clients_dir.join("revoked.key"),
        revoked_key
            .private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), key_password)
            .expect("Failed to encrypt and PEM encode key"),
    )
    .expect("Failed to write revoked client key");
    println!("Generated TLS revoked client certificate");

    // 生成错误CA签发的客户端证书
    let (wrong_ca_cert, wrong_ca_key, _) = create_cert_with_usage(
        group,
        &other_ca_cert,
        &other_ca_pkey,
        "localhost",
        KeyUsageFlags::DIGITAL_SIGNATURE | KeyUsageFlags::KEY_ENCIPHERMENT,
        Some(&["clientAuth"]),
    );
    fs::write(
        test_clients_dir.join("wrong-ca.crt"),
        wrong_ca_cert.to_pem().expect("Failed to PEM encode"),
    )
    .expect("Failed to write wrong-ca client cert");
    fs::write(
        test_clients_dir.join("wrong-ca.key"),
        wrong_ca_key
            .private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), key_password)
            .expect("Failed to encrypt and PEM encode key"),
    )
    .expect("Failed to write wrong-ca client key");
    println!("Generated TLS wrong-ca client certificate");

    // 生成客户端CRL（包含被吊销的证书）
    let crl = create_crl_with_revoked(ca_cert, ca_pkey, &[revoked_cert]);
    fs::write(test_clients_dir.join("client-crl.crt"), crl).expect("Failed to write client CRL");
    println!("Generated TLS client CRL with 1 revoked certificate");
}
