use openssl::ec::EcGroup;
use openssl::x509::X509;
use std::fs;
use std::path::Path;

use crate::certificate::{
    create_ca_cert, create_expired_cert, create_self_signed_cert, create_signer_cert,
    create_tls_client_cert, create_tls_server_cert, generate_crl, generate_tls_client_crl,
};

pub fn generate_cms_certificates(output_path: &Path, group: &EcGroup) {
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

pub fn generate_tls_certificates(output_path: &Path, group: &EcGroup) {
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