use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, CrlNumber, ExtendedKeyUsage, KeyUsage,
    SubjectKeyIdentifier,
};
use openssl::x509::{
    X509Builder, X509CrlBuilder, X509Extension, X509NameBuilder, X509RevokedBuilder, X509,
};
use std::fs;
use std::path::Path;

use crate::utils::{get_subject_key_id, rand_serial};

/// KeyUsage 标志位
pub struct KeyUsageFlags;

impl KeyUsageFlags {
    pub const DIGITAL_SIGNATURE: u32 = 0x80;
    pub const KEY_ENCIPHERMENT: u32 = 0x20;
    pub const NON_REPUDIATION: u32 = 0x40;
    pub const DATA_ENCIPHERMENT: u32 = 0x10;
    pub const KEY_AGREEMENT: u32 = 0x08;
    pub const KEY_CERT_SIGN: u32 = 0x04;
    pub const CRL_SIGN: u32 = 0x02;
}

fn build_key_usage_extension(key_usage: u32) -> X509Extension {
    let mut ku = KeyUsage::new();
    if (key_usage & KeyUsageFlags::DIGITAL_SIGNATURE) != 0 {
        ku.digital_signature();
    }
    if (key_usage & KeyUsageFlags::KEY_ENCIPHERMENT) != 0 {
        ku.key_encipherment();
    }
    if (key_usage & KeyUsageFlags::NON_REPUDIATION) != 0 {
        ku.non_repudiation();
    }
    if (key_usage & KeyUsageFlags::DATA_ENCIPHERMENT) != 0 {
        ku.data_encipherment();
    }
    if (key_usage & KeyUsageFlags::KEY_AGREEMENT) != 0 {
        ku.key_agreement();
    }
    if (key_usage & KeyUsageFlags::KEY_CERT_SIGN) != 0 {
        ku.key_cert_sign();
    }
    if (key_usage & KeyUsageFlags::CRL_SIGN) != 0 {
        ku.crl_sign();
    }
    ku.build().expect("Failed to build KeyUsage")
}

fn build_extended_key_usage_extension(eku_oids: &[&str]) -> X509Extension {
    let mut eku = ExtendedKeyUsage::new();
    for oid in eku_oids {
        match *oid {
            "serverAuth" => eku.server_auth(),
            "clientAuth" => eku.client_auth(),
            _ => panic!("Unsupported EKU OID: {}", oid),
        };
    }
    eku.build().expect("Failed to build ExtendedKeyUsage")
}

fn add_key_identifiers(builder: &mut X509Builder, ca_cert: &X509) {
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
}

pub fn create_ca_cert(group: &EcGroup, cn: &str) -> (X509, PKey<openssl::pkey::Private>, Vec<u8>) {
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

pub fn create_cert_with_usage(
    group: &EcGroup,
    ca_cert: &X509,
    ca_pkey: &PKey<openssl::pkey::Private>,
    cn: &str,
    key_usage: u32,
    extended_key_usage: Option<&[&str]>,
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
        .set_issuer_name(ca_cert.subject_name())
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

    builder
        .append_extension(build_key_usage_extension(key_usage))
        .expect("Failed to append KU");

    if let Some(eku_oids) = extended_key_usage {
        builder
            .append_extension(build_extended_key_usage_extension(eku_oids))
            .expect("Failed to append EKU");
    }

    add_key_identifiers(&mut builder, ca_cert);

    builder
        .sign(ca_pkey, MessageDigest::sha256())
        .expect("Failed to sign cert");
    let cert = builder.build();
    let cert_id = get_subject_key_id(&cert);

    (cert, pkey, cert_id)
}

pub fn create_signer_cert(
    group: &EcGroup,
    ca_cert: &X509,
    ca_pkey: &PKey<openssl::pkey::Private>,
    cn: String,
) -> (X509, PKey<openssl::pkey::Private>, Vec<u8>) {
    create_cert_with_usage(
        group,
        ca_cert,
        ca_pkey,
        &cn,
        KeyUsageFlags::DIGITAL_SIGNATURE,
        None,
    )
}

pub fn create_comm_cert(
    group: &EcGroup,
    ca_cert: &X509,
    ca_pkey: &PKey<openssl::pkey::Private>,
    cn: &str,
) -> (X509, PKey<openssl::pkey::Private>, Vec<u8>) {
    create_cert_with_usage(
        group,
        ca_cert,
        ca_pkey,
        cn,
        KeyUsageFlags::DIGITAL_SIGNATURE | KeyUsageFlags::KEY_ENCIPHERMENT,
        Some(&["serverAuth"]),
    )
}

pub fn create_expired_cert(
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

    let mut ku_builder = KeyUsage::new();
    ku_builder.digital_signature();
    let ku = ku_builder.build().expect("Failed to build KU");
    builder.append_extension(ku).expect("Failed to append KU");

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

#[allow(dead_code)]
pub fn create_not_yet_valid_cert(
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

    let not_before = Asn1Time::days_from_now(365).expect("Failed to create not_before");
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

    let mut ku_builder = KeyUsage::new();
    ku_builder.digital_signature();
    let ku = ku_builder.build().expect("Failed to build KU");
    builder.append_extension(ku).expect("Failed to append KU");

    let context = builder.x509v3_context(None, None);
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

pub fn create_self_signed_cert(
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

    let mut ku_builder = KeyUsage::new();
    ku_builder.digital_signature();
    let ku = ku_builder.build().expect("Failed to build KU");
    builder.append_extension(ku).expect("Failed to append KU");

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

pub fn create_tls_server_cert(
    group: &EcGroup,
    ca_cert: &X509,
    ca_pkey: &PKey<openssl::pkey::Private>,
    cn: String,
) -> (X509, PKey<openssl::pkey::Private>, Vec<u8>) {
    create_comm_cert(group, ca_cert, ca_pkey, &cn)
}

pub fn create_tls_client_cert(
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

    let ku = KeyUsage::new()
        .digital_signature()
        .key_encipherment()
        .build()
        .expect("Failed to build KU");
    builder.append_extension(ku).expect("Failed to append KU");

    let eku = ExtendedKeyUsage::new()
        .client_auth()
        .build()
        .expect("Failed to build EKU");
    builder.append_extension(eku).expect("Failed to append EKU");

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

pub fn generate_crl(
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

pub fn generate_tls_client_crl(
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
