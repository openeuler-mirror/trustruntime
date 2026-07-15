//! 单元测试

use super::connection::create_error_response;
use super::error::*;
use super::tls::{set_socket_timeout, TlsConfig};
use super::VsockTransport;
use crate::transport::{DataHandler, TransportLayer};
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::x509::extension::{BasicConstraints, SubjectKeyIdentifier};
use openssl::x509::{X509Builder, X509NameBuilder};
use std::fs;

fn create_test_cert_and_key() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let (ca_cert, ca_pkey) = create_test_ca_cert();
    let (server_cert, server_pkey) = create_test_server_cert(&ca_cert, &ca_pkey);

    (
        ca_cert.to_pem().unwrap(),
        server_cert.to_pem().unwrap(),
        server_pkey.private_key_to_pem_pkcs8().unwrap(),
    )
}

fn create_test_ca_cert() -> (openssl::x509::X509, PKey<openssl::pkey::Private>) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ca_key = EcKey::generate(&group).unwrap();
    let ca_pkey = PKey::from_ec_key(ca_key.clone()).unwrap();

    let mut ca_name = X509NameBuilder::new().unwrap();
    ca_name.append_entry_by_text("CN", "Test CA").unwrap();
    let ca_name = ca_name.build();

    let mut ca_builder = X509Builder::new().unwrap();
    ca_builder.set_version(2).unwrap();
    ca_builder.set_subject_name(&ca_name).unwrap();
    ca_builder.set_issuer_name(&ca_name).unwrap();
    ca_builder.set_pubkey(&ca_pkey).unwrap();

    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(3650).unwrap();
    ca_builder.set_not_before(&not_before).unwrap();
    ca_builder.set_not_after(&not_after).unwrap();

    let serial = BigNum::from_u32(1).unwrap();
    ca_builder
        .set_serial_number(&serial.to_asn1_integer().unwrap())
        .unwrap();

    let bc = BasicConstraints::new().critical().ca().build().unwrap();
    ca_builder.append_extension(bc).unwrap();

    let context = ca_builder.x509v3_context(None, None);
    let ski = SubjectKeyIdentifier::new().build(&context).unwrap();
    ca_builder.append_extension(ski).unwrap();

    ca_builder.sign(&ca_pkey, MessageDigest::sha256()).unwrap();
    let ca_cert = ca_builder.build();

    (ca_cert, ca_pkey)
}

fn create_test_server_cert(
    ca_cert: &openssl::x509::X509,
    ca_pkey: &PKey<openssl::pkey::Private>,
) -> (openssl::x509::X509, PKey<openssl::pkey::Private>) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let server_key = EcKey::generate(&group).unwrap();
    let server_pkey = PKey::from_ec_key(server_key.clone()).unwrap();

    let mut server_name = X509NameBuilder::new().unwrap();
    server_name
        .append_entry_by_text("CN", "Test Server")
        .unwrap();
    let server_name = server_name.build();

    let mut server_builder = X509Builder::new().unwrap();
    server_builder.set_version(2).unwrap();
    server_builder.set_subject_name(&server_name).unwrap();
    server_builder
        .set_issuer_name(ca_cert.subject_name())
        .unwrap();
    server_builder.set_pubkey(&server_pkey).unwrap();

    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(3650).unwrap();
    server_builder.set_not_before(&not_before).unwrap();
    server_builder.set_not_after(&not_after).unwrap();

    let serial2 = BigNum::from_u32(2).unwrap();
    server_builder
        .set_serial_number(&serial2.to_asn1_integer().unwrap())
        .unwrap();

    let context2 = server_builder.x509v3_context(Some(ca_cert), None);
    let ski2 = SubjectKeyIdentifier::new().build(&context2).unwrap();
    server_builder.append_extension(ski2).unwrap();

    server_builder
        .sign(ca_pkey, MessageDigest::sha256())
        .unwrap();
    let server_cert = server_builder.build();

    (server_cert, server_pkey)
}

struct MockHandler;

impl DataHandler for MockHandler {
    fn handle(&self, data: &[u8]) -> Option<Vec<u8>> {
        Some(data.to_vec())
    }
}

#[test]
fn vsock_transport_can_be_created() {
    let temp_dir = std::env::temp_dir().join("vsock_transport_test");
    fs::create_dir_all(&temp_dir).unwrap();

    let (ca_pem, server_pem, server_key_pem) = create_test_cert_and_key();
    let ca_path = temp_dir.join("ca.crt");
    let server_path = temp_dir.join("server.crt");
    let server_key_path = temp_dir.join("server.key");

    fs::write(&ca_path, &ca_pem).unwrap();
    fs::write(&server_path, &server_pem).unwrap();
    fs::write(&server_key_path, &server_key_pem).unwrap();

    let config = TlsConfig {
        cert_path: server_path.to_str().unwrap().to_string(),
        key_path: server_key_path.to_str().unwrap().to_string(),
        key_password: None,
        ca_cert_path: ca_path.to_str().unwrap().to_string(),
        crl_path: None,
    };

    let transport = VsockTransport::new(&config, 12345, MAX_CONCURRENT_CONNECTIONS as u32);
    assert!(transport.is_ok());

    fs::remove_dir_all(&temp_dir).unwrap();
}

#[test]
fn vsock_transport_registers_handlers() {
    let temp_dir = std::env::temp_dir().join("vsock_handler_test");
    fs::create_dir_all(&temp_dir).unwrap();

    let (ca_pem, server_pem, server_key_pem) = create_test_cert_and_key();
    let ca_path = temp_dir.join("ca.crt");
    let server_path = temp_dir.join("server.crt");
    let server_key_path = temp_dir.join("server.key");

    fs::write(&ca_path, &ca_pem).unwrap();
    fs::write(&server_path, &server_pem).unwrap();
    fs::write(&server_key_path, &server_key_pem).unwrap();

    let config = TlsConfig {
        cert_path: server_path.to_str().unwrap().to_string(),
        key_path: server_key_path.to_str().unwrap().to_string(),
        key_password: None,
        ca_cert_path: ca_path.to_str().unwrap().to_string(),
        crl_path: None,
    };

    let transport = VsockTransport::new(&config, 12345, MAX_CONCURRENT_CONNECTIONS as u32).unwrap();
    transport.register_handler(0x10, Box::new(MockHandler));
    transport.register_handler(0x12, Box::new(MockHandler));

    let handlers = transport.handlers().read().unwrap();
    assert_eq!(handlers.len(), 2);
    assert!(handlers.contains_key(&0x10));
    assert!(handlers.contains_key(&0x12));

    fs::remove_dir_all(&temp_dir).unwrap();
}

#[test]
fn vsock_transport_handler_registration_overwrites() {
    let temp_dir = std::env::temp_dir().join("vsock_overwrite_test");
    fs::create_dir_all(&temp_dir).unwrap();

    let (ca_pem, server_pem, server_key_pem) = create_test_cert_and_key();
    let ca_path = temp_dir.join("ca.crt");
    let server_path = temp_dir.join("server.crt");
    let server_key_path = temp_dir.join("server.key");

    fs::write(&ca_path, &ca_pem).unwrap();
    fs::write(&server_path, &server_pem).unwrap();
    fs::write(&server_key_path, &server_key_pem).unwrap();

    let config = TlsConfig {
        cert_path: server_path.to_str().unwrap().to_string(),
        key_path: server_key_path.to_str().unwrap().to_string(),
        key_password: None,
        ca_cert_path: ca_path.to_str().unwrap().to_string(),
        crl_path: None,
    };

    let transport = VsockTransport::new(&config, 12345, MAX_CONCURRENT_CONNECTIONS as u32).unwrap();

    transport.register_handler(0x10, Box::new(MockHandler));
    transport.register_handler(0x10, Box::new(MockHandler));

    let handlers = transport.handlers().read().unwrap();
    assert_eq!(handlers.len(), 1);
    assert!(handlers.contains_key(&0x10));

    fs::remove_dir_all(&temp_dir).unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires vsock environment"]
async fn vsock_transport_start_returns_ok() {
    let temp_dir = std::env::temp_dir().join("vsock_start_test");
    fs::create_dir_all(&temp_dir).unwrap();

    let (ca_pem, server_pem, server_key_pem) = create_test_cert_and_key();
    let ca_path = temp_dir.join("ca.crt");
    let server_path = temp_dir.join("server.crt");
    let server_key_path = temp_dir.join("server.key");

    fs::write(&ca_path, &ca_pem).unwrap();
    fs::write(&server_path, &server_pem).unwrap();
    fs::write(&server_key_path, &server_key_pem).unwrap();

    let config = TlsConfig {
        cert_path: server_path.to_str().unwrap().to_string(),
        key_path: server_key_path.to_str().unwrap().to_string(),
        key_password: None,
        ca_cert_path: ca_path.to_str().unwrap().to_string(),
        crl_path: None,
    };

    let transport = VsockTransport::new(&config, 12345, MAX_CONCURRENT_CONNECTIONS as u32).unwrap();
    let result = transport.start().await;
    assert!(result.is_ok());

    fs::remove_dir_all(&temp_dir).unwrap();
}

#[test]
fn create_error_response_has_zero_len() {
    let resp = create_error_response(123, PROTOCOL_VERSION, ERROR_PROTOCOL);
    assert_eq!(resp.header.seq, 123);
    assert_eq!(resp.header.version, PROTOCOL_VERSION);
    assert_eq!(resp.header.msg_type, ERROR_PROTOCOL);
    assert_eq!(resp.header.len, 0);
    assert!(resp.data.is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn set_socket_timeout_success() {
    use std::time::Duration;

    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    assert!(fd >= 0);

    let result = set_socket_timeout(fd, Duration::from_secs(1));
    assert!(result.is_ok());

    unsafe { libc::close(fd) };
}

#[cfg(target_os = "linux")]
#[test]
fn accept_timeout_error_handling() {
    use std::io::Error;

    let e = Error::from_raw_os_error(libc::EAGAIN);
    assert!(e.raw_os_error() == Some(libc::EAGAIN));

    let e = Error::from_raw_os_error(libc::EWOULDBLOCK);
    assert!(e.raw_os_error() == Some(libc::EWOULDBLOCK));
}
