//! 验签+签名接口示例 (0x12 → 0x13)
//!
//! 演示如何调用 TrustRuntime 验签+签名接口：
//! 1. 使用签名接口产生的 signed_data 进行验签
//! 2. 验签通过后使用新的数据进行签名
//!
//! 运行前需要：
//! - TrustRuntime 服务已启动
//! - 已通过签名接口获得 signed_data 和 cert_id
//!
//! 运行方法：
//! ```bash
//! # 设置环境变量（可选，默认使用内置值）
//! export TRUSTRUNTIME_CID=3
//! export TRUSTRUNTIME_PORT=12345
//! export TRUSTRUNTIME_CLIENT_CERT=/etc/cert/cms/communication/client.crt
//! export TRUSTRUNTIME_CLIENT_KEY=/etc/cert/cms/communication/client.key
//! export TRUSTRUNTIME_CA_CERT=/etc/cert/cms/communication/ca_root.crt
//!
//! # 编译并运行
//! cargo run --example verify_and_sign_example
//! ```

mod common;

const MSG_TYPE_VERIFY_AND_SIGN_REQ: u32 = 0x12;
const MSG_TYPE_VERIFY_AND_SIGN_RESP: u32 = 0x13;

fn main() {
    let (cid, port) = common::get_config();

    println!("验签+签名接口示例");
    println!("连接: CID={}, Port={}", cid, port);

    let original_data = "Hello, TrustRuntime!";
    let signed_data = "<Base64编码的签名数据，来自0x11响应>";
    let signer_cert_id = "<Base64编码的证书ID，来自0x11响应>";
    let new_data = "New message to sign";
    let new_cert_id = signer_cert_id;

    match verify_and_sign(
        cid,
        port,
        original_data,
        signed_data,
        signer_cert_id,
        new_data,
        new_cert_id,
    ) {
        Ok(result) => {
            println!("\n验签+签名成功:");
            println!(
                "  signed_data: {}...",
                &result.signed_data[..50.min(result.signed_data.len())]
            );
            println!("  cert_id: {}", result.cert_id);
            println!("  result: {}", result.result);
        }
        Err(e) => {
            println!("\n验签+签名失败: {}", e);
        }
    }
}

struct VerifyAndSignResult {
    signed_data: String,
    cert_id: String,
    result: u32,
}

fn verify_and_sign(
    cid: u32,
    port: u32,
    verify_data: &str,
    verify_signed_data: &str,
    verify_cert_id: &str,
    sign_data: &str,
    sign_cert_id: &str,
) -> Result<VerifyAndSignResult, String> {
    let mut stream = common::connect_vsock_tls(cid, port)?;

    let request = serde_json::json!({
        "to-verify": {
            "data": verify_data,
            "signed_data": verify_signed_data,
            "id": verify_cert_id
        },
        "to-sign": {
            "data": sign_data,
            "id": sign_cert_id
        }
    });
    let request_bytes = request.to_string().into_bytes();

    common::send_message(&mut stream, 1, MSG_TYPE_VERIFY_AND_SIGN_REQ, &request_bytes)?;

    let (resp_type, resp_data) = common::recv_message(&mut stream)?;

    if resp_type != MSG_TYPE_VERIFY_AND_SIGN_RESP {
        return Err(format!("响应类型错误: 0x{:02x}", resp_type));
    }

    let json: serde_json::Value =
        serde_json::from_slice(&resp_data).map_err(|e| format!("JSON解析失败: {}", e))?;

    let result = json["result"].as_u64().unwrap_or(999) as u32;

    if result != 0 {
        return Err(format!("验签+签名失败, result={}", result));
    }

    Ok(VerifyAndSignResult {
        signed_data: json["signed_data"].as_str().unwrap_or("").to_string(),
        cert_id: json["id"].as_str().unwrap_or("").to_string(),
        result,
    })
}
