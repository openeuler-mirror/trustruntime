//! 验签接口示例 (0x14 → 0x15)
//!
//! 演示如何调用 TrustRuntime 验签接口：
//! 1. 使用验签+签名接口产生的 signed_data 进行验签
//! 2. 判断签名方证书身份
//!
//! 返回 result 含义：
//! - 0: 本节点签名（证书ID匹配）
//! - 1: 其他节点签名（验签有效，ID不匹配）
//! - 2: 证书身份冲突（验签有效，公钥相同）
//! - >=3: 验签失败
//!
//! 运行前需要：
//! - TrustRuntime 服务已启动
//! - 已获得 signed_data 和 cert_id
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
//! cargo run --example verify_example
//! ```

mod common;

const MSG_TYPE_VERIFY_REQ: u32 = 0x14;
const MSG_TYPE_VERIFY_RESP: u32 = 0x15;

fn main() {
    let (cid, port) = common::get_config();

    println!("验签接口示例");
    println!("连接: CID={}, Port={}", cid, port);

    let original_data = "New message to sign";
    let signed_data = "<Base64编码的签名数据，来自0x13响应>";
    let signer_cert_id = "<Base64编码的证书ID，来自0x13响应>";

    match verify(cid, port, original_data, signed_data, signer_cert_id) {
        Ok(result) => {
            println!("\n验签结果:");
            println!("  result: {}", result);
            match result {
                0 => println!("  含义: 本节点签名"),
                1 => println!("  含义: 其他节点签名（验签有效）"),
                2 => println!("  含义: 证书身份冲突（安全告警）"),
                r => println!("  含义: 验签失败 (code={})", r),
            }
        }
        Err(e) => {
            println!("\n验签失败: {}", e);
        }
    }
}

fn verify(
    cid: u32,
    port: u32,
    data: &str,
    signed_data: &str,
    cert_id: &str,
) -> Result<u32, String> {
    let mut stream = common::connect_vsock_tls(cid, port)?;

    let request = serde_json::json!({
        "to-verify": {
            "data": data,
            "signed_data": signed_data,
            "id": cert_id
        }
    });
    let request_bytes = request.to_string().into_bytes();

    common::send_message(&mut stream, 1, MSG_TYPE_VERIFY_REQ, &request_bytes)?;

    let (resp_type, resp_data) = common::recv_message(&mut stream)?;

    if resp_type != MSG_TYPE_VERIFY_RESP {
        return Err(format!("响应类型错误: 0x{:02x}", resp_type));
    }

    let json: serde_json::Value =
        serde_json::from_slice(&resp_data).map_err(|e| format!("JSON解析失败: {}", e))?;

    Ok(json["result"].as_u64().unwrap_or(999) as u32)
}
