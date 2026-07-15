//! 签名接口示例 (0x10 → 0x11)
//!
//! 演示如何调用 TrustRuntime 签名接口：
//! 1. 建立 TLS over vsock 连接
//! 2. 发送签名请求 (type=0x10)
//! 3. 接收签名响应 (type=0x11)
//!
//! 运行前需要：
//! - TrustRuntime 服务已启动
//! - 配置正确的客户端证书
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
//! cargo run --example sign_example
//! ```

mod common;

const MSG_TYPE_SIGN_REQ: u32 = 0x10;
const MSG_TYPE_SIGN_RESP: u32 = 0x11;

fn main() {
    let (cid, port) = common::get_config();

    println!("签名接口示例");
    println!("连接: CID={}, Port={}", cid, port);

    let data_to_sign = "Hello, TrustRuntime!";

    match sign(cid, port, data_to_sign) {
        Ok(result) => {
            println!("\n签名成功:");
            println!(
                "  signed_data: {}...",
                &result.signed_data[..50.min(result.signed_data.len())]
            );
            println!("  cert_id: {}", result.cert_id);
            println!("  result: {}", result.result);
        }
        Err(e) => {
            println!("\n签名失败: {}", e);
        }
    }
}

struct SignResult {
    signed_data: String,
    cert_id: String,
    result: u32,
}

fn sign(cid: u32, port: u32, data: &str) -> Result<SignResult, String> {
    let mut stream = common::connect_vsock_tls(cid, port)?;

    let request = serde_json::json!({
        "to-sign": {
            "data": data
        }
    });
    let request_bytes = request.to_string().into_bytes();

    common::send_message(&mut stream, 1, MSG_TYPE_SIGN_REQ, &request_bytes)?;

    let (resp_type, resp_data) = common::recv_message(&mut stream)?;

    if resp_type != MSG_TYPE_SIGN_RESP {
        return Err(format!("响应类型错误: 0x{:02x}", resp_type));
    }

    let json: serde_json::Value =
        serde_json::from_slice(&resp_data).map_err(|e| format!("JSON解析失败: {}", e))?;

    let result = json["result"].as_u64().unwrap_or(999) as u32;
    if result != 0 {
        return Err(format!("签名失败, result={}", result));
    }

    Ok(SignResult {
        signed_data: json["signed_data"].as_str().unwrap_or("").to_string(),
        cert_id: json["id"].as_str().unwrap_or("").to_string(),
        result,
    })
}
