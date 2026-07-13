//! vsock CID测试工具
//!
//! 用于探测vsock连接的可用CID值。
//! 在WSL2环境中，不同CID可能有不同的可达性。
//!
//! ## 测试的CID值
//! - 1: VMADDR_CID_LOCAL（本地连接）
//! - 2: 预留CID
//! - 0xFFFFFFFF: VMADDR_CID_ANY（任意地址）
//! - 0xFFFFFFFE: VMADDR_CID_HOST（连接宿主机）
//!
//! ## 使用方式
//! ```bash
//! cargo run --bin vsock_cid_test
//! ```

use std::io::{Read, Write};
use vsock::VsockAddr;

fn main() {
    let port = 12345;

    // 尝试不同的CID值
    // VMADDR_CID_LOCAL (1) - WSL2本地连接常用
    // VMADDR_CID_HOST (0xFFFFFFFE) - 从guest连接到host
    for cid in [1, 2, 0xFFFFFFFF, 0xFFFFFFFE] {
        println!("Testing CID={} (0x{:08X})...", cid, cid);
        let addr = VsockAddr::new(cid, port);
        match vsock::VsockStream::connect(&addr) {
            Ok(mut stream) => {
                println!("  Connected successfully!");
                // 发送测试数据
                let _ = stream.write_all(b"test");
                let mut buf = [0u8; 100];
                match stream.read(&mut buf) {
                    Ok(n) => println!("  Received {} bytes", n),
                    Err(e) => println!("  Read error: {}", e),
                }
                return;
            }
            Err(e) => println!("  Connection failed: {}", e),
        }
    }

    println!("All CID attempts failed");
}