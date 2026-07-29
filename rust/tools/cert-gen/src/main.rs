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

//! cert-gen: ECC-256测试证书生成工具
//!
//! 生成CMS集成测试和TLS测试所需的测试证书、私钥和CRL文件。
//!
//! 用法: `cert-gen --output-dir <DIR> [--force]`
//!
//! 详细说明见 README.md。

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
