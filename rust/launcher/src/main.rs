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

mod cli;
mod dispatcher;

mod logger;
mod qemu;
mod utils;

use crate::cli::{SubCommand, print_help};
use log::info;
use std::error::Error;
use std::process;

fn main() -> Result<(), Box<dyn Error>> {
    if let Err(e) = logger::init_default_logger() {
        eprintln!("Failed to initialize logger: {}", e);
        process::exit(1);
    }
    info!("Start to run vm");
    let sub_command = cli::parse_args()?;
    match sub_command {
        SubCommand::Help(help_type) => {
            print_help(&help_type);
            process::exit(0);
        }
        SubCommand::Run(mut run_args) => {
            if run_args.runtime.is_none() {
                run_args.runtime = Some("qemu".to_string());
            }
            dispatcher::run(&run_args)?;
        }
    }
    Ok(())
}
