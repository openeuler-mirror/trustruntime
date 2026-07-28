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

use log::LevelFilter;
use log4rs::append::rolling_file::policy::compound::{
    roll::fixed_window::FixedWindowRollerBuilder, trigger::size::SizeTrigger, CompoundPolicy,
};
use log4rs::append::rolling_file::RollingFileAppender;
use log4rs::config::{Appender, Config, Root};
use log4rs::encode::pattern::PatternEncoder;
use std::error::Error;
use std::path::Path;

const MAX_FILE_SIZE: u64 = 1024 * 1024;
const MAX_BACKUPS: u32 = 5;

pub fn init_logger(
    log_path: &str,
    max_file_size: u64,
    max_backups: u32,
    log_level: LevelFilter,
) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = Path::new(log_path).parent() {
        std::fs::create_dir_all(parent).unwrap_or_else(|e| {
            eprintln!("Error creating log directory: {}", e);
        });
    }

    let log_path_buf = Path::new(log_path).to_path_buf();
    let log_dir = log_path_buf
        .parent()
        .unwrap_or_else(|| Path::new("/var/log/trustruntime/"));
    let log_filename = log_path_buf
        .file_name()
        .unwrap_or_else(|| Path::new("trtlauncher").as_os_str())
        .to_str()
        .unwrap_or("trtlauncher");
    let binding = log_dir.join(format!("{}.{{}}", log_filename));
    let archive_pattern = binding.to_str().unwrap_or("/var/log/trustruntime/trtlauncher.{}");
    let roller = FixedWindowRollerBuilder::default()
        .base(1)
        .build(archive_pattern, max_backups)?;

    //配置回滚
    let trigger = SizeTrigger::new(max_file_size);
    let policy = CompoundPolicy::new(Box::new(trigger), Box::new(roller));

    //日志格式说明：[时间] [级别] [文件：行号] 消息\n
    let log_pattern = "[{d(%y-%m-%d %H:%M:%S%.3f)}] [{l}] [{f}:{L}] - {m}{n}";
    let file_appender = RollingFileAppender::builder()
        .encoder(Box::new(PatternEncoder::new(log_pattern)))
        .build(log_path, Box::new(policy))?;
    let config = Config::builder()
        .appender(Appender::builder().build("file", Box::new(file_appender)))
        .build(Root::builder().appender("file").build(log_level))?;

    log4rs::init_config(config)?;
    Ok(())
}

pub fn init_default_logger() -> Result<(), Box<dyn Error>> {
    init_logger(
        "/var/log/trustruntime/trtlauncher",
        MAX_FILE_SIZE,
        MAX_BACKUPS,
        LevelFilter::Debug,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use log::LevelFilter;

    #[test]
    fn init_logger_success_then_second_fails() {
        let dir = tempfile::TempDir::new().unwrap();
        let log_path1 = dir.path().join("test1.log");
        let log_path2 = dir.path().join("test2.log");
        let result1 = init_logger(&log_path1.to_string_lossy(), 1024 * 1024, 5, LevelFilter::Debug);
        assert!(result1.is_ok());
        let result2 = init_logger(&log_path2.to_string_lossy(), 1024 * 1024, 5, LevelFilter::Debug);
        assert!(result2.is_err());
    }
}
