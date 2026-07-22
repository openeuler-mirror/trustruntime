mod cli;
mod dispatcher;

mod logger;
mod qemu;
mod utils;

use crate::cli::{print_help, SubCommand};
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
