// No console window for the GUI app on Windows; CLI mode re-attaches to the parent console.
#![cfg_attr(windows, windows_subsystem = "windows")]

mod app_ui;
mod browse;
mod browser_ui;
mod cli;
mod config;
mod engine;
#[cfg(test)]
mod feature_tests;
mod file_crypto;
mod glob;
mod json;
mod paths;
mod preview;
mod remote;
mod schedule;
mod secret;
mod timefmt;

#[cfg(windows)]
fn attach_console() {
    #[link(name = "kernel32")]
    extern "system" {
        fn AttachConsole(pid: u32) -> i32;
    }
    unsafe {
        AttachConsole(0xFFFF_FFFF); // ATTACH_PARENT_PROCESS
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if !args.is_empty() && !args[0].starts_with("-psn_") {
        #[cfg(windows)]
        attach_console();
        std::process::exit(cli::run(&args));
    }
    let result = app_ui::run();
    preview::shutdown();
    if let Err(err) = result {
        eprintln!("Could not open Backup Taker: {err}");
        std::process::exit(1);
    }
}
