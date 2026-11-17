// No console window for the GUI app on Windows; CLI mode re-attaches to the parent console.
#![cfg_attr(windows, windows_subsystem = "windows")]

mod cli;
mod config;
mod engine;
mod glob;
mod json;
mod paths;
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
    eprintln!("GUI not wired yet");
}
