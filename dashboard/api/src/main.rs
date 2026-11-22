use std::{env, net::SocketAddr, path::PathBuf};
use stow_dashboard::{app, AppState};
use tower_http::services::ServeDir;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    set_private_file_creation();
    let administrator = env::var("STOW_ADMIN_TOKEN")?;
    let path = PathBuf::from(
        env::var_os("STOW_DB").unwrap_or_else(|| "dashboard/data/stow.sqlite3".into()),
    );
    if let Some(parent) = path.parent().filter(|path| !path.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let state = AppState::open(path, &administrator)?;
    #[cfg(feature = "aws")]
    let state = if env::var("STOW_AWS_SESSIONS").as_deref() == Ok("1") {
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .load()
            .await;
        state.with_aws(
            aws_sdk_sts::Client::new(&config),
            env::var("STOW_AWS_EXTERNAL_ID").ok(),
        )
    } else {
        state
    };
    let listen = env::var("STOW_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:8787".into())
        .parse::<SocketAddr>()?;
    let mut router = app(state);
    let web =
        PathBuf::from(env::var_os("STOW_WEB_DIR").unwrap_or_else(|| "dashboard/web/dist".into()));
    if web.join("index.html").is_file() {
        router = router.fallback_service(ServeDir::new(web));
    }
    let listener = tokio::net::TcpListener::bind(listen).await?;
    println!(
        "Stow dashboard listening at http://{}",
        listener.local_addr()?
    );
    axum::serve(listener, router).await?;
    Ok(())
}

#[cfg(unix)]
fn set_private_file_creation() {
    unsafe extern "C" {
        fn umask(mask: std::ffi::c_uint) -> std::ffi::c_uint;
    }
    // Apply the private default before opening SQLite or creating its sidecar files.
    unsafe {
        umask(0o077);
    }
}
