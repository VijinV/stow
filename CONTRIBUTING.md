# Contributing to Stow

Bug fixes, portability improvements, tests, and documentation are welcome. For a larger change, open an issue to discuss the behavior and scope before writing code. Follow the [code of conduct](CODE_OF_CONDUCT.md) and report security concerns through [private disclosure](SECURITY.md).

## Set up your checkout

1. Fork [VijinV/stow](https://github.com/VijinV/stow) and clone your fork.
2. Install the stable Rust toolchain and your platform’s native tools. On Linux, use a standard C toolchain and an X11 session to exercise the desktop GUI. The local TLS integration tests use OpenSSL. On macOS, install the Xcode command-line tools. On Windows, use the MSVC toolchain and the Visual Studio C++ build tools.
3. For dashboard work, install Node.js 22.12 or newer. The dashboard’s AWS dependencies require Rust 1.94.1 or newer.

## Build and test

Run these from the repository root.

```sh
cargo test --workspace --locked
cargo build --release --locked
```

For dashboard changes, run the API tests and build the web application.

```sh
cargo test --locked --manifest-path dashboard/api/Cargo.toml
npm --prefix dashboard/web ci
npm --prefix dashboard/web run build
```

See the [dashboard guide](dashboard/README.md) to run both components together. The default test suites use test fixtures. Opt-in S3 integration tests require disposable storage. They default to loopback ports 9000 and 8333 and accept `BT_S3_ENDPOINTS`, `BT_S3_KEY`, and `BT_S3_SECRET` for disposable credentials and endpoints.

```sh
cargo test --locked -p bt-s3 --test integration -- --ignored --test-threads=1
cargo test --locked --bin backup-taker feature_tests::encrypted_backup_browse_restore_end_to_end -- --ignored --test-threads=1
```

For packaging changes, see [the release workflow](.github/workflows/release.yml). It builds the Linux packages with `packaging/linux/build-deb.sh`, the macOS DMG with `packaging/macos/build-app.sh`, and the Windows setup with Inno Setup and `packaging/windows/installer.iss`.

## Find the right code

- `src/` contains the desktop GUI, CLI, backup engine, and dashboard integration.
- `crates/bt-gui`, `crates/bt-s3`, and `crates/bt-tls` contain the desktop GUI toolkit, S3 client, and TLS implementation.
- `dashboard/api` contains the Axum API and SQLite schema. `dashboard/web` contains the React frontend.

## Submit a pull request

Keep changes focused and describe how you verified them. Include the platform, storage provider, and whether you tested standalone or managed mode when relevant. Add a regression test for a bug when the existing tests would miss it. Update the [user guide](docs/usage.md) or [dashboard guide](dashboard/README.md) when changing a user workflow. Use synthetic files and credentials in all examples, tests, logs, and screenshots.

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
