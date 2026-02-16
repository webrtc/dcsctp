# GEMINI.md

## Project Overview

`dcsctp` is a Rust implementation of the Stream Control Transmission Protocol
(SCTP, [RFC 9260](https://www.rfc-editor.org/rfc/rfc9260.txt)) designed for 
WebRTC Data Channels ([RFC 8831](https://www.rfc-editor.org/rfc/rfc8831.txt)). 
It is a user-space library intended to be embedded in larger systems (like 
WebRTC  implementations), not a standalone server or in an operating system 
kernel.

## Architecture

- **Core Design**: The library is single-threaded and event-driven. It does not
  perform I/O directly. The consumer drives the loop by feeding packets/timer
  events and handling outgoing commands.
- **Entry Point**: The primary interface is the `DcSctpSocket` trait defined in 
  `src/api/mod.rs`. Use `dcsctp::new_socket` (in `src/lib.rs`) to instantiate.
- **Directory Structure**:
  - `src/api/`: Public API and configuration options.
  - `src/packet/`: Wire format parsing and serialization (Chunks, Parameters).
  - `src/socket/`: Main state machine and socket logic.
  - `src/rx/` & `src/tx/`: Receiver and Transmitter logic (reassembly,
    congestion control).
  - `src/timer/`: Timer abstractions (does not use system timers directly).
  - `fuzz/`: Fuzz targets.
- **C++ Bindings**: `src/ffi.rs` provides C++ bindings using `cxx`. Any changes
  to the public API must also be added here.

## Development Workflow

- **Build**: `cargo build`
- **Test**: `cargo test` (Runs extensive unit and integration tests).
- **Lint**: `cargo clippy --all-features --all-targets -- -D warnings`
- **Format**: `cargo +nightly fmt --all -- --check`

## Coding Standards

- **Safety**: `unsafe` code is strictly prohibited (`deny(unsafe_code)`).
- **Error Handling**: Use `thiserror` for error types. Return
  `Result<T, Error>` for fallible operations.
- **Logging**: Use the `log` crate (`trace!`, `debug!`, `info!`, `warn!`,
  `error!`). Do not use `println!`.
- **Async**: The library is synchronous. Do not introduce `async/await` in core
  logic.
- **Dependencies**: Keep dependencies minimal. Major ones: `log`, `thiserror`,
  `fastrand`.

## Contribution Rules

- **Changelog**: All functional changes must be documented in `CHANGELOG.md`
  under the *Unreleased* section (categories: Added, Changed, Deprecated,
  Removed, Fixed, Security).
- **Commits**: Use clear, descriptive commit messages.
- **Pull Requests**: One change per PR.
