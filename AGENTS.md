# AGENTS.md

## Project Overview

`dcsctp` is a Rust implementation of the Stream Control Transmission Protocol
(SCTP, [RFC 9260](https://www.rfc-editor.org/rfc/rfc9260.txt)) designed for
WebRTC Data Channels ([RFC 8831](https://www.rfc-editor.org/rfc/rfc8831.txt)).
It is a user-space library intended to be embedded in larger systems (like
WebRTC implementations), not a standalone server or in an operating system
kernel.

## Architecture

- **Core Design**: The library is **single-threaded** and **event-driven**.
  It does not perform I/O directly. The consumer drives the loop by feeding
  packets/timer events and handling outgoing commands.
- **Entry Point**: The primary public interface is the `DcSctpSocket` trait
  (`src/api/mod.rs`). The implementation is `Socket` (`src/socket/mod.rs`).
- **Internal**:
  - `src/socket/`: State machine, connection establishment/teardown.
  - `src/rx/`: Receiver logic (congestion control, reassembly).
  - `src/tx/`: Transmitter logic (congestion control, retransmission).
  - `src/timer/`: Timer abstractions (does not use system timers).
- **C++ Bindings**: `src/ffi.rs` uses `cxx` to expose the Rust API to C++.
  Changes to `src/api/` must often be reflected in `src/ffi.rs`.

## Development Workflow

- **Build**: `cargo build`
- **Test**: `cargo test` (Runs extensive unit and integration tests).
- **Lint**: `cargo clippy --all-features --all-targets -- -D warnings`
- **Format**: `cargo +nightly fmt --all -- --check`

## Contribution Rules

- **Changelog**: All functional changes must be documented in `CHANGELOG.md`
  under the *Unreleased* section (categories: Added, Changed, Deprecated,
  Removed, Fixed, Security).
