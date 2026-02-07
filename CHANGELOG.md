# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Fixed

 - Possible incorrect RTT calculation on packet loss.

## 0.1.10 - 2025-02-26

### Fixed

 - Relaxed sequence number handling for stream reset requests.
 - Corrected outgoing requests to be compliant with RFC6525.

### Changed

 - Optimized performance of message reassembly.

## 0.1.9 - 2025-02-16

### Fixed

 - Corrected "Fast Recovery" retransmission logic.
 - Corrected outstanding data calculation.
 - Added OnLifecycleMessageFullySent lifecycle events when sending message.
 - Fixed bug where delayed SACKs would be sent immediately when time advances.

## 0.1.8 - 2026-02-06

### Changed

 - Replaced `rng` crate dependency with more lightweight `fastrand`.
 - Removed dependency on `crc_any` crate.
 - The `rwnd` member in handover state has been renamed to `a_rwnd`.

### Fixed

 - Fixed a wrapping substraction during zero window probing.
 - Improved chunk validation

## 0.1.7 - 2026-01-21

### Fixed

 - Fixed a socket handover bug.

## 0.1.6 - 2026-01-19

### Fixed

 - Fixed a bug with simultaneous connection attempts.

## 0.1.5 - 2026-01-15

### Added

- `DcSctpSocket::send_many()` is now implemented and accessible with CXX.
- Exposed handover methods and structs in the CXX interface.
- Added `dcsctp_cxx::get_metrics()` and `dcsctp_cxx::reset_streams()` to the
  CXX interface, making it expose the full `DcSctpSocket` trait.

### Changed

- The code is now compatible with Rust 2024 edition.
- Updated CXX interface for `dcsctp_cxx::send()` to avoid copying the message
  payload.
- Handover is now code complete, compatible with the C++ implementation.

## 0.1.4 - 2026-01-12

### Added

- Most of the API methods are exposed in CXX.

## 0.1.3 - 2026-01-09

### Changed

- The cxx child crate is now part of the parent crate, as an optional feature.
- Time handling is revised, to use a custom SocketTime instead of Instant.
- Added CXX FFI for time handling.

## 0.1.2 - 2025-12-15

### Added

- Added cxx child crate for C++ interoperability.

## 0.1.1 - 2025-08-21

### Added

- Exposed Socket in the public API.

### Changed

- A pull-based API for receiving messages, which allows for back-pressure to be
  applied when the application can't consume messages fast enough.

## 0.1.0 - 2025-08-12

First release.
