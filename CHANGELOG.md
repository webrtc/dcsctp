# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- `DcSctpSocket::send_many()` is now implemented.

### Changed

- The code is now compatible with Rust 2024 edition.

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
