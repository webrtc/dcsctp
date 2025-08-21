# GEMINI.md

This document provides important context about the `dcsctp` project for the Gemini AI assistant.

## Project Overview

`dcsctp` is a Rust implementation of the Stream Control Transmission Protocol (SCTP) tailored for WebRTC Data Channels. It's a network programming library designed to be used in larger WebRTC applications.

## Directory Structure

*   `.github/`: Contains GitHub Actions workflows for continuous integration.
*   `fuzz/`: Contains fuzzing targets and related files for testing the robustness of the parser.
*   `src/`: The main source code for the `dcsctp` library.
    *   `api/`: Public API definitions.
    *   `events.rs`: Event definitions.
    *   `fuzzer/`: Fuzzing-related utilities.
    *   `lib.rs`: The main library file.
    *   `packet/`: SCTP packet and chunk definitions and parsing logic.
    *   `rx/`: Code related to receiving data.
    *   `socket/`: The main SCTP socket implementation.
    *   `testing/`: Testing utilities and data generators.
    *   `timer.rs`: Timer-related logic.
    *   `tx/`: Code related to sending data.
    *   `types.rs`: Core data types used throughout the library.

## Core Commands

When working on this project, please use the following commands to ensure code quality and correctness.

### Building the code

To build the project, run:
```bash
cargo build
```

### Running tests

The project has a comprehensive test suite. To run all tests, use:
```bash
cargo test
```

### Linting and formatting

This project uses `rustfmt` for code formatting and `clippy` for linting.

To check for formatting issues, run:
```bash
cargo +nightly fmt --all -- --check
```

To run the linter, use:
```bash
cargo clippy --all-features --all-targets -- -D warnings
```

## Project Conventions

*   The project follows standard Rust conventions.
*   All code should be formatted with `rustfmt`.
*   All code should pass `clippy` checks with no warnings.
*   New features should be accompanied by unit tests.
*   Commit messages should be clear and descriptive.
