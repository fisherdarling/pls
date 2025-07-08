# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`pls` (renamed to `certs`) is a human-first tool for working with x509 certificates and other WebPKI/TLS primitives. The project recently underwent a rename from `pls` to `certs` but some references may still use the old name.

## Build and Development Commands

### Building
```bash
cargo build --workspace          # Build all crates
cargo build --release           # Release build
cargo check --workspace         # Quick compile check
```

### Testing
```bash
cargo test --workspace          # Run all tests
cargo test --workspace -- --nocapture  # Run tests with output
cargo test -p certs-types        # Test specific crate
```

### Linting and Quality
```bash
cargo clippy --workspace        # Run clippy lints
cargo clippy --workspace --fix  # Auto-fix linting issues
cargo fmt --all                 # Format code
```

### Running the CLI
The main binary is built as `certs`:
```bash
cargo run --bin certs -- parse ./test-data/certs/chain.pem
cargo run --bin certs -- scan /path/to/directory
```

## Architecture

### Workspace Structure
This is a Rust workspace with multiple crates:

- **certs-cli**: Main CLI application with argument parsing and command dispatch
- **certs-types**: Core data structures for certificates, keys, CSRs, and X.509 primitives
- **certs-parser**: PEM/DER parsing logic for extracting certificates from various formats
- **certs-scanner**: File system scanning and certificate discovery
- **certs-display**: Output formatting (JSON, text, PEM) and display logic
- **certs-settings**: Configuration management
- **certs-scan-index**: Indexing for scanned certificates
- **simple-progress**: Progress bar utility library

### Key Dependencies
- Uses **BoringSSL** (via custom fork) for cryptographic operations and X.509 parsing
- **clap** for CLI argument parsing
- **insta** for snapshot testing
- **jiff** for date/time handling
- **foundations** for structured logging

### Data Flow
1. CLI parses arguments and determines command (scan/parse)
2. Files are discovered and read by scanner/parser
3. PEM entities are extracted and parsed into typed structures
4. Results are formatted and displayed via certs-display

### Testing
- Uses `insta` for snapshot testing with `.snap` files in `certs-types/src/snapshots/`
- Test data available in `test-data/` directory with sample certificates, CSRs, and keys
- Tests cover parsing various certificate formats and edge cases

## Development Notes

- The project uses edition 2024 Rust features
- Custom BoringSSL fork adds post-quantum crypto support and additional X.509 field access
- Supports parsing certificates embedded in YAML, JSON, and other text formats
- Automatic JSON output when stdout is not a TTY
- Certificate chains are handled as arrays by default