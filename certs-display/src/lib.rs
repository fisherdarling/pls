//! Display X.509 certificates and related cryptographic types in human-readable format or JSON.
//!
//! This crate provides rendering capabilities for certificate data structures from [`certs-types`],
//! using the `iocraft` library for terminal UI components with SwiftUI-like syntax.
//!
//! ## Core Components
//!
//! - [`Config`]: Controls which certificate fields are displayed (public keys, SANs, fingerprints, etc.)
//! - [`OutputFormat`]: Specifies output format (JSON, text, or PEM)
//!
//! ## Display Components
//!
//! The crate includes specialized view components for different certificate parts:
//! - `CertView`: Main certificate display with subject, validity, public key, usage, issuer, and fingerprints
//! - `SubjectView`: Certificate subject information with SANs, SKI, and serial number
//! - `SansView`: Subject Alternative Names (DNS, IP, email, URI)
//! - Utility components for labeled text and lists
//!
//! ## Usage
//!
//! Components use `iocraft`'s declarative syntax with Views, flex directions, gaps, margins,
//! and coloring. All view components follow the pattern of accepting `Option<&T>` props
//! and gracefully handling missing data with fallback displays.
//!
//! ## Implementation Notes
//!
//! - Components are marked with `#[component]` and props must `#[derive(Props)]` and `impl Default`
//! - The crate uses a pattern of `struct Props { foo: Option<Foo> }` with early returns for missing data
//! - Colors are used consistently: Green for labels and content, Red for error states
//! - Layout uses flexbox-style containers with configurable directions and spacing
//!
//! ## Testing
//!
//! Testing is done via `insta` snapshot testing to ensure consistent output formatting.
//! Tests render components to strings and compare against stored snapshots, making it
//! easy to catch unintended formatting changes.

mod impls;

/// Configuration for controlling which certificate fields are displayed.
///
/// This struct provides fine-grained control over the output, allowing users to
/// show or hide specific certificate components based on their needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// Display public key information (algorithm, key size, key data)
    pub print_public_keys: bool,
    /// Display private key information (disabled by default for security)
    pub print_private_keys: bool,
    /// Display Subject Alternative Names (DNS, IP, email, URI)
    pub print_sans: bool,
    /// Display certificate fingerprints (SHA-256, SHA-1, MD5)
    pub print_fingerprints: bool,
    /// Display certificate validity period (not before/after dates)
    pub print_expiry: bool,
    /// Display certificate serial number
    pub print_serial: bool,
    /// Display certificate issuer information
    pub print_issuer: bool,
    /// Display certificate subject information
    pub print_subject: bool,
    /// Display file paths where certificates were found
    pub print_paths: bool,
    /// Display line and column numbers for certificate locations in files
    pub print_line_and_col: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            print_public_keys: true,
            print_private_keys: false,
            print_sans: true,
            print_fingerprints: true,
            print_expiry: true,
            print_serial: true,
            print_issuer: true,
            print_subject: true,
            print_paths: true,
            print_line_and_col: true,
        }
    }
}

/// Output format for certificate display.
///
/// Determines how certificate information is rendered to the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Machine-readable JSON format for programmatic consumption
    Json,
    /// Human-readable text format with colors and formatting
    Text,
    /// PEM-encoded certificate format
    Pem,
}
