use std::net::{SocketAddr, ToSocketAddrs};

use boring::ssl::SslContextBuilder;
use clap::Parser;
use color_eyre::eyre::Context;
use url::Url;

use super::{CommandExt, Format};

mod quic;
mod tcp;

pub(crate) const DEFAULT_CURVES: &str =
    "X25519MLKEM768:X25519Kyber768Draft00:P256Kyber768Draft00:X25519:P-256:P-384:P-521";

pub(crate) const PQC_CURVES: &str = "X25519MLKEM768:X25519Kyber768Draft00:P256Kyber768Draft00";

/// Set the curve/group list on a [`SslContextBuilder`]. If `curves` is `None`,
/// the [`DEFAULT_CURVES`] are supplied.
pub(crate) fn set_curves(
    builder: &mut SslContextBuilder,
    curves: Option<&str>,
) -> color_eyre::Result<()> {
    let curves = curves.unwrap_or(DEFAULT_CURVES);
    builder
        .set_curves_list(curves)
        .with_context(|| format!("Setting curve list to: {curves:?}"))
}

/// Connect to the given host and print information about the TLS connection.
/// Supports both TCP/TLS and QUIC.
#[derive(Default, Clone, Debug, Parser)]
pub struct Connect {
    /// The host to connect to. Can be a hostname, IP address or URL.
    host: String,

    /// Outputs the certificate chain.
    #[arg(long)]
    chain: bool,

    /// Do not print out any certificates.
    #[arg(long)]
    no_cert: bool,

    /// [NOT YET IMPLEMENTED] Use RPK (Raw Public Key) for certificate validation rather than WebPKI
    /// (x509).
    #[arg(long)]
    rpk: bool,

    /// The curves to use when connecting to the server. Curves must be `:`
    /// separated. Defaults to a PQC-preferring.
    // todo: combine the curves for the user. Users should be able to input a simple list.
    #[arg(long)]
    curves: Option<String>,

    /// Offer only post-quantum (PQC) curves, dropping classical fallbacks.
    #[arg(long, conflicts_with = "curves")]
    pqc: bool,

    /// Connect over QUIC (HTTP/3, ALPN `h3`) instead of TCP+TLS.
    #[arg(long, conflicts_with = "rpk")]
    quic: bool,
}

impl Connect {
    /// The curve list to offer: `PQC_CURVES` when `--pqc` is set, else the
    /// user's `--curves` (or `None` to fall back to `DEFAULT_CURVES`).
    pub(crate) fn curves(&self) -> Option<&str> {
        if self.pqc {
            Some(PQC_CURVES)
        } else {
            self.curves.as_deref()
        }
    }
}

impl CommandExt for Connect {
    async fn run(self, format: Format) -> color_eyre::Result<()> {
        if self.quic {
            quic::run(&self, format).await
        } else {
            tcp::run(&self, format).await
        }
    }
}

/// Parse the host string into a hostname and SocketAddr.
pub(crate) fn parse_host(host: &str) -> (String, SocketAddr) {
    if let Ok(addr) = host.parse::<SocketAddr>() {
        // If the host is already a valid IP address, return it as-is
        return (addr.ip().to_string(), addr);
    }

    if let Ok(url) = host.parse::<Url>() {
        // If the host is a valid URL, extract the host and port
        // todo: handle errors here and different ports:

        // `cloudflare.com:443` parses as a url with no host and a scheme of
        // `cloudflare.com`. This check is to ensure that the host exists
        if url.host().is_some() {
            return (
                url.host_str().unwrap().to_string(),
                url.socket_addrs(|| Some(443)).unwrap()[0],
            );
        }
    }

    // If the host is not a valid IP address or URL, assume it is a hostname
    let (hostname, port) = if let Some(port) = host.split(':').nth(1) {
        (
            host.split(':').next().unwrap(),
            port.parse::<u16>().unwrap(), // todo: handle parse error
        )
    } else {
        (host, 443)
    };

    // Resolve the hostname to an IP address
    // todo: handle errors here
    (
        hostname.to_string(),
        (hostname, port).to_socket_addrs().unwrap().next().unwrap(),
    )
}
