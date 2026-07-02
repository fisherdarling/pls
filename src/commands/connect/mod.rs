use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use boring::ssl::SslContextBuilder;
use clap::Parser;
use color_eyre::eyre::{eyre, Context};
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
pub(crate) fn parse_host(host: &str) -> color_eyre::Result<(String, SocketAddr)> {
    if let Ok(addr) = host.parse::<SocketAddr>() {
        // If the host is already a valid IP address, return it as-is
        tracing::debug!("parsed {host} as socket address");
        return Ok((addr.ip().to_string(), addr));
    }

    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = bare.parse::<IpAddr>() {
        tracing::debug!("parsed {host} as bare IP address");
        return Ok((ip.to_string(), SocketAddr::new(ip, 443)));
    }

    if let Ok(url) = host.parse::<Url>() {
        // If the host is a valid URL, extract the host and port

        // `cloudflare.com:443` parses as a url with no host and a scheme of
        // `cloudflare.com`. This check is to ensure that the host exists
        if url.host().is_some() {
            tracing::debug!("parsed {host} as URL");
            let addrs = url
                .socket_addrs(|| Some(443))
                .with_context(|| format!("resolving URL host {host:?}"))?;
            let addr = addrs
                .into_iter()
                .next()
                .ok_or_else(|| eyre!("URL host {host:?} resolved to no addresses"))?;
            // host_str() is Some whenever host() is Some (checked above).
            return Ok((url.host_str().unwrap().to_string(), addr));
        }
    }

    // If the host is not a valid IP address or URL, assume it is a hostname
    let (hostname, port) = if let Some((hostname, port)) = host.split_once(':') {
        let port = port
            .parse::<u16>()
            .with_context(|| format!("parsing port {port:?} in host {host:?}"))?;
        (hostname, port)
    } else {
        (host, 443)
    };

    // Resolve the hostname to an IP address
    tracing::debug!("parsed {host} as hostname:port ({hostname}:{port})");
    let addr = (hostname, port)
        .to_socket_addrs()
        .with_context(|| format!("resolving {hostname}:{port}"))?
        .next()
        .ok_or_else(|| eyre!("{hostname}:{port} resolved to no addresses"))?;
    Ok((hostname.to_string(), addr))
}

#[cfg(test)]
mod tests {
    use super::parse_host;

    #[test]
    fn parses_ipv6() {
        // Bare IPv6, default port.
        let (host, addr) = parse_host("::1").unwrap();
        assert_eq!(host, "::1");
        assert_eq!(addr.to_string(), "[::1]:443");

        // Bracketed IPv6, default port.
        let (_, addr) = parse_host("[2001:db8::1]").unwrap();
        assert_eq!(addr.to_string(), "[2001:db8::1]:443");

        // Bracketed IPv6 with explicit port.
        let (_, addr) = parse_host("[::1]:8443").unwrap();
        assert_eq!(addr.to_string(), "[::1]:8443");

        // IPv4 still works.
        let (_, addr) = parse_host("1.2.3.4:80").unwrap();
        assert_eq!(addr.to_string(), "1.2.3.4:80");
    }
}
