use std::net::{SocketAddr, ToSocketAddrs};

use boring::ssl::{SslConnector, SslMethod, SslVerifyMode};
use clap::Parser;
use url::Url;

use crate::{args::print_certs, simple_cert::SimpleCert};

/// Connect to the given host and print information about the TLS connection.
/// Supports both TCP/TLS and QUIC.
#[derive(Default, Clone, Debug, Parser)]
pub struct Connect {
    /// The host to connect to. Can be a hostname, IP address or URL.
    host: String,
    /// Outputs the certificate chain.
    #[arg(long)]
    chain: bool,
    /// Output the results as JSON. Defaults to true if stdout is not a TTY.
    #[arg(long, conflicts_with = "text")]
    json: bool,
    /// Output the results as human-readable text. Defaults to true if stdout is
    /// a TTY.
    #[arg(long)]
    text: bool,
}

impl Connect {
    pub async fn run(self) -> color_eyre::Result<()> {
        let (hostname, addr) = parse_host(&self.host);
        let stream = tokio::net::TcpStream::connect(addr).await?;

        let mut connector_builder = SslConnector::builder(SslMethod::tls_client())?;
        connector_builder.set_verify(SslVerifyMode::NONE);
        let connector = connector_builder.build();

        // handle connection failure and print error to user:
        let tls = tokio_boring::connect(connector.configure()?, &hostname, stream).await?;

        let certs = if self.chain {
            let chain = tls.ssl().peer_cert_chain().unwrap();
            chain
                .into_iter()
                .map(ToOwned::to_owned)
                .map(SimpleCert::from)
                .collect()
        } else {
            vec![SimpleCert::from(tls.ssl().peer_certificate().unwrap())]
        };

        print_certs(certs, self.text, self.json)?;

        Ok(())
    }
}

/// Parse the host string into a hostname and SocketAddr.
fn parse_host(host: &str) -> (String, SocketAddr) {
    println!("host: {}", host);

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
