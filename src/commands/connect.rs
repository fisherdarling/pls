use std::{
    net::{SocketAddr, ToSocketAddrs},
    time::Instant,
};

use boring::ssl::{SslConnector, SslMethod, SslVerifyMode};
use clap::Parser;
use color_eyre::eyre::Context;
use url::Url;

use crate::{
    components::connection::{print_tls_connection_with_certs, ConnectionWithCerts},
    connection::{Connection, Time, Transport},
    x509::cert::SimpleCert,
};

use super::{CommandExt, Format};

/// Connect to the given host and print information about the TLS connection.
/// Supports both TCP/TLS and QUIC.
#[derive(Default, Clone, Debug, Parser)]
pub struct Connect {
    /// The host to connect to. Can be a hostname, IP address or URL.
    host: String,

    /// Outputs the certificate chain.
    #[arg(long)]
    chain: bool,

    /// Use RPK (Raw Public Key) for certificate validation rather than WebPKI
    /// (x509).
    #[arg(long)]
    rpk: bool,

    /// The curves to use when connecting to the server. Curves must be `:` separated.
    // todo: combine the curves for the user. Users should be able to input a simple list.
    #[arg(long)]
    curves: Option<String>,

    /// Force Post-Quantum Cryptography (PQC) ciphersuites. This enables
    /// `X25519MLKEM768` and `X25519Kyber768Draft00` ciphersuites.
    #[arg(long, conflicts_with = "curves")]
    pqc: bool,
}

impl CommandExt for Connect {
    async fn run(mut self, format: Format) -> color_eyre::Result<()> {
        let dns_start = Instant::now();
        let (hostname, addr) = parse_host(&self.host);
        let time_dns = dns_start.elapsed();

        let connect_start = Instant::now();
        let stream = tokio::net::TcpStream::connect(addr).await?;
        let time_connect = connect_start.elapsed();

        let mut connector_builder = if self.rpk {
            SslConnector::rpk_builder()?
        } else {
            SslConnector::builder(SslMethod::tls_client())?
        };

        if !self.rpk {
            connector_builder.set_verify(SslVerifyMode::NONE);
        }

        if self.pqc {
            self.curves = Some("X25519MLKEM768:X25519Kyber768Draft00".to_string());
        }
        if let Some(curve_list) = self.curves {
            connector_builder
                .set_curves_list(&curve_list)
                .with_context(|| format!("Setting curve list to: {curve_list:?}"))?;
        }

        let connector = connector_builder.build();

        // handle connection failure and print error to user:
        // todo(fisher): fix RPK connections. Are we required to set the raw public key?
        let tls_start = Instant::now();
        let tls = tokio_boring::connect(connector.configure()?, &hostname, stream).await?;
        let time_tls = tls_start.elapsed();

        let time = Time {
            dns: time_dns,
            connect: time_connect,
            tls: time_tls,
        };

        let tls_connection = Connection::from((Transport::TCP, time, tls.ssl()));
        if !self.rpk {
            let mut certs = if self.chain {
                let chain = tls.ssl().peer_cert_chain().unwrap();
                chain
                    .into_iter()
                    .map(ToOwned::to_owned)
                    .map(SimpleCert::from)
                    .collect()
            } else {
                vec![SimpleCert::from(tls.ssl().peer_certificate().unwrap())]
            };

            if let Some(cert) = certs.first_mut() {
                cert.apply_verify_result(tls.ssl().verify_result());
            }

            // todo: combine into a single function / output struct
            print_tls_connection_with_certs(
                ConnectionWithCerts {
                    tls: tls_connection,
                    certs,
                },
                format,
            )?;
        } else {
            println!("Connected to {}", hostname);
        }

        Ok(())
    }
}

/// Parse the host string into a hostname and SocketAddr.
fn parse_host(host: &str) -> (String, SocketAddr) {
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
