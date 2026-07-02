use std::time::Instant;

use boring::ssl::{SslConnector, SslMethod, SslVerifyMode};

use crate::commands::Format;
use crate::components::connection::{print_tls_connection_with_certs, ConnectionWithCerts};
use crate::connection::{Connection, Time, Transport};
use crate::x509::SimpleCert;

use super::{parse_host, Connect};

/// Connect to `cmd.host` over TCP, complete the TLS handshake, and print the
/// connection + certificate information.
pub(super) async fn run(cmd: &Connect, format: Format) -> color_eyre::Result<()> {
    let dns_start = Instant::now();
    let (hostname, addr) = parse_host(&cmd.host);
    let time_dns = dns_start.elapsed();

    let connect_start = Instant::now();
    let stream = tokio::net::TcpStream::connect(addr).await?;
    let time_connect = connect_start.elapsed();

    let mut connector_builder = if cmd.rpk {
        SslConnector::rpk_builder()?
    } else {
        SslConnector::builder(SslMethod::tls_client())?
    };

    if !cmd.rpk {
        connector_builder.set_verify(SslVerifyMode::NONE);
    }

    super::set_curves(&mut connector_builder, cmd.curves())?;

    let connector = connector_builder.build();

    // handle connection failure and print error to user:
    // todo(fisher): fix RPK connections. Are we required to set the raw public key?
    let tls_start = Instant::now();
    let tls = tokio_boring::connect(connector.configure()?, &hostname, stream).await?;
    let time_tls = tls_start.elapsed();

    let time = Time {
        dns: time_dns,
        connect: Some(time_connect),
        tls: time_tls,
    };

    let tls_connection = Connection::from((Transport::TCP, time, tls.ssl()));
    if !cmd.rpk {
        let mut certs = if cmd.chain {
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

        if cmd.no_cert {
            certs.clear();
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
