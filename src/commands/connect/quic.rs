use std::ffi::CString;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use boring::ssl::{SslContextBuilder, SslMethod, SslVerifyMode};
use boring::x509::X509;
use color_eyre::eyre::eyre;
use tokio::sync::oneshot;
use tokio_quiche::quic::{ConnectionHook, HandshakeInfo, QuicheConnection};
use tokio_quiche::settings::{CertificateKind, Hooks, QuicSettings, TlsCertificatePaths};
use tokio_quiche::socket::Socket;
use tokio_quiche::{ApplicationOverQuic, ConnectionParams, QuicResult};

use crate::components::connection::{print_tls_connection_with_certs, ConnectionWithCerts};
use crate::connection::{Connection, Time, Transport};
use crate::x509::SimpleCert;

use crate::commands::Format;

use super::{parse_host, Connect};

pub(super) async fn run(cmd: &Connect, format: Format) -> color_eyre::Result<()> {
    let dns_start = Instant::now();
    let (hostname, addr) = parse_host(&cmd.host);
    let time_dns = dns_start.elapsed();

    let handshake_start = Instant::now();
    let udp = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    udp.connect(addr).await?;
    let socket = Socket::try_from(udp).map_err(|e| eyre!("building QUIC socket: {e}"))?;

    let mut settings = QuicSettings::default();
    settings.handshake_timeout = Some(Duration::from_secs(10));

    // The hook only fires when `tls_cert` is `Some`, so pass placeholder paths.
    let hook: Arc<dyn ConnectionHook + Send + Sync> = Arc::new(TlsHook {
        curves: cmd.curves.clone(),
    });
    let hooks = Hooks {
        connection_hook: Some(hook),
    };
    let placeholder_cert = TlsCertificatePaths {
        cert: "",
        private_key: "",
        kind: CertificateKind::X509,
    };
    let params = ConnectionParams::new_client(settings, Some(placeholder_cert), hooks);

    let (tx, rx) = oneshot::channel();
    let app = InspectApp {
        tx: Some(tx),
        want_chain: cmd.chain,
        no_cert: cmd.no_cert,
        time_dns,
        handshake_start,
        buf: vec![0u8; 64 * 1024],
    };

    // Hold the handle so the connection stays up until the handshake completes.
    let _quic_conn = tokio_quiche::quic::connect_with_config(socket, Some(&hostname), &params, app)
        .await
        .map_err(|e| eyre!("QUIC connection to {hostname} failed: {e}"))?;

    let connection = rx.await.map_err(|_| {
        eyre!("QUIC handshake to {hostname} did not complete; the server may not support HTTP/3 (ALPN h3)")
    })?;

    print_tls_connection_with_certs(connection, format)
}

/// quiche bypasses the boring fork's per-connection curve setup, so mirror its
/// client list on the context to offer the same PQC hybrids as the TCP path.
const PQC_CLIENT_CURVES: &str =
    "X25519:P-256:P-384:P-521:X25519MLKEM768:X25519Kyber768Draft00:P256Kyber768Draft00";

struct TlsHook {
    curves: Option<String>,
}

impl ConnectionHook for TlsHook {
    fn create_custom_ssl_context_builder(
        &self,
        _settings: TlsCertificatePaths<'_>,
    ) -> Option<SslContextBuilder> {
        let mut builder = SslContextBuilder::new(SslMethod::tls_client()).ok()?;
        builder.set_default_verify_paths().ok()?;
        builder.set_verify(SslVerifyMode::NONE);

        // `set_curves_list` is compiled out under the fork's `kx-safe-default`
        // feature, so set them on the context directly via FFI.
        let curves = self.curves.as_deref().unwrap_or(PQC_CLIENT_CURVES);
        let curves = CString::new(curves).ok()?;
        // SAFETY: `builder` owns a live `SSL_CTX` and `curves` is a valid,
        // NUL-terminated C string that outlives the call.
        let rc = unsafe { boring_sys::SSL_CTX_set1_curves_list(builder.as_ptr(), curves.as_ptr()) };
        if rc != 1 {
            return None;
        }

        Some(builder)
    }
}

struct InspectApp {
    tx: Option<oneshot::Sender<ConnectionWithCerts>>,
    want_chain: bool,
    no_cert: bool,
    time_dns: Duration,
    handshake_start: Instant,
    buf: Vec<u8>,
}

impl ApplicationOverQuic for InspectApp {
    fn on_conn_established(
        &mut self,
        qconn: &mut QuicheConnection,
        _handshake_info: &HandshakeInfo,
    ) -> QuicResult<()> {
        // Copy the DER certs before borrowing `qconn` mutably for the SslRef.
        let der_chain: Vec<Vec<u8>> = if self.want_chain {
            qconn
                .peer_cert_chain()
                .map(|chain| chain.iter().map(|der| der.to_vec()).collect())
                .unwrap_or_default()
        } else {
            qconn
                .peer_cert()
                .map(|der| vec![der.to_vec()])
                .unwrap_or_default()
        };

        let time = Time {
            dns: self.time_dns,
            connect: None,
            tls: self.handshake_start.elapsed(),
        };

        let ssl = qconn.as_mut();
        let verify_result = ssl.verify_result();
        let tls = Connection::from((Transport::QUIC, time, &*ssl));

        let mut certs: Vec<SimpleCert> = der_chain
            .iter()
            .filter_map(|der| X509::from_der(der).ok())
            .map(SimpleCert::from)
            .collect();
        if let Some(cert) = certs.first_mut() {
            cert.apply_verify_result(verify_result);
        }
        if self.no_cert {
            certs.clear();
        }

        if let Some(tx) = self.tx.take() {
            let _ = tx.send(ConnectionWithCerts { tls, certs });
        }

        Ok(())
    }

    fn should_act(&self) -> bool {
        false
    }

    fn buffer(&mut self) -> &mut [u8] {
        self.buf.as_mut_slice()
    }

    fn wait_for_data(
        &mut self,
        _qconn: &mut QuicheConnection,
    ) -> impl Future<Output = QuicResult<()>> + Send {
        std::future::pending()
    }

    fn process_reads(&mut self, _qconn: &mut QuicheConnection) -> QuicResult<()> {
        Ok(())
    }

    fn process_writes(&mut self, _qconn: &mut QuicheConnection) -> QuicResult<()> {
        Ok(())
    }
}
