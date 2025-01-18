use std::time::Duration;

use boring::ssl::SslRef;
use serde::Serialize;

#[derive(Debug, Default, Clone, Serialize)]
pub struct Connection {
    #[serde(serialize_with = "serialize_duration")]
    pub time_connect: Duration,
    #[serde(serialize_with = "serialize_duration")]
    pub time_tls: Duration,
    pub curve: String,
    pub version: String,
    pub transport: Transport,
}

#[derive(Debug, Default, Copy, Clone, Serialize)]
#[allow(clippy::upper_case_acronyms)]
pub enum Transport {
    #[default]
    TCP,
    #[allow(unused)]
    QUIC,
}

/// serialize a duration as a number in microseconds
fn serialize_duration<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_f64(duration.as_millis() as f64)
}

impl From<(Transport, Duration, Duration, &SslRef)> for Connection {
    fn from(
        (transport, time_connect, time_tls, ssl): (Transport, Duration, Duration, &SslRef),
    ) -> Self {
        Self {
            time_connect,
            time_tls,
            curve: ssl
                .curve()
                .and_then(|c| c.name())
                .unwrap_or_default()
                .to_string(),
            version: ssl.version_str().to_string(),
            transport,
        }
    }
}
