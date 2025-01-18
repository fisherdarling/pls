use std::{
    ops::{Div, Mul},
    time::Duration,
};

use boring::ssl::SslRef;
use serde::Serialize;

#[derive(Debug, Default, Clone, Serialize)]
pub struct Connection {
    pub curve: String,
    pub is_pqc: bool,
    pub version: String,
    pub transport: Transport,
    pub time: Time,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct Time {
    #[serde(serialize_with = "serialize_duration")]
    pub dns: Duration,
    #[serde(serialize_with = "serialize_duration")]
    pub connect: Duration,
    #[serde(serialize_with = "serialize_duration")]
    pub tls: Duration,
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
    serializer.serialize_f64(
        (duration.as_secs_f64() * 1_000.0)
            .mul(1_000.0)
            .round()
            .div(1_000.0),
    )
}

impl From<(Transport, Time, &SslRef)> for Connection {
    fn from((transport, time, ssl): (Transport, Time, &SslRef)) -> Self {
        let curve = ssl
            .curve()
            .and_then(|c| c.name())
            .unwrap_or_default()
            .to_string();

        // todo(fix): poor man's PQC check
        let is_pqc = curve.contains("Kyber") || curve.contains("MLKEM");

        Self {
            curve,
            is_pqc,
            version: ssl.version_str().to_string(),
            transport,
            time,
        }
    }
}
