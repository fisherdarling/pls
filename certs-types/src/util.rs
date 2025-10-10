use bytes::Bytes;
use serde::{Deserialize, Serialize, Serializer};

pub struct HexDebug<T>(pub T);

impl<T> std::fmt::Debug for HexDebug<T>
where
    T: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0.as_ref() {
            write!(f, "{:02x}", byte)?;
        }

        Ok(())
    }
}

#[derive(Clone, PartialEq, Hash, Eq, Serialize, Deserialize)]
pub struct Hex(#[serde(serialize_with = "serialize_hex")] Bytes);

impl Hex {
    pub fn new(bytes: Bytes) -> Self {
        Self(bytes)
    }

    pub fn from_hex(data: &str) -> anyhow::Result<Self> {
        Ok(Self(decode_hex(data)?))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl std::fmt::Debug for Hex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", &HexDebug(&self.0))
    }
}

impl From<Hex> for Bytes {
    fn from(hex: Hex) -> Self {
        hex.0
    }
}

impl<T: AsRef<[u8]>> From<T> for Hex {
    fn from(bytes: T) -> Self {
        Self(Bytes::copy_from_slice(bytes.as_ref()))
    }
}

fn decode_hex(data: &str) -> anyhow::Result<Bytes> {
    let mut bytes = Vec::new();

    if data.len() % 2 != 0 {
        anyhow::bail!("invalid hex string");
    }

    let mut hex_chunks = data.as_bytes().chunks_exact(2);
    while let Some(chunk) = hex_chunks.next() {
        let [a, b] = [chunk[0], chunk[1]];
        let byte = u8::from_str_radix(std::str::from_utf8(&[a, b])?, 16)?;
        bytes.push(byte);
    }

    Ok(Bytes::from(bytes))
}

pub fn serialize_hex<T, S>(t: &T, s: S) -> Result<S::Ok, S::Error>
where
    T: std::fmt::Debug,
    T: AsRef<[u8]>,
    S: Serializer,
{
    // avoids allocation via `format_args!`
    s.collect_str(&format!("{:?}", HexDebug(t)))
}
