use bytes::Bytes;
use serde::{Deserialize, Serialize};

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
pub struct Hex(Bytes);

impl std::fmt::Debug for Hex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", &HexDebug(&self.0))
    }
}

impl Hex {
    pub fn new(bytes: Bytes) -> Self {
        Self(bytes)
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
