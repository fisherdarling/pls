use boring::nid::Nid as BoringNid;
use serde::Serialize;

#[derive(Clone, Serialize)]
pub struct Nid(i32);

impl std::fmt::Debug for Nid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Nid")
            .field("raw", &self.0)
            .field("long_name", &self.long_name())
            .field("short_name", &self.short_name())
            .finish()
    }
}

impl Nid {
    pub fn from_boring(nid: BoringNid) -> Self {
        Self(nid.as_raw())
    }

    pub fn to_boring(&self) -> BoringNid {
        BoringNid::from_raw(self.0)
    }

    pub fn short_name(&self) -> &'static str {
        self.to_boring().short_name().unwrap_or("UnknownNid")
    }

    pub fn long_name(&self) -> &'static str {
        self.to_boring().long_name().unwrap_or("UnknownNid")
    }
}
