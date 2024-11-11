#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ChainId {
    id: u64,
    version: u64,
}

impl ChainId {
    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn new(id: u64) -> Self {
        //TODO support upgrade. currently follow the ethereum-elc-
        ChainId { id, version: 0 }
    }

    pub fn version(&self) -> u64 {
        self.version
    }
}
