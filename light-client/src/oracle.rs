use alloc::format;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use hashbrown::HashMap;
use kona_preimage::{HintWriterClient, PreimageKey, PreimageOracleClient};
use kona_preimage::errors::{PreimageOracleError, PreimageOracleResult};

#[derive(Clone)]
pub struct MemoryOracleClient {
    /// Avoid deepcopy by clone operation because the preimage size is so big.
    preimages: Arc<HashMap<PreimageKey, Vec<u8>>>
}

impl MemoryOracleClient {
    pub fn new(preimages: HashMap<PreimageKey, Vec<u8>>) -> Self {
        Self {
            preimages: Arc::new(preimages)
        }
    }
}

impl PreimageOracleClient for MemoryOracleClient {
    async fn get(&self, key: PreimageKey) -> PreimageOracleResult<Vec<u8>> {
        if let Some(value) = self.preimages.get(&key) {
            Ok(value.clone())
        }else {
            Err(PreimageOracleError::Other(format!("key not found: {:?}", key)))
        }
    }

    async fn get_exact(&self, key: PreimageKey, buf: &mut [u8]) -> PreimageOracleResult<()> {
        if let Some(value) = self.preimages.get(&key) {
            buf.copy_from_slice(value.as_slice());
            Ok(())
        } else {
            Err(PreimageOracleError::Other(format!("key not found: {:?}", key)))
        }
    }
}


impl HintWriterClient for MemoryOracleClient {
    async fn write(&self, hint: &str) -> PreimageOracleResult<()> {
        Err(PreimageOracleError::Other("unsupported operation".to_string()))
    }
}