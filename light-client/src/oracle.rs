use alloc::format;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use hashbrown::HashMap;
use kona_preimage::{HintWriterClient, PreimageKey, PreimageOracleClient};
use kona_preimage::errors::{PreimageOracleError, PreimageOracleResult};
use optimism_ibc_proto::ibc::lightclients::ethereum::v1::Preimage;
use crate::errors::Error;
use crate::errors::Error::InvalidPreimageKeySize;

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

impl TryFrom<Vec<Preimage>> for MemoryOracleClient {
    type Error = Error;

    fn try_from(value: Vec<Preimage>) -> Result<Self, Self::Error> {
        let mut inner = HashMap::with_capacity(value.len());
        for preimage in value {
            let key : [u8; 32]= preimage.key.try_into().map_err(|v: Vec<u8>| InvalidPreimageKeySize(v.len()))?;
            //TODO verify the key is derived from the value
            inner.insert(PreimageKey::try_from(key)?, preimage.value);
        }
        Ok(Self {
            preimages: Arc::new(inner),
        })
    }
}