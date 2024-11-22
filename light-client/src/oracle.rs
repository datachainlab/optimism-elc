use crate::errors::Error;
use crate::errors::Error::InvalidPreimageKeySize;
use alloc::format;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloy_primitives::keccak256;
use hashbrown::HashMap;
use kona_preimage::errors::{PreimageOracleError, PreimageOracleResult};
use kona_preimage::{HintWriterClient, PreimageKey, PreimageKeyType, PreimageOracleClient};
use optimism_ibc_proto::ibc::lightclients::optimism::v1::Preimage;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug)]
pub struct MemoryOracleClient {
    /// Avoid deepcopy by clone operation because the preimage size is so big.
    preimages: Arc<HashMap<PreimageKey, Vec<u8>>>,
}

impl MemoryOracleClient {
    pub fn new(preimages: HashMap<PreimageKey, Vec<u8>>) -> Self {
        Self {
            preimages: Arc::new(preimages),
        }
    }
}

impl PreimageOracleClient for MemoryOracleClient {
    async fn get(&self, key: PreimageKey) -> PreimageOracleResult<Vec<u8>> {
        if let Some(value) = self.preimages.get(&key) {
            Ok(value.clone())
        } else {
            Err(PreimageOracleError::Other(format!(
                "key not found: {:?}",
                key
            )))
        }
    }

    async fn get_exact(&self, key: PreimageKey, buf: &mut [u8]) -> PreimageOracleResult<()> {
        if let Some(value) = self.preimages.get(&key) {
            buf.copy_from_slice(value.as_slice());
            Ok(())
        } else {
            Err(PreimageOracleError::Other(format!(
                "key not found: {:?}",
                key
            )))
        }
    }
}

impl HintWriterClient for MemoryOracleClient {
    async fn write(&self, hint: &str) -> PreimageOracleResult<()> {
        Err(PreimageOracleError::Other(
            "unsupported operation".to_string(),
        ))
    }
}

impl TryFrom<Vec<Preimage>> for MemoryOracleClient {
    type Error = Error;

    fn try_from(value: Vec<Preimage>) -> Result<Self, Self::Error> {
        let mut inner = HashMap::with_capacity(value.len());
        for preimage in value {
            let key: [u8; 32] = preimage
                .key
                .try_into()
                .map_err(|v: Vec<u8>| InvalidPreimageKeySize(v.len()))?;
            //TODO verify the key is derived from the value
            inner.insert(PreimageKey::try_from(key)?, preimage.value);
        }
        Ok(Self {
            preimages: Arc::new(inner),
        })
    }
}

fn verify_preimage(key: &PreimageKey, data: &[u8]) -> Result<(), Error> {
    match key.key_type() {
        PreimageKeyType::Local => {
            // unused
            Ok(())
        }
        PreimageKeyType::GlobalGeneric => Err(Error::UnexpectedGlobalGlobalGeneric(key.clone())),
        PreimageKeyType::Keccak256 => {
            let value_data = &keccak256(data).0[1..];
            let key_data = key.key_value().as_le_slice();
            if value_data != key_data {
                Err(Error::InvalidPreimageValue {
                    key: key.clone(),
                    value: data.to_vec(),
                })
            } else {
                Ok(())
            }
        }
        PreimageKeyType::Sha256 => {
            let value_hash: [u8; 32] = Sha256::digest(data).into();
            let value_data = &value_hash[1..];
            let key_data = key.key_value().as_le_slice();
            if value_data != key_data {
                Err(Error::InvalidPreimageValue {
                    key: key.clone(),
                    value: data.to_vec(),
                })
            } else {
                Ok(())
            }
        }
        _ => {
            //TODO
            // Verify Blob and Precompile
            unreachable!("TODO")
        }
    }
}
