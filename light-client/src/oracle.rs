use crate::errors::Error;
use crate::errors::Error::UnexpectedPreimageKeySize;
use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::{format, vec};
use alloy_eips::eip4844::builder::Bytes48;
use alloy_eips::eip4844::{BlobTransactionSidecarItem, Bytes48, FIELD_ELEMENTS_PER_BLOB};
use alloy_primitives::{keccak256, Address, B256};
use hashbrown::HashMap;
use kona_preimage::errors::{PreimageOracleError, PreimageOracleResult};
use kona_preimage::{HintWriterClient, PreimageKey, PreimageKeyType, PreimageOracleClient};
use optimism_derivation::precompiles;
use optimism_ibc_proto::ibc::lightclients::optimism::v1::Preimage;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug)]
pub struct MemoryOracleClient {
    /// Avoid deepcopy by clone operation because the preimage size is so big.
    preimages: Arc<HashMap<PreimageKey, Vec<u8>>>,
}

#[async_trait::async_trait]
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

#[async_trait::async_trait]
impl HintWriterClient for MemoryOracleClient {
    async fn write(&self, _hint: &str) -> PreimageOracleResult<()> {
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
                .map_err(|v: Vec<u8>| UnexpectedPreimageKeySize(v.len()))?;
            let preimage_key = PreimageKey::try_from(key)
                .map_err(|e| Error::UnexpectedPreimageKey { source: e, key })?;

            verify_hash_preimage(&preimage_key, &preimage.value)?;

            inner.insert(preimage_key, preimage.value);
        }

        // Ensure preimage key and value match
        for (preimage_key, value) in inner.iter() {
            verify_precompile_and_blob_preimage(preimage_key, value, &inner)?;
        }
        Ok(Self {
            preimages: Arc::new(inner),
        })
    }
}
fn verify_hash_preimage(key: &PreimageKey, data: &[u8]) -> Result<(), Error> {
    match key.key_type() {
        PreimageKeyType::Keccak256 => {
            let value_data = &keccak256(data).0[1..];
            let key_data = key.key_value();
            let key_data = key_data.as_le_slice();
            if value_data != key_data {
                Err(Error::UnexpectedPreimageValue {
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
            let key_data = key.key_value();
            let key_data = key_data.as_le_slice();
            if value_data != key_data {
                Err(Error::UnexpectedPreimageValue {
                    key: key.clone(),
                    value: data.to_vec(),
                })
            } else {
                Ok(())
            }
        }
        _ => Ok(()),
    }
}

fn verify_precompile_and_blob_preimage(
    key: &PreimageKey,
    data: &[u8],
    preimages: &HashMap<PreimageKey, Vec<u8>>,
) -> Result<(), Error> {
    match key.key_type() {
        PreimageKeyType::Precompile => {
            let raw_key = B256::from(*key).0;
            let hash_code_key = PreimageKey::new(raw_key, PreimageKeyType::Keccak256);
            let hint_data = preimages
                .get(&hash_code_key)
                .ok_or(Error::NoPreimagePrecompiledCodeFound { key: hash_code_key })?;

            if !precompiles::verify(hint_data, data) {
                return Err(Error::UnexpectedPrecompiledValue {
                    key: key.clone(),
                    value: data.to_vec(),
                });
            }
            Ok(())
        }
        PreimageKeyType::Blob => {
            let raw_key = B256::from(*key).0;
            let blob_key_hash = PreimageKey::new(raw_key, PreimageKeyType::Keccak256);
            let blob_key_got = preimages
                .get(&blob_key_hash)
                .ok_or(Error::NoPreimageBlobFound { key: blob_key_hash })?;

            let blob_key = blob_key_got.clone();
            let kzg_commitment = blob_key_got[..48];
            //TODO cache by kzg_commitment

            let field_element_index = blob_key_got[72..];
            let field_element_index = u64::try_from_slice(&field_element_index)?;

            // Require kzg_proof data to verify all the blob index
            let kzg_proof = if field_element_index == FIELD_ELEMENTS_PER_BLOB {
                data
            } else {
                blob_key[72..].copy_from_slice((FIELD_ELEMENTS_PER_BLOB).to_be_bytes().as_ref());
                let blob_key_hash = keccak256(blob_key.as_ref());
                preimages
                    .get(&PreimageKey::new(*blob_key_hash, PreimageKeyType::Blob))
                    .ok_or(Error::NoPreimageBlobFound {
                        key: PreimageKey::new(*blob_key_hash, PreimageKeyType::Blob),
                    })?
            };

            let mut sidecar = BlobTransactionSidecarItem {
                index: 0,
                blob: Box::new(Default::default()),
                kzg_commitment: Bytes48::try_from(&kzg_commitment)?,
                kzg_proof: Bytes48::try_from(&kzg_proof)?,
            };
            for i in 0..FIELD_ELEMENTS_PER_BLOB {
                blob_key[72..].copy_from_slice(i.to_be_bytes().as_ref());
                let blob_key_hash = keccak256(blob_key.as_ref());
                let blob_key_hash = PreimageKey::new(*blob_key_hash, PreimageKeyType::Blob);
                let sidecar_blob = preimages
                    .get(&blob_key_hash)
                    .ok_or(Error::NoPreimageBlobFound { key: blob_key_hash })?;
                sidecar.blob[(i as usize) << 5..(i as usize + 1) << 5]
                    .copy_from_slice(sidecar_blob);
            }
            sidecar
                .verify_blob_kzg_proof()
                .map_err(Error::UnexpectedPreimageBlob)?;
            Ok(())
        }
        _ => Ok(()),
    }
}
