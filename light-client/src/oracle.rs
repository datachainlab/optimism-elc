use crate::errors::Error;
use crate::errors::Error::UnexpectedPreimageKeySize;
use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::{format};
use alloy_eips::eip4844::{BlobTransactionSidecarItem, Bytes48, FIELD_ELEMENTS_PER_BLOB};
use alloy_primitives::{keccak256, B256};
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
            let actual= get_data_by_hash_key(key, preimages)?;
            if !precompiles::verify(actual, data) {
                return Err(Error::UnexpectedPrecompiledValue {
                    key: key.clone(),
                    actual: actual.to_vec(),
                    expected: data.to_vec(),
                });
            }
            Ok(())
        }
        PreimageKeyType::Blob => {
            let blob_key = get_data_by_hash_key(key, preimages)?;
            let kzg_commitment = &blob_key[..48];
            let index_bytes :[u8; 8] = blob_key[72..].try_into().map_err(Error::UnexpectedBlobFieldIndex)?;
            let field_element_index = u64::from_be_bytes(index_bytes);
            //TODO cache by kzg_commitment

            let blob_key  = &mut blob_key.to_vec();
            // Require kzg_proof data to verify all the blob index
            let kzg_proof = if field_element_index == FIELD_ELEMENTS_PER_BLOB {
                data
            } else {
                blob_key[72..].copy_from_slice((FIELD_ELEMENTS_PER_BLOB).to_be_bytes().as_ref());
                get_data_by_blob_key(blob_key, preimages)?
            };

            // Populate blob sidecar
            let mut sidecar = BlobTransactionSidecarItem {
                kzg_commitment: Bytes48::try_from(kzg_commitment).map_err(Error::UnexpectedKZGCommitment)?,
                kzg_proof: Bytes48::try_from(kzg_proof).map_err(Error::UnexpectedKZGProof)?,
                ..Default::default()
            };
            for i in 0..FIELD_ELEMENTS_PER_BLOB {
                blob_key[72..].copy_from_slice(i.to_be_bytes().as_ref());
                let sidecar_blob = get_data_by_blob_key(blob_key, preimages)?;
                sidecar.blob[(i as usize) << 5..(i as usize + 1) << 5]
                    .copy_from_slice(sidecar_blob);
            }

            // Ensure valida blob
            sidecar
                .verify_blob_kzg_proof()
                .map_err(Error::UnexpectedPreimageBlob)?;
            Ok(())
        }
        _ => Ok(()),
    }
}

fn get_data_by_hash_key<'a>(key: &PreimageKey, preimages: &'a HashMap<PreimageKey, Vec<u8>>) -> Result<&'a [u8], Error> {
    let raw_key = B256::from(*key).0;
    let hash_key = PreimageKey::new(raw_key, PreimageKeyType::Keccak256);
    let data = preimages
        .get(&hash_key)
        .ok_or(Error::NoPreimageKeyFound{ key: hash_key })?;
    Ok(data)
}

fn get_data_by_blob_key<'a>(blob_key: &[u8], preimages: &'a HashMap<PreimageKey, Vec<u8>>) -> Result<&'a [u8], Error> {
    let blob_key_hash = keccak256(blob_key);
    let blob = preimages
        .get(&PreimageKey::new(*blob_key_hash, PreimageKeyType::Blob))
        .ok_or(Error::NoPreimageKeyFound {
            key: PreimageKey::new(*blob_key_hash, PreimageKeyType::Blob),
        })?;
    Ok(blob)
}