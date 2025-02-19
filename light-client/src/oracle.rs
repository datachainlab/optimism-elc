use crate::errors::Error;
use crate::errors::Error::UnexpectedPreimageKeySize;
use alloc::boxed::Box;
use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloy_eips::eip4844::{
     BYTES_PER_COMMITMENT, FIELD_ELEMENTS_PER_BLOB,
};
use alloy_primitives::{keccak256, B256, U256};
use hashbrown::{HashMap, HashSet};
use kona_preimage::errors::{PreimageOracleError, PreimageOracleResult};
use kona_preimage::{HintWriterClient, PreimageKey, PreimageKeyType, PreimageOracleClient};
use kona_proof::FlushableCache;
use optimism_derivation::types::Preimage;
use optimism_derivation::POSITION_FIELD_ELEMENT;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug)]
pub struct MemoryOracleClient {
    /// Avoid deepcopy by clone operation because the preimage size is so big.
    preimages: Arc<HashMap<PreimageKey, Vec<u8>>>,
}

impl FlushableCache for MemoryOracleClient {
    fn flush(&self) {}
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
        Ok(())
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

            // Ensure hash type preimage is valid
            match preimage_key.key_type() {
                PreimageKeyType::Keccak256 => {
                    verify_keccak256_preimage(&preimage_key, &preimage.data)?
                }
                PreimageKeyType::Sha256 => verify_sha256_preimage(&preimage_key, &preimage.data)?,
                PreimageKeyType::Precompile => {
                    // Precomiles is needless because rerun the contract in derivation.
                    continue;
                }
                _ => {}
            }

            inner.insert(preimage_key, preimage.data);
        }

        let mut kzg_cache = HashSet::<Vec<u8>>::new();
        // Ensure blob and precomile preimage is value
        for (key, data) in inner.iter() {
            if key.key_type() == PreimageKeyType::Blob {
                verify_blob_preimage(key, data, &inner, &mut kzg_cache)?
            }
        }
        Ok(Self {
            preimages: Arc::new(inner),
        })
    }
}

fn get_data_by_hash_key<'a>(
    key: &PreimageKey,
    preimages: &'a HashMap<PreimageKey, Vec<u8>>,
) -> Result<&'a [u8], Error> {
    let raw_key = B256::from(*key).0;
    let hash_key = PreimageKey::new(raw_key, PreimageKeyType::Keccak256);
    let data = preimages
        .get(&hash_key)
        .ok_or(Error::NoPreimageKeyFound { key: hash_key })?;
    Ok(data)
}

fn get_data_by_blob_key<'a>(
    blob_key: &[u8],
    preimages: &'a HashMap<PreimageKey, Vec<u8>>,
) -> Result<&'a [u8], Error> {
    let blob_key_hash = keccak256(blob_key);
    let blob = preimages
        .get(&PreimageKey::new(*blob_key_hash, PreimageKeyType::Blob))
        .ok_or(Error::NoPreimageKeyFound {
            key: PreimageKey::new(*blob_key_hash, PreimageKeyType::Blob),
        })?;
    Ok(blob)
}

fn verify_sha256_preimage(key: &PreimageKey, data: &[u8]) -> Result<(), Error> {
    let value_hash: [u8; 32] = Sha256::digest(data).into();
    let value_data = &value_hash[1..];
    let value_data = U256::from_be_slice(value_data);
    let key_data = key.key_value();
    if value_data != key_data {
        return Err(Error::UnexpectedPreimageValue {
            key: *key,
            value: data.to_vec(),
        });
    }
    Ok(())
}
fn verify_keccak256_preimage(key: &PreimageKey, data: &[u8]) -> Result<(), Error> {
    let value_data = &keccak256(data).0[1..];
    let value_data = U256::from_be_slice(value_data);
    let key_data = key.key_value();
    if value_data != key_data {
        return Err(Error::UnexpectedPreimageValue {
            key: *key,
            value: data.to_vec(),
        });
    }
    Ok(())
}

fn verify_blob_preimage(
    key: &PreimageKey,
    data: &[u8],
    preimages: &HashMap<PreimageKey, Vec<u8>>,
    kzg_cache: &mut HashSet<Vec<u8>>,
) -> Result<(), Error> {
    let blob_key = get_data_by_hash_key(key, preimages)
        .map_err(|e| Error::NoPreimageKeyFoundInVerifyBlob(Box::new(e)))?;
    let kzg_commitment = &blob_key[..BYTES_PER_COMMITMENT];
    if kzg_cache.contains(kzg_commitment) {
        return Ok(());
    }
    let index_bytes: [u8; 8] = blob_key[POSITION_FIELD_ELEMENT..]
        .try_into()
        .map_err(Error::UnexpectedBlobFieldIndex)?;
    let field_element_index = u64::from_be_bytes(index_bytes);

    let blob_key = &mut blob_key.to_vec();
    // Require kzg_proof data to verify all the blob index
    let kzg_proof = if field_element_index == FIELD_ELEMENTS_PER_BLOB {
        data
    } else {
        // Get by 4096 index
        blob_key[POSITION_FIELD_ELEMENT..]
            .copy_from_slice((FIELD_ELEMENTS_PER_BLOB).to_be_bytes().as_ref());
        get_data_by_blob_key(blob_key, preimages)?
    };

    // Populate blob sidecar
    let mut blob = [0u8; kzg_rs::BYTES_PER_BLOB];
    for i in 0..FIELD_ELEMENTS_PER_BLOB {
        blob_key[POSITION_FIELD_ELEMENT..].copy_from_slice(i.to_be_bytes().as_ref());
        let sidecar_blob = get_data_by_blob_key(blob_key, preimages)?;
        blob[(i as usize) << 5..(i as usize + 1) << 5].copy_from_slice(sidecar_blob);
    }
    let kzg_blob = kzg_rs::Blob::from_slice(&blob) .map_err(Error::UnexpectedKZGBlob)?;

    // Ensure valida blob
    let settings = kzg_rs::get_kzg_settings();
    let result = kzg_rs::kzg_proof::KzgProof::verify_blob_kzg_proof(
        kzg_blob,
        &kzg_rs::Bytes48::from_slice(kzg_commitment).map_err(Error::UnexpectedKZGCommitment)?,
        &kzg_rs::Bytes48::from_slice(kzg_proof).map_err(Error::UnexpectedKZGProof)?,
        &settings
    ).map_err(Error::UnexpectedPreimageBlob)?;
    if !result {
        return Err(Error::UnexpectedPreimageBlobResult(key.clone()));
    }
    kzg_cache.insert(kzg_commitment.to_vec());

    Ok(())
}

#[cfg(test)]
mod test {
    use crate::oracle::MemoryOracleClient;
    use alloc::format;
    use maili_genesis::RollupConfig;
    use optimism_derivation::derivation::Derivation;
    use optimism_derivation::types::Preimages;
    use prost::Message;

    extern crate std;

    const TEST_DIR: &str = "../testdata/oracle";

    #[test]
    pub fn test_try_from() {
        let value = std::fs::read(format!("{TEST_DIR}/preimage.bin")).unwrap();
        let preimages = Preimages::decode(value.as_slice()).unwrap();
        let oracle = MemoryOracleClient::try_from(preimages.preimages).unwrap();
    }

    #[test]
    pub fn test_derivation() {
        let value = std::fs::read(format!("{TEST_DIR}/preimage.bin")).unwrap();
        let preimages = Preimages::decode(value.as_slice()).unwrap();
        let oracle = MemoryOracleClient::try_from(preimages.preimages).unwrap();

        let derivation = std::fs::read(format!("{TEST_DIR}/derivation.json")).unwrap();
        let derivation: Derivation = serde_json::from_slice(&derivation).unwrap();

        let rollup_config = std::fs::read(format!("{TEST_DIR}/rollup_config.json")).unwrap();
        let rollup_config: RollupConfig = serde_json::from_slice(&rollup_config).unwrap();

        derivation
            .verify(0, &rollup_config, oracle.clone())
            .unwrap();
    }
}
