use crate::errors::Error;
use crate::errors::Error::UnexpectedPreimageKeySize;
use crate::types::Preimage;
use crate::POSITION_FIELD_ELEMENT;
use alloc::boxed::Box;
use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloy_eips::eip4844::{BYTES_PER_COMMITMENT, FIELD_ELEMENTS_PER_BLOB};
use alloy_primitives::{keccak256, B256, U256};
use ark_ff::fields::PrimeField;
use ark_ff::BigInteger;
use hashbrown::{HashMap, HashSet};
use kona_preimage::errors::{PreimageOracleError, PreimageOracleResult};
use kona_preimage::{HintWriterClient, PreimageKey, PreimageKeyType, PreimageOracleClient};
use kona_proof::l1::ROOTS_OF_UNITY;
use kona_proof::FlushableCache;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Default)]
pub struct MemoryOracleClient {
    /// Avoid deepcopy by clone operation because the preimage size is so big.
    preimages: Arc<HashMap<PreimageKey, Vec<u8>>>,
}

impl MemoryOracleClient {
    pub fn len(&self) -> usize {
        self.preimages.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
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
impl HintWriterClient for NopeHintWriter {
    async fn write(&self, _hint: &str) -> PreimageOracleResult<()> {
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct NopeHintWriter;
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
                _ => {}
            }
            if inner.insert(preimage_key, preimage.data).is_some() {
                return Err(Error::UnexpectedDuplicatePreimageKey(preimage_key));
            }
        }

        // Ensure blob preimage is valid
        let mut kzg_cache = HashSet::<Vec<u8>>::new();
        for (key, data) in inner.iter() {
            if key.key_type() == PreimageKeyType::Blob {
                verify_blob_preimage(key, data, &inner, &mut kzg_cache)?
            } else if key.key_type() == PreimageKeyType::Precompile {
                verify_precompile(key, &inner)?
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
    let key = PreimageKey::new(*blob_key_hash, PreimageKeyType::Blob);
    let blob = preimages.get(&key).ok_or(Error::NoPreimageKeyFound {
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
        return Err(Error::UnexpectedSha256PreimageValue {
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
        return Err(Error::UnexpectedKeccak256PreimageValue {
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

    let blob_key = &mut blob_key.to_vec();
    // Populate blob sidecar
    let mut blob = [0u8; kzg_rs::BYTES_PER_BLOB];
    for i in 0..FIELD_ELEMENTS_PER_BLOB {
        let slice = &mut blob_key[BYTES_PER_COMMITMENT..];
        try_copy_slice(
            slice,
            ROOTS_OF_UNITY[i as usize]
                .into_bigint()
                .to_bytes_be()
                .as_ref(),
        )?;
        let sidecar_blob = get_data_by_blob_key(blob_key, preimages)?;
        blob[(i as usize) << 5..(i as usize + 1) << 5].copy_from_slice(sidecar_blob);
    }

    // Require kzg_proof data to verify all the blob index
    let kzg_proof = {
        let field_element_index: [u8; 8] = blob_key[POSITION_FIELD_ELEMENT..]
            .try_into()
            .map_err(Error::UnexpectedBlobFieldIndex)?;
        if u64::from_be_bytes(field_element_index) == FIELD_ELEMENTS_PER_BLOB {
            data
        } else {
            // Get by 4096 index
            let slice = &mut blob_key[POSITION_FIELD_ELEMENT..];
            try_copy_slice(slice, FIELD_ELEMENTS_PER_BLOB.to_be_bytes().as_ref())?;
            get_data_by_blob_key(blob_key, preimages).map_err(|e| {
                Error::NoPreimageDataFoundInVerifyBlob(blob_key.to_vec(), Box::new(e))
            })?
        }
    };
    // Ensure valida blob
    let kzg_blob = kzg_rs::Blob::from_slice(&blob).map_err(Error::UnexpectedKZGBlob)?;
    let settings = kzg_rs::get_kzg_settings();
    let result = kzg_rs::kzg_proof::KzgProof::verify_blob_kzg_proof(
        kzg_blob,
        &kzg_rs::Bytes48::from_slice(kzg_commitment).map_err(Error::UnexpectedKZGCommitment)?,
        &kzg_rs::Bytes48::from_slice(kzg_proof).map_err(Error::UnexpectedKZGProof)?,
        &settings,
    )
    .map_err(Error::UnexpectedPreimageBlob)?;
    if !result {
        return Err(Error::UnexpectedPreimageBlobResult(*key));
    }
    kzg_cache.insert(kzg_commitment.to_vec());

    Ok(())
}

fn verify_precompile(
    key: &PreimageKey,
    preimages: &HashMap<PreimageKey, Vec<u8>>,
) -> Result<(), Error> {
    get_data_by_hash_key(key, preimages)
        .map_err(|e| Error::NoPreimageKeyFoundInPrecompile(Box::new(e)))?;
    Ok(())
}

fn try_copy_slice(slice: &mut [u8], value: &[u8]) -> Result<(), Error> {
    if slice.len() == value.len() {
        slice.copy_from_slice(value);
        Ok(())
    } else {
        Err(Error::UnexpectedSliceLength(slice.len(), value.len()))
    }
}

#[cfg(test)]
mod test {
    use crate::errors::Error;
    use crate::oracle::{try_copy_slice, verify_blob_preimage, MemoryOracleClient};
    use crate::types::Preimage;
    use crate::POSITION_FIELD_ELEMENT;
    use alloc::vec;
    use alloy_eips::eip4844::{BYTES_PER_COMMITMENT, FIELD_ELEMENTS_PER_BLOB};
    use alloy_primitives::keccak256;
    use alloy_primitives::map::HashMap;
    use ark_ff::{BigInteger, PrimeField};
    use hashbrown::HashSet;
    use kona_preimage::{PreimageKey, PreimageKeyType};
    use kona_proof::l1::ROOTS_OF_UNITY;
    use sha2::{Digest, Sha256};

    #[test]
    fn test_try_from_key_error() {
        let preimage = vec![Preimage {
            key: vec![0u8; 10],
            data: vec![0u8; 10],
        }];
        let err = MemoryOracleClient::try_from(preimage).unwrap_err();
        match err {
            Error::UnexpectedPreimageKeySize(_) => {}
            _ => panic!("Unexpected error, got: {:?}", err),
        }
    }

    #[test]
    fn test_try_from_duplicate_preimage_error() {
        let value = vec![0u8; 10];
        let key: [u8; 32] = Sha256::digest(&value).try_into().unwrap();
        let preimage = vec![
            Preimage::new(
                PreimageKey::new(key, PreimageKeyType::Sha256),
                value.clone(),
            ),
            Preimage::new(PreimageKey::new(key, PreimageKeyType::Sha256), value),
        ];
        let err = MemoryOracleClient::try_from(preimage).unwrap_err();
        match err {
            Error::UnexpectedDuplicatePreimageKey(_) => {}
            _ => panic!("Unexpected error, got: {:?}", err),
        }
    }

    #[test]
    fn test_try_from_sha256_error() {
        let preimage = vec![Preimage::new(
            PreimageKey::new([0u8; 32], PreimageKeyType::Sha256),
            vec![0u8; 10],
        )];
        let err = MemoryOracleClient::try_from(preimage).unwrap_err();
        match err {
            Error::UnexpectedSha256PreimageValue { value: _, key: _ } => {}
            _ => panic!("Unexpected error, got: {:?}", err),
        }
    }

    #[test]
    fn test_try_from_keccak256_error() {
        let preimage = vec![Preimage::new(
            PreimageKey::new([0u8; 32], PreimageKeyType::Keccak256),
            vec![0u8; 10],
        )];
        let err = MemoryOracleClient::try_from(preimage).unwrap_err();
        match err {
            Error::UnexpectedKeccak256PreimageValue { value: _, key: _ } => {}
            _ => panic!("Unexpected error, got: {:?}", err),
        }
    }

    #[test]
    fn test_try_from_precompile_error() {
        let preimage = vec![Preimage::new(
            PreimageKey::new([0u8; 32], PreimageKeyType::Precompile),
            vec![0u8; 10],
        )];
        let err = MemoryOracleClient::try_from(preimage).unwrap_err();
        match err {
            Error::NoPreimageKeyFoundInPrecompile(_) => {}
            _ => panic!("Unexpected error, got: {:?}", err),
        }
    }

    #[test]
    fn test_try_from_blob_no_key_error() {
        let preimage = vec![Preimage::new(
            PreimageKey::new([0u8; 32], PreimageKeyType::Blob),
            vec![0u8; 10],
        )];
        let err = MemoryOracleClient::try_from(preimage).unwrap_err();
        match err {
            Error::NoPreimageKeyFoundInVerifyBlob(_) => {}
            _ => panic!("Unexpected error, got: {:?}", err),
        }
    }

    #[test]
    fn test_try_from_blob_no_kzg_proof_error() {
        let mut blob_key = [0u8; POSITION_FIELD_ELEMENT + 8];
        let mut preimages = HashMap::new();

        for i in 0..FIELD_ELEMENTS_PER_BLOB {
            blob_key[BYTES_PER_COMMITMENT..].copy_from_slice(
                ROOTS_OF_UNITY[i as usize]
                    .into_bigint()
                    .to_bytes_be()
                    .as_ref(),
            );
            let blob_per_index_key = keccak256(blob_key);
            let sidecar_blob = [0u8; 32].to_vec();
            preimages.insert(
                PreimageKey::new(*blob_per_index_key, PreimageKeyType::Blob),
                sidecar_blob,
            );
        }

        let blob_key_hash = keccak256(blob_key);
        preimages.insert(
            PreimageKey::new(*blob_key_hash, PreimageKeyType::Keccak256),
            blob_key.to_vec(),
        );

        let first_key = PreimageKey::new(*blob_key_hash, PreimageKeyType::Blob);
        let mut cache = HashSet::new();
        let err = verify_blob_preimage(&first_key, &[0u8; 10], &preimages, &mut cache).unwrap_err();
        match err {
            Error::NoPreimageDataFoundInVerifyBlob(_, _) => {}
            _ => panic!("Unexpected error, got: {:?}", err),
        }
    }

    #[test]
    fn test_verify_blob_preimage_error() {
        let mut blob_key = [0u8; POSITION_FIELD_ELEMENT + 8];
        let mut preimages = HashMap::new();

        for i in 0..FIELD_ELEMENTS_PER_BLOB {
            blob_key[BYTES_PER_COMMITMENT..].copy_from_slice(
                ROOTS_OF_UNITY[i as usize]
                    .into_bigint()
                    .to_bytes_be()
                    .as_ref(),
            );
            let blob_per_index_key = keccak256(blob_key);
            let sidecar_blob = [0u8; 32].to_vec();
            preimages.insert(
                PreimageKey::new(*blob_per_index_key, PreimageKeyType::Blob),
                sidecar_blob,
            );
        }

        let blob_key_hash = keccak256(blob_key);
        let mut final_kzg_proof_key = blob_key;
        final_kzg_proof_key[POSITION_FIELD_ELEMENT..]
            .copy_from_slice((FIELD_ELEMENTS_PER_BLOB).to_be_bytes().as_ref());
        let final_kzg_proof = [0u8; BYTES_PER_COMMITMENT];
        let kzg_proof_key_hash = keccak256(final_kzg_proof_key);
        preimages.insert(
            PreimageKey::new(*blob_key_hash, PreimageKeyType::Keccak256),
            blob_key.to_vec(),
        );
        preimages.insert(
            PreimageKey::new(*kzg_proof_key_hash, PreimageKeyType::Blob),
            final_kzg_proof.to_vec(),
        );

        let first_key = PreimageKey::new(*blob_key_hash, PreimageKeyType::Blob);
        let mut cache = HashSet::new();
        let err = verify_blob_preimage(&first_key, &[0u8; 10], &preimages, &mut cache).unwrap_err();
        match err {
            Error::UnexpectedPreimageBlob(_) => {}
            _ => panic!("Unexpected error, got: {:?}", err),
        }
    }

    #[test]
    fn test_copy_slice_error() {
        let mut slice = [0u8; 4];
        let value = [0u8; 5];
        let err = try_copy_slice(&mut slice, &value).unwrap_err();
        match err {
            Error::UnexpectedSliceLength(4, 5) => {}
            _ => panic!("Unexpected error, got: {:?}", err),
        }
    }
}
