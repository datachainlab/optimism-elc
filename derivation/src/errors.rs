use alloc::boxed::Box;
use alloc::vec::Vec;
use alloy_primitives::B256;
use core::array::TryFromSliceError;
use kona_preimage::errors::PreimageOracleError;
use kona_preimage::PreimageKey;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid derivation {0}")]
    Kona(#[from] anyhow::Error),
    #[error("invalid claim actual={0}, expected={1}")]
    InvalidClaim(B256, B256),
    #[error("UnexpectedKZGCommitment: {0}")]
    UnexpectedKZGCommitment(kzg_rs::enums::KzgError),
    #[error("UnexpectedKZGProof: {0}")]
    UnexpectedKZGProof(kzg_rs::enums::KzgError),
    #[error("UnexpectedKZGBlob: {0}")]
    UnexpectedKZGBlob(kzg_rs::enums::KzgError),
    #[error("UnexpectedPreimageBlob: {0}")]
    UnexpectedPreimageBlob(kzg_rs::enums::KzgError),
    #[error("UnexpectedPreimageBlobResult: {0}")]
    UnexpectedPreimageBlobResult(PreimageKey),
    #[error("UnexpectedBlobFieldIndex: {0}")]
    UnexpectedBlobFieldIndex(TryFromSliceError),
    #[error("UnexpectedPreimageKey: {0}")]
    UnexpectedPreimageKeySize(usize),
    #[error("UnexpectedPreimageKey: {source:?} {key:?}")]
    UnexpectedPreimageKey {
        source: PreimageOracleError,
        key: [u8; 32],
    },
    #[error("UnexpectedPrecompilePreimage: {0}")]
    UnexpectedPrecompilePreimage(PreimageKey),
    #[error("UnexpectedPreimageValue: {value:?} {key:?}")]
    UnexpectedPreimageValue { value: Vec<u8>, key: PreimageKey },
    #[error("UnexpectedPrecompiledValue: {actual:?} {expected:?} {key:?}")]
    UnexpectedPrecompiledValue {
        expected: Vec<u8>,
        actual: Vec<u8>,
        key: PreimageKey,
    },
    #[error("NoPreimagePrecompiledCodeFound: {key:?}")]
    NoPreimagePrecompiledCodeFound { key: PreimageKey },
    #[error("NoPreimageKeyFound: {key:?}")]
    NoPreimageKeyFound { key: PreimageKey },
    #[error("NoPreimageKeyFoundInVerifyBlob: {0:?}")]
    NoPreimageKeyFoundInVerifyBlob(Box<Error>),
    #[error("UnexpectedGlobalGlobalGeneric: {0}")]
    UnexpectedGlobalGlobalGeneric(PreimageKey),
}
