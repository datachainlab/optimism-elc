use alloc::boxed::Box;
use alloc::vec::Vec;
use alloy_primitives::B256;
use core::array::TryFromSliceError;
use kona_preimage::errors::PreimageOracleError;
use kona_preimage::PreimageKey;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("InvalidClaim actual={0}, expected={1}")]
    InvalidClaim(B256, B256),
    #[error("UnexpectedKZGCommitment: err={0:?}")]
    UnexpectedKZGCommitment(kzg_rs::enums::KzgError),
    #[error("UnexpectedKZGProof: err={0:?}")]
    UnexpectedKZGProof(kzg_rs::enums::KzgError),
    #[error("UnexpectedKZGBlob: err={0:?}")]
    UnexpectedKZGBlob(kzg_rs::enums::KzgError),
    #[error("UnexpectedPreimageBlob: err={0:?}")]
    UnexpectedPreimageBlob(kzg_rs::enums::KzgError),
    #[error("UnexpectedPreimageBlobResult: key={0}")]
    UnexpectedPreimageBlobResult(PreimageKey),
    #[error("UnexpectedBlobFieldIndex: err={0:?}")]
    UnexpectedBlobFieldIndex(TryFromSliceError),
    #[error("UnexpectedBlobKeySuffix: blobKey={0:?}")]
    UnexpectedBlobKeySuffix(Vec<u8>),
    #[error("UnexpectedPreimageKeySize: size={0}")]
    UnexpectedPreimageKeySize(usize),
    #[error("UnexpectedPreimageKey: err={source:?} key={key:?}")]
    UnexpectedPreimageKey {
        source: PreimageOracleError,
        key: [u8; 32],
    },
    #[error("UnexpectedSha256PreimageValue: value={value:?} key={key}")]
    UnexpectedSha256PreimageValue { value: Vec<u8>, key: PreimageKey },
    #[error("UnexpectedKeccak256PreimageValue: value={value:?} key={key}")]
    UnexpectedKeccak256PreimageValue { value: Vec<u8>, key: PreimageKey },
    #[error("NoPreimageKeyFound: key={key}")]
    NoPreimageKeyFound { key: PreimageKey },
    #[error("NoPreimageKeyFoundInVerifyBlob: err={0:?}")]
    NoPreimageKeyFoundInVerifyBlob(Box<Error>),
    #[error("NoPreimageDataFoundInVerifyBlob: blobKey={0:?}, err={1:?}")]
    NoPreimageDataFoundInVerifyBlob(Vec<u8>, Box<Error>),
    #[error("NoPreimageKeyFoundInPrecompile: err={0:?}")]
    NoPreimageKeyFoundInPrecompile(Box<Error>),
    #[error("UnexpectedSliceLength: {0} {1}")]
    UnexpectedSliceLength(usize, usize),
    #[error("OracleProviderError: err={0:?}")]
    OracleProviderError(#[from] kona_proof::errors::OracleProviderError),
    #[error("DriverError: err={0:?}")]
    DriverError(#[from] kona_driver::DriverError<kona_executor::ExecutorError>),
    #[error("PipelineError: err={0:?}")]
    PipelineError(#[from] kona_derive::errors::PipelineErrorKind),
}
