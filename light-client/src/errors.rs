use alloc::string::String;
use alloc::vec::Vec;
use core::array::TryFromSliceError;
use ethereum_ibc::consensus::errors::Error as L1ConsensusError;
use ethereum_ibc::consensus::types::H256;
use ethereum_ibc::errors::Error as L1IBCError;
use ethereum_ibc::light_client_verifier::errors::Error as L1VerifyError;
use kona_preimage::errors::InvalidPreimageKeyType;
use kona_preimage::PreimageKey;
use light_client::commitments::Error as CommitmentError;
use light_client::types::{ClientId, Height, Time, TimeError};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    // Preimage
    #[error("InvalidPreimageKeySize: {0}")]
    InvalidPreimageKeySize(usize),
    #[error("InvalidPreimageKey: {source:?} {key:?}")]
    InvalidPreimageKey {
        source: InvalidPreimageKeyType,
        key: [u8; 32],
    },
    #[error("InvalidPreimageValue: {value:?} {key:?}")]
    InvalidPreimageValue { value: Vec<u8>, key: PreimageKey },
    #[error("UnexpectedGlobalGlobalGeneric: {0}")]
    UnexpectedGlobalGlobalGeneric(PreimageKey),

    // data conversion error
    #[error("TimestampOverflowError: {0}")]
    TimestampOverflowError(u128),
    #[error("TimeError: {0}")]
    TimeError(TimeError),
    #[error("RLPDecodeError: {0}")]
    RLPDecodeError(rlp::DecoderError),
    #[error("ProtoDecodeError: {0}")]
    ProtoDecodeError(prost::DecodeError),
    #[error("ProtoEncodeError: {0}")]
    ProtoEncodeError(prost::EncodeError),
    #[error("UnknownHeaderType: {0}")]
    UnknownHeaderType(String),
    #[error("UnknownClientStateType: {0}")]
    UnknownClientStateType(String),
    #[error("UnknownConsensusStateType: {0}")]
    UnknownConsensusStateType(String),
    #[error("UnknownMisbehaviourType: {0}")]
    UnknownMisbehaviourType(String),
    #[error("UnexpectedClientType: {0}")]
    UnexpectedClientType(String),
    #[error("LCPCommitmentError: {0}")]
    LCPCommitmentError(CommitmentError),

    // ClientState error
    #[error("MissingLatestHeight")]
    MissingLatestHeight,
    #[error("UnexpectedStoreAddress: {0:?}")]
    UnexpectedStoreAddress(L1ConsensusError),
    #[error("UnexpectedCommitmentSlot: {0:?}")]
    UnexpectedCommitmentSlot(TryFromSliceError),
    #[error("ClientFrozen: {0}")]
    ClientFrozen(ClientId),
    #[error("UnexpectedProofHeight: {0} {1}")]
    UnexpectedProofHeight(Height, Height),
    #[error("MissingTrustedHeight")]
    MissingTrustedHeight,
    #[error("MissingTrustingPeriod")]
    MissingTrustingPeriod,
    #[error("NegativeMaxClockDrift")]
    NegativeMaxClockDrift,
    #[error("UnexpectedRollupConfig {0}")]
    UnexpectedRollupConfig(serde_json::Error),

    // ConsState error
    #[error("UnexpectedStorageRoot: proof_height={0} latest_height={1}")]
    UnexpectedStorageRoot(Height, Height),
    #[error("UnexpectedConsensusStorageRoot {0}")]
    UnexpectedConsensusStorageRoot(TryFromSliceError),
    #[error("UnexpectedHeaderHash {0}")]
    UnexpectedHeaderHash(TryFromSliceError),
    #[error("UnexpectedOutputRoot {0}")]
    UnexpectedOutputRoot(TryFromSliceError),
    #[error("MissingTrustLevel")]
    MissingTrustLevel,
    #[error("MissingForkParameters")]
    MissingForkParameters,

    // Update
    #[error("MissingL1Config")]
    MissingL1Config,
    #[error("MissingForkSpec")]
    MissingForkSpec,
    #[error("MissingL1Head")]
    MissingL1Head,
    #[error("MissingL1ConsensusUpdate")]
    MissingL1ConsensusUpdate,
    #[error("MissingL1ExecutionUpdate")]
    MissingL1ExecutionUpdate,
    #[error("MissingAccountUpdate")]
    MissingAccountUpdate,
    #[error("UnexpectedEmptyDerivations")]
    UnexpectedEmptyDerivations,
    #[error("UnexpectedL1HeadHash {0}")]
    UnexpectedL1HeadHash(TryFromSliceError),
    #[error("UnexpectedAgreedL2HeadHash {0}")]
    UnexpectedAgreedL2HeadHash(TryFromSliceError),
    #[error("UnexpectedAgreedL2OutputRoot {0}")]
    UnexpectedAgreedL2OutputRoot(TryFromSliceError),
    #[error("UnexpectedL2HeadHash {0}")]
    UnexpectedL2HeadHash(TryFromSliceError),
    #[error("UnexpectedL2OutputRoot {0}")]
    UnexpectedL2OutputRoot(TryFromSliceError),
    #[error("AccountStorageRootMismatch {0} {1} {2} {3:?} {4:?}")]
    AccountStorageRootMismatch(H256, H256, H256, String, Vec<String>),
    #[error("MPTVerificationError {0} {1} {2} {3:?}")]
    MPTVerificationError(
        ethereum_ibc::light_client_verifier::errors::Error,
        H256,
        String,
        Vec<String>,
    ),
    #[error("OutOfTrustingPeriod {0} {1}")]
    OutOfTrustingPeriod(Time, Time),
    #[error("HeaderFromFuture {0} {1:?} {2}")]
    HeaderFromFuture(Time, core::time::Duration, Time),
    #[error("L1VerifyError {0}")]
    L1VerifyError(L1VerifyError),
    #[error("L1IBCError {0}")]
    L1IBCError(L1IBCError),
    #[error("DerivationError {0}")]
    DerivationError(optimism_derivation::Error),

    // Framework
    #[error("LCPError {0}")]
    LCPError(light_client::Error),
}

impl light_client::LightClientSpecificError for Error {}
