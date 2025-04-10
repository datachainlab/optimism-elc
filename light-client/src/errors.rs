use crate::l1::L1Consensus;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use alloy_primitives::B256;
use core::array::TryFromSliceError;
use ethereum_ibc::consensus::beacon::Slot;
use ethereum_ibc::consensus::bls::PublicKey;
use ethereum_ibc::consensus::errors::Error as L1ConsensusError;
use ethereum_ibc::consensus::fork::ForkSpec;
use ethereum_ibc::consensus::sync_protocol::SyncCommitteePeriod;
use ethereum_ibc::consensus::types::H256;
use ethereum_ibc::errors::Error as L1IBCError;
use ethereum_ibc::light_client_verifier::errors::Error as L1VerifyError;
use kona_preimage::errors::PreimageOracleError;
use kona_preimage::PreimageKey;
use light_client::commitments::Error as CommitmentError;
use light_client::types::{ClientId, Height, Time, TimeError};
use optimism_derivation::derivation::Derivation;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    // Preimage
    #[error("UnexpectedPreimageKey: {0}")]
    UnexpectedPreimageKeySize(usize),
    #[error("UnexpectedPreimageKey: {source:?} {key:?}")]
    UnexpectedPreimageKey {
        source: PreimageOracleError,
        key: [u8; 32],
    },
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
    #[error("OracleClientError: {0}")]
    OracleClientError(#[from] optimism_derivation::errors::Error),

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
    #[error("MissingTrustedSyncCommittee")]
    MissingTrustedSyncCommittee,
    #[error("MissingL1ExecutionUpdate")]
    MissingL1ExecutionUpdate,
    #[error("MissingAccountUpdate")]
    MissingAccountUpdate,
    #[error("UnexpectedEmptyDerivations")]
    UnexpectedEmptyDerivations,
    #[error("UnexpectedTrustedOutputRoot {0:?} {1:?}")]
    UnexpectedTrustedOutputRoot(B256, B256),
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
    #[error("L1ExecutionVerifyError {fork_spec:?} {slot:?} {err:?}")]
    L1ExecutionVerifyError {
        fork_spec: ForkSpec,
        slot: Slot,
        err: L1VerifyError,
    },
    #[error("L1VerifyError {0:?}")]
    L1VerifyError(L1VerifyError),
    #[error("L1IBCError {0}")]
    L1IBCError(L1IBCError),
    #[error("L1ConsensusError {0}")]
    L1ConsensusError(L1ConsensusError),
    #[error("L1VerifyError index={0}, prev_updated_as_next={1:?} prev={2:?}, err={3}")]
    L1HeaderVerifyError(usize, bool, L1Consensus, Box<Error>),
    #[error("L1VerifyError index={0}, prev_updated_as_next={1:?} prev={2:?}, err={3}")]
    L1HeaderForDerivationVerifyError(usize, bool, L1Consensus, Box<Error>),
    #[error("DerivationError derivation={0:?}, preimage_size:{1:?} err{2:?}")]
    DerivationError(Derivation, usize, optimism_derivation::Error),
    #[error("UnexpectedCurrentSyncCommitteeKeys {0:?} {1:?}")]
    UnexpectedCurrentSyncCommitteeKeys(PublicKey, PublicKey),
    #[error("UnexpectedNextSyncCommitteeKeys {0:?} {1:?}")]
    UnexpectedNextSyncCommitteeKeys(PublicKey, PublicKey),
    #[error("NoNextSyncCommitteeInConsensusUpdate {0:?} {1:?}")]
    NoNextSyncCommitteeInConsensusUpdate(SyncCommitteePeriod, SyncCommitteePeriod),
    #[error("StoreNotSupportedFinalizedPeriod {0:?} {1:?}")]
    StoreNotSupportedFinalizedPeriod(SyncCommitteePeriod, SyncCommitteePeriod),

    // Framework
    #[error("LCPError {0}")]
    LCPError(light_client::Error),
}

impl light_client::LightClientSpecificError for Error {}
