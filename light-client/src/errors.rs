use alloc::string::String;
use alloc::vec::Vec;
use core::array::TryFromSliceError;
use ethereum_ibc::consensus::types::H256;
use ethereum_ibc::light_client_verifier::errors::Error as L1VerifyError;
use ethereum_ibc::errors::Error as L1IBCError;
use kona_preimage::errors::InvalidPreimageKeyType;
use kona_preimage::PreimageKey;
use light_client::commitments::{CommitmentPrefix, Error as CommitmentError};
use light_client::types::{Any, ClientId, Height, Time, TimeError};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    // Preimage
    InvalidPreimageKeySize(usize),
    InvalidPreimageKey {
        #[from]
        source: InvalidPreimageKeyType,
        key: [u8; 32],
    },
    InvalidPreimageValue {
        value: Vec<u8>,
        key: PreimageKey,
    },
    UnexpectedGlobalGlobalGeneric(PreimageKey),

    // data conversion error
    TimestampOverflowError(u128),
    TimeError(#[from] TimeError),
    RLPDecodeError(#[from] rlp::DecoderError),
    ProtoDecodeError(#[from] prost::DecodeError),
    ProtoEncodeError(#[from] prost::EncodeError),
    UnknownHeaderType(String),
    UnknownClientStateType(String),
    UnknownConsensusStateType(String),
    UnknownMisbehaviourType(String),
    UnexpectedClientType(String),
    LCPCommitmentError(#[from] CommitmentError),

    // ClientState error
    MissingLatestHeight,
    UnexpectedStoreAddress(Vec<u8>),
    UnexpectedCommitmentSlot(Vec<u8>),
    ClientFrozen(ClientId),
    UnexpectedProofHeight(Height, Height),
    MissingTrustedHeight,
    MissingTrustingPeriod,
    NegativeMaxClockDrift,
    UnexpectedRollupConfig(#[from] serde_json::Error),

    // ConsState error
    #[error("UnexpectedStorageRoot: proof_height={0} latest_height={1}")]
    UnexpectedStorageRoot(Height, Height),
    UnexpectedConsensusStorageRoot(#[from] TryFromSliceError),
    UnexpectedHeaderHash(#[from] TryFromSliceError),
    UnexpectedOutputRoot(#[from] TryFromSliceError),
    MissingTrustLevel,
    MissingForkParameters,

    // Update
    MissingL1Head,
    MissingL1ConsensusUpdate,
    MissingL1ExecutionUpdate,
    MissingAccountUpdate,
    UnexpectedEmptyDerivations,
    UnexpectedL1HeadHash(#[from] TryFromSliceError),
    UnexpectedAgreedL2HeadHash(#[from] TryFromSliceError),
    UnexpectedAgreedL2OutputRoot(#[from] TryFromSliceError),
    UnexpectedL2HeadHash(#[from] TryFromSliceError),
    UnexpectedL2OutputRoot(#[from] TryFromSliceError),
    AccountStorageRootMismatch(H256, H256, H256, String, Vec<String>),
    MPTVerificationError(
        ethereum_ibc::light_client_verifier::errors::Error,
        H256,
        String,
        Vec<String>,
    ),
    OutOfTrustingPeriod(Time, Time),
    HeaderFromFuture(Time, core::time::Duration, Time),
    L1VerifyError(#[from] L1VerifyError),
    L1IBCError(#[from] L1IBCError),

    // Framework
    LCPError(light_client::Error),
}

impl light_client::LightClientSpecificError for Error {}
