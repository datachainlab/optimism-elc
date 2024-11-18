use alloc::string::String;
use alloc::vec::Vec;
use ethereum_ibc::light_client_verifier::errors::Error as L1Error;
use kona_preimage::errors::InvalidPreimageKeyType;
use kona_preimage::PreimageKey;
use light_client::commitments::{CommitmentPrefix, Error as CommitmentError};
use light_client::types::{Any, ClientId, Height, TimeError};

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
    UnexpectedConsensusStateRoot(Vec<u8>),
    UnexpectedHeaderHash(Vec<u8>),
    UnexpectedOutputRoot(Vec<u8>),

    // Update
    L1Error(#[from] L1Error),

    // Framework
    LCPError(light_client::Error),
}

#[derive(thiserror::Error, Debug)]
pub enum ClientError {
    LatestHeight {
        #[from]
        cause: Error,
        client_id: ClientId,
    },
    CreateClient {
        #[from]
        cause: Error,
        client_state: Any,
        consensus_sate: Any,
    },
    UpdateClient {
        #[from]
        cause: Error,
        client_id: ClientId,
    },
    VerifyMembership {
        #[from]
        cause: Error,
        client_id: ClientId,
        prefix: CommitmentPrefix,
        path: String,
        value: Vec<u8>,
        proof_height: Height,
        proof: Vec<u8>,
    },
    VerifyNonMembership {
        #[from]
        cause: Error,
        client_id: ClientId,
        prefix: CommitmentPrefix,
        path: String,
        proof_height: Height,
        proof: Vec<u8>,
    },
}

impl light_client::LightClientSpecificError for ClientError {}
