use alloc::string::String;
use alloc::vec::Vec;
use kona_preimage::errors::InvalidPreimageKeyType;
use light_client::commitments::{CommitmentPrefix, Error as CommitmentError};
use light_client::types::{ClientId, Height, TimeError};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    // Preimage
    InvalidPreimageKeySize(usize),
    InvalidPreimageKey {
        #[from]
        source: InvalidPreimageKeyType,
        key: [u8; 32],
    },

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
    UnexpectedConsensusStateRoot(Vec<u8>),
    UnexpectedHeaderHash(Vec<u8>),
    UnexpectedOutputRoot(Vec<u8>),
}
