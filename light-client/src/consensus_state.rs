use alloc::borrow::ToOwned as _;
use alloc::vec::Vec;
use alloy_primitives::B256;
use ethereum_ibc::consensus::types::H256;
use light_client::types::{Any, Time};
use prost::Message as _;

use super::errors::Error;
use crate::misc::new_timestamp;
use optimism_ibc_proto::google::protobuf::Any as IBCAny;
use optimism_ibc_proto::ibc::lightclients::optimism::v1::ConsensusState as RawConsensusState;

pub const OPTIMISM_CONSENSUS_STATE_TYPE_URL: &str = "/ibc.lightclients.optimism.v1.ConsensusState";

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConsensusState {
    /// the storage root of the IBC contract
    pub storage_root: H256,
    /// timestamp from execution payload
    pub timestamp: Time,
    /// The agreed l2 output root
    pub output_root: B256,
    /// The agreed l2 header hash
    pub hash: B256,
}

impl ConsensusState {
    /// canonicalize canonicalizes some fields of specified client state
    /// target fields: nothing
    pub fn canonicalize(self) -> Self {
        self
    }
}

impl TryFrom<RawConsensusState> for ConsensusState {
    type Error = Error;

    fn try_from(value: RawConsensusState) -> Result<Self, Self::Error> {
        let storage_root: H256 = H256::try_from(&value.storage_root)
            .map_err(|e| Error::UnexpectedConsensusStorageRoot(value.storage_root))?;
        let timestamp = new_timestamp(value.timestamp)?;
        let output_root: B256 = B256::try_from(&value.output_root)
            .map_err(|e| Error::UnexpectedOutputRoot(value.output_root))?;
        let hash: B256 =
            B256::try_from(&value.hash).map_err(|e| Error::UnexpectedHeaderHash(value.hash))?;
        Ok(Self {
            storage_root,
            timestamp,
            output_root,
            hash,
        })
    }
}

impl From<ConsensusState> for RawConsensusState {
    fn from(value: ConsensusState) -> Self {
        Self {
            storage_root: value.storage_root.to_vec(),
            timestamp: value.timestamp.as_unix_timestamp_secs(),
            output_root: value.output_root.into(),
            hash: value.hash.into(),
        }
    }
}

impl TryFrom<IBCAny> for ConsensusState {
    type Error = Error;

    fn try_from(any: IBCAny) -> Result<Self, Self::Error> {
        if any.type_url != OPTIMISM_CONSENSUS_STATE_TYPE_URL {
            return Err(Error::UnknownConsensusStateType(any.type_url));
        }
        RawConsensusState::decode(any.value.as_slice())
            .map_err(Error::ProtoDecodeError)?
            .try_into()
    }
}

impl TryFrom<ConsensusState> for IBCAny {
    type Error = Error;

    fn try_from(value: ConsensusState) -> Result<Self, Self::Error> {
        let value: RawConsensusState = value.into();
        let mut v = Vec::new();
        value.encode(&mut v).map_err(Error::ProtoEncodeError)?;
        Ok(Self {
            type_url: OPTIMISM_CONSENSUS_STATE_TYPE_URL.to_owned(),
            value: v,
        })
    }
}

impl TryFrom<ConsensusState> for Any {
    type Error = Error;

    fn try_from(value: ConsensusState) -> Result<Self, Self::Error> {
        Ok(IBCAny::try_from(value)?.into())
    }
}

impl TryFrom<Any> for ConsensusState {
    type Error = Error;

    fn try_from(any: Any) -> Result<Self, Self::Error> {
        IBCAny::from(any).try_into()
    }
}
