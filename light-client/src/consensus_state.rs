use alloc::borrow::ToOwned as _;
use alloc::vec::Vec;
use alloy_primitives::B256;
use ethereum_ibc::consensus::beacon::Slot;
use ethereum_ibc::consensus::bls::PublicKey;
use ethereum_ibc::consensus::compute::compute_sync_committee_period_at_slot;
use ethereum_ibc::consensus::context::ChainContext;
use ethereum_ibc::consensus::sync_protocol::SyncCommitteePeriod;
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

    /// L1 Consensus
    /// finalized header's slot
    pub l1_slot: Slot,
    /// aggregate public key of current sync committee
    /// "current" indicates a period corresponding to the `slot`
    pub l1_current_sync_committee: PublicKey,
    /// aggregate public key of next sync committee
    /// "next" indicates `current + 1` period
    pub l1_next_sync_committee: PublicKey,
}

impl ConsensusState {
    /// canonicalize canonicalizes some fields of specified client state
    /// target fields: nothing
    pub fn canonicalize(mut self) -> Self {
        self.l1_slot = Slot::default();
        self.l1_current_sync_committee = PublicKey::default();
        self.l1_next_sync_committee = PublicKey::default();
        self
    }

    pub fn current_l1_period<C: ChainContext>(&self, ctx: &C) -> SyncCommitteePeriod {
        compute_sync_committee_period_at_slot(ctx, self.l1_slot)
    }
}

impl TryFrom<RawConsensusState> for ConsensusState {
    type Error = Error;

    fn try_from(value: RawConsensusState) -> Result<Self, Self::Error> {
        let storage_root = B256::try_from(value.storage_root.as_slice())
            .map_err(Error::UnexpectedConsensusStorageRoot)?;
        let storage_root = H256::from(storage_root.0);
        let timestamp = new_timestamp(value.timestamp)?;
        let output_root =
            B256::try_from(value.output_root.as_slice()).map_err(Error::UnexpectedOutputRoot)?;

        Ok(Self {
            storage_root,
            timestamp,
            output_root,
            // L1
            l1_slot: value.l1_slot.into(),
            l1_current_sync_committee: PublicKey::try_from(value.l1_current_sync_committee)
                .map_err(Error::L1ConsensusError)?,
            l1_next_sync_committee: PublicKey::try_from(value.l1_next_sync_committee)
                .map_err(Error::L1ConsensusError)?,
        })
    }
}

impl From<ConsensusState> for RawConsensusState {
    fn from(value: ConsensusState) -> Self {
        Self {
            storage_root: value.storage_root.0.to_vec(),
            timestamp: value.timestamp.as_unix_timestamp_secs(),
            output_root: value.output_root.to_vec(),
            // L1
            l1_slot: value.l1_slot.into(),
            l1_current_sync_committee: value.l1_current_sync_committee.to_vec(),
            l1_next_sync_committee: value.l1_next_sync_committee.to_vec(),
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
