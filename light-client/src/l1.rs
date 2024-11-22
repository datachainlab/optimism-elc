use crate::errors::Error;
use ethereum_ibc::consensus::beacon::{Epoch, Root, Slot};
use ethereum_ibc::consensus::compute::compute_sync_committee_period_at_slot;
use ethereum_ibc::consensus::context::ChainContext;
use ethereum_ibc::consensus::fork::ForkParameters;
use ethereum_ibc::consensus::sync_protocol::{SyncCommittee, SyncCommitteePeriod};
use ethereum_ibc::consensus::types::{U64};
use ethereum_ibc::light_client_verifier::consensus::{
    SyncProtocolVerifier,
};
use ethereum_ibc::light_client_verifier::context::{
    ConsensusVerificationContext, Fraction, LightClientContext,
};
use ethereum_ibc::light_client_verifier::state::LightClientStoreReader;
use ethereum_ibc::light_client_verifier::updates::ConsensusUpdate;
use ethereum_ibc::types::{convert_proto_to_consensus_update, convert_proto_to_execution_update, ExecutionUpdateInfo};
use ethereum_ibc::update::{ConsensusUpdateInfo};
use serde::{Deserialize, Serialize};
use optimism_ibc_proto::ibc::lightclients::optimism::v1::L1Header as RawL1Header;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct L1Config {
    /// Chain Param
    pub genesis_validators_root: Root,
    pub min_sync_committee_participants: U64,
    pub genesis_time: U64,
    pub fork_parameters: ForkParameters,
    pub seconds_per_slot: U64,
    pub slots_per_epoch: Slot,
    pub epochs_per_sync_committee_period: Epoch,

    /// Light Client parameters
    pub trust_level: Fraction,
}

impl L1Config {
    pub(crate) fn build_context(
        &self,
        host_unix_timestamp: u64,
    ) -> impl ChainContext + ConsensusVerificationContext {
        let current_timestamp = U64::from(host_unix_timestamp);
        LightClientContext::new(
            self.fork_parameters.clone(),
            self.seconds_per_slot,
            self.slots_per_epoch,
            self.epochs_per_sync_committee_period,
            self.genesis_time,
            self.genesis_validators_root,
            self.min_sync_committee_participants.0 as usize,
            self.trust_level.clone(),
            current_timestamp,
        )
    }
}

#[derive(Clone, Debug)]
pub struct L1Header<const SYNC_COMMITTEE_SIZE: usize> {
    pub consensus_update: ConsensusUpdateInfo<SYNC_COMMITTEE_SIZE>,
    pub execution_update: ExecutionUpdateInfo,
}

impl <const SYNC_COMMITTEE_SIZE: usize> TryFrom<RawL1Header> for L1Header<SYNC_COMMITTEE_SIZE> {
    type Error = ();

    fn try_from(value: RawL1Header) -> Result<Self, Self::Error> {
        let consensus_update = value.consensus_update.ok_or(Error::MissingL1ConsensusUpdate)?;
        let execution_update = value.execution_update.ok_or(Error::MissingL1ExecutionUpdate)?;

        Ok(Self {
            consensus_update: convert_proto_to_consensus_update(consensus_update)?,
            execution_update: convert_proto_to_execution_update(execution_update),
        })
    }

}

#[derive(Clone, Debug)]
pub struct L1SyncCommittee {
    pub slot: Slot,
}

impl<const SYNC_COMMITTEE_SIZE: usize> LightClientStoreReader<SYNC_COMMITTEE_SIZE> for L1SyncCommittee {

    fn current_period<CC: ChainContext>(&self, ctx: &CC) -> SyncCommitteePeriod {
        compute_sync_committee_period_at_slot(ctx, self.slot)
    }

    fn current_sync_committee(&self) -> &SyncCommittee<SYNC_COMMITTEE_SIZE> {
        todo!("current_sync_committee is not implemented for L1SyncCommittee")
    }

    fn next_sync_committee(&self) -> Option<&SyncCommittee<SYNC_COMMITTEE_SIZE>> {
        todo!("next_sync_committee is not implemented for L1SyncCommittee")
    }

    fn ensure_relevant_update<CC: ChainContext, C: ConsensusUpdate<SYNC_COMMITTEE_SIZE>>(&self, ctx: &CC, update: &C) -> Result<(), ethereum_ibc::light_client_verifier::errors::Error> {
        unreachable!("ensure_relevant_update is not implemented for L1SyncCommittee");
    }
}

pub struct L1Verifier<const SYNC_COMMITTEE_SIZE: usize> {
    consensus_verifier: SyncProtocolVerifier<
        SYNC_COMMITTEE_SIZE,
        L1SyncCommittee,
    >,
}


impl<const SYNC_COMMITTEE_SIZE: usize> L1Verifier<SYNC_COMMITTEE_SIZE>
{
    pub fn new() -> Self {
        Self {
            consensus_verifier: Default::default(),
        }
    }
    pub fn verify(
        &self,
        host_unix_timestamp: u64,
        l1_config: &L1Config,
        header: &L1Header<SYNC_COMMITTEE_SIZE>,
    ) -> Result<(), Error> {
        let ctx = l1_config.build_context(host_unix_timestamp);
        let slot = header
            .consensus_update
            .finalized_header
            .0
            .slot
            .clone();
        let l1_sync_committee = &L1SyncCommittee { slot };
        let consensus_update = &header.consensus_update;
        let execution_update = &header.execution_update;
        self.consensus_verifier
            .validate_updates(ctx, &l1_sync_committee, consensus_update, execution_update)
            .map_err(Error::L1Error)
    }
}
