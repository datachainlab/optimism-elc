use crate::errors::Error;
use ethereum_ibc::consensus::beacon::{Epoch, Root, Slot};
use ethereum_ibc::consensus::context::ChainContext;
use ethereum_ibc::consensus::fork::ForkParameters;
use ethereum_ibc::consensus::sync_protocol::SyncCommittee;
use ethereum_ibc::consensus::types::U64;
use ethereum_ibc::light_client_verifier::consensus::{
    CurrentNextSyncProtocolVerifier, SyncProtocolVerifier,
};
use ethereum_ibc::light_client_verifier::context::{
    ConsensusVerificationContext, Fraction, LightClientContext,
};
use ethereum_ibc::light_client_verifier::state::SyncCommitteeView;
use ethereum_ibc::update::{ConsensusUpdateInfo, ExecutionUpdateInfo};

#[derive(Clone, Debug)]
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
        let current_slot = (current_timestamp - self.genesis_time) / self.seconds_per_slot
            + self.fork_parameters.genesis_slot();
        LightClientContext::new(
            self.fork_parameters.clone(),
            self.seconds_per_slot,
            self.slots_per_epoch,
            self.epochs_per_sync_committee_period,
            self.genesis_time,
            self.genesis_validators_root,
            self.min_sync_committee_participants.0 as usize,
            self.trust_level.clone(),
            move || current_slot,
        )
    }
}

#[derive(Clone, Debug)]
pub struct L1Header<const SYNC_COMMITTEE_SIZE: usize> {
    pub sync_committee: L1SyncCommittee<SYNC_COMMITTEE_SIZE>,
    pub consensus_update: ConsensusUpdateInfo<SYNC_COMMITTEE_SIZE>,
    pub execution_update: ExecutionUpdateInfo,
}

#[derive(Clone, Debug)]
pub struct L1SyncCommittee<const SYNC_COMMITTEE_SIZE: usize> {
    pub slot: Slot,
}

impl<const SYNC_COMMITTEE_SIZE: usize> SyncCommitteeView<SYNC_COMMITTEE_SIZE>
    for L1SyncCommittee<SYNC_COMMITTEE_SIZE>
{
    fn current_slot(&self) -> Slot {
        self.slot.clone()
    }

    fn current_sync_committee(&self) -> &SyncCommittee<SYNC_COMMITTEE_SIZE> {
        unreachable!("current_sync_committee is not implemented for L1SyncCommittee")
    }

    fn next_sync_committee(&self) -> Option<&SyncCommittee<SYNC_COMMITTEE_SIZE>> {
        unreachable!("next_sync_committee is not implemented for L1SyncCommittee")
    }
}

pub struct L1Verifier<const SYNC_COMMITTEE_SIZE: usize, const EXECUTION_PAYLOAD_TREE_DEPTH: usize> {
    consensus_verifier: CurrentNextSyncProtocolVerifier<
        SYNC_COMMITTEE_SIZE,
        EXECUTION_PAYLOAD_TREE_DEPTH,
        L1SyncCommittee<SYNC_COMMITTEE_SIZE>,
    >,
}

impl<const SYNC_COMMITTEE_SIZE: usize, const EXECUTION_PAYLOAD_TREE_DEPTH: usize>
    L1Verifier<SYNC_COMMITTEE_SIZE, EXECUTION_PAYLOAD_TREE_DEPTH>
{
    pub fn verify(
        &self,
        host_unix_timestamp: u64,
        l1_config: &L1Config,
        header: &L1Header<SYNC_COMMITTEE_SIZE>,
    ) -> Result<(), Error> {
        let ctx = l1_config.build_context(host_unix_timestamp);
        let sync_committee = &header.sync_committee;
        let consensus_update = &header.consensus_update;
        let execution_update = &header.execution_update;
        self.consensus_verifier
            .validate_updates(ctx, sync_committee, consensus_update, execution_update)
            .map_err(Error::L1Error)
    }
}
