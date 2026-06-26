//! Test utilities for the optimism light client (L1 part).
//!
//! Generates fully-synthetic, internally-consistent L1 headers (valid BLS sync
//! committee signatures + execution payload Merkle proofs, including the
//! `block_hash` branch that optimism's `validate_execution_update` requires).
//! This lets the L1 unit tests run without prover-generated fixtures, so they
//! are stable across proto/schema changes.

use crate::l1::{L1Config, L1ConsensusState, L1Header};
use core::time::Duration;
use ethereum_consensus::compute::compute_timestamp_at_slot;
use ethereum_consensus::config;
use ethereum_consensus::context::ChainContext;
use ethereum_consensus::fork::deneb::prover::gen_execution_payload_field_proof;
use ethereum_consensus::preset::minimal::PRESET;
use ethereum_consensus::types::{H256, U64};
use ethereum_light_client_types::consensus::{
    convert_consensus_update_to_proto, convert_execution_update_to_proto, ConsensusUpdateInfo,
    ExecutionUpdateInfo, TrustedSyncCommittee,
};
use optimism_ibc_proto::ibc::lightclients::optimism::v1::L1Header as RawL1Header;
use ethereum_light_client_verifier::consensus::test_utils::{
    gen_finalized_beacon_block, gen_light_client_update_with_params, MockSyncCommittee,
    MockSyncCommitteeManager,
};
use ethereum_light_client_verifier::context::{Fraction, LightClientContext};
use light_client::types::{Height, Time};

/// Sync committee size from the minimal preset.
pub const SYNC_COMMITTEE_SIZE: usize = PRESET.SYNC_COMMITTEE_SIZE;

/// `block_hash` leaf index within the execution payload (state_root=2, block_number=6).
const EXECUTION_BLOCK_HASH_LEAF_INDEX: usize = 12;

/// Default genesis time for tests (2020-01-01 00:00:00 UTC).
pub const DEFAULT_GENESIS_TIME: u64 = 1577836800;

fn new_time(secs: u64) -> Time {
    Time::from_unix_timestamp(secs as i64, 0).unwrap()
}

/// Converts the verifier's `ConsensusUpdateInfo` to the types crate's one.
pub fn to_consensus_update_info(
    consensus_update: ethereum_light_client_verifier::updates::ConsensusUpdateInfo<
        SYNC_COMMITTEE_SIZE,
    >,
) -> ConsensusUpdateInfo<SYNC_COMMITTEE_SIZE> {
    ConsensusUpdateInfo {
        attested_header: consensus_update.light_client_update.attested_header,
        next_sync_committee: consensus_update.light_client_update.next_sync_committee,
        finalized_header: consensus_update.light_client_update.finalized_header,
        sync_aggregate: consensus_update.light_client_update.sync_aggregate,
        signature_slot: consensus_update.light_client_update.signature_slot,
        finalized_execution_root: consensus_update.finalized_execution_root,
        finalized_execution_branch: consensus_update.finalized_execution_branch,
    }
}

/// Synthetic L1 test fixture: mock sync committees + a minimal-preset context.
pub struct L1Fixture {
    pub scm: MockSyncCommitteeManager<SYNC_COMMITTEE_SIZE>,
    pub ctx: LightClientContext,
    pub genesis_time: u64,
    pub period_1: U64,
    pub base_signature_slot: U64,
    pub base_attested_slot: U64,
    pub base_finalized_epoch: U64,
}

impl Default for L1Fixture {
    fn default() -> Self {
        Self::new()
    }
}

impl L1Fixture {
    pub fn new() -> Self {
        let genesis_time = DEFAULT_GENESIS_TIME;
        let current_time = genesis_time + 100_000;
        let scm = MockSyncCommitteeManager::<SYNC_COMMITTEE_SIZE>::new(1, 4);
        let ctx = LightClientContext::new_with_config(
            config::minimal::get_config(),
            H256::from_slice(&[1u8; 32]),
            genesis_time.into(),
            Fraction::new(2, 3).unwrap(),
            current_time.into(),
        );
        let period_1 = U64(1) * ctx.slots_per_epoch() * ctx.epochs_per_sync_committee_period();
        let base_signature_slot = period_1 + 11;
        let base_attested_slot = base_signature_slot - 1;
        let base_finalized_epoch = base_attested_slot / ctx.slots_per_epoch();
        Self {
            scm,
            ctx,
            genesis_time,
            period_1,
            base_signature_slot,
            base_attested_slot,
            base_finalized_epoch,
        }
    }

    pub fn committee(&self, period: u64) -> &MockSyncCommittee<SYNC_COMMITTEE_SIZE> {
        self.scm.get_committee(period)
    }

    /// Builds an `L1Config` consistent with this fixture's context.
    pub fn l1_config(&self) -> L1Config {
        use ethereum_light_client_verifier::context::ConsensusVerificationContext;
        L1Config {
            genesis_validators_root: self.ctx.genesis_validators_root(),
            min_sync_committee_participants: 1u64.into(),
            genesis_time: self.genesis_time.into(),
            fork_parameters: self.ctx.fork_parameters().clone(),
            seconds_per_slot: PRESET.SECONDS_PER_SLOT,
            slots_per_epoch: PRESET.SLOTS_PER_EPOCH,
            epochs_per_sync_committee_period: PRESET.EPOCHS_PER_SYNC_COMMITTEE_PERIOD,
            trust_level: Fraction::new(2, 3).unwrap(),
            trusting_period: Duration::from_secs(60 * 60 * 24 * 7),
            max_clock_drift: Duration::from_secs(60 * 10),
        }
    }

    /// Trusted L1 consensus state at period 1 (current=committee1, next=committee2).
    pub fn l1_consensus_state(&self) -> L1ConsensusState {
        L1ConsensusState {
            slot: self.period_1 + 1,
            current_sync_committee: self.committee(1).to_committee().aggregate_pubkey,
            next_sync_committee: self.committee(2).to_committee().aggregate_pubkey,
            timestamp: new_time(self.genesis_time + 1),
        }
    }

    /// A valid same-period L1 header signed by committee 1, with a valid
    /// `block_hash` Merkle branch (so `validate_execution_update` passes).
    pub fn l1_header(&self) -> L1Header<SYNC_COMMITTEE_SIZE> {
        let execution_state_root = H256::from_slice(&[1u8; 32]);
        let execution_block_number = 100u64;

        let (consensus_update, execution_update) =
            gen_light_client_update_with_params::<SYNC_COMMITTEE_SIZE, _>(
                &self.ctx,
                self.base_signature_slot,
                self.base_attested_slot,
                self.base_finalized_epoch,
                execution_state_root,
                execution_block_number.into(),
                self.committee(1),
                self.committee(2),
                true,
                SYNC_COMMITTEE_SIZE,
            );

        // Recreate the same finalized block to derive the block_hash branch.
        let finalized_block = gen_finalized_beacon_block::<SYNC_COMMITTEE_SIZE, _>(
            &self.ctx,
            self.base_finalized_epoch,
            execution_state_root,
            execution_block_number.into(),
        );
        let payload_header = finalized_block.body.execution_payload.clone().to_header();
        let block_hash = payload_header.block_hash;
        let (_root, block_hash_branch) =
            gen_execution_payload_field_proof(&payload_header, EXECUTION_BLOCK_HASH_LEAF_INDEX)
                .unwrap();

        let consensus_update = to_consensus_update_info(consensus_update);
        let finalized_slot = consensus_update.finalized_header.0.slot;
        let timestamp = new_time(compute_timestamp_at_slot(&self.ctx, finalized_slot).0);

        L1Header {
            trusted_sync_committee: TrustedSyncCommittee {
                height: Height::new(0, 1),
                sync_committee: self.committee(1).to_committee(),
                is_next: false,
            },
            consensus_update,
            execution_update: ExecutionUpdateInfo {
                state_root: execution_update.state_root,
                state_root_branch: execution_update.state_root_branch,
                block_number: execution_update.block_number,
                block_number_branch: execution_update.block_number_branch,
                block_hash,
                block_hash_branch,
            },
            timestamp,
        }
    }

    /// A valid next-period L1 header: finalized in period 2 (store_period + 1),
    /// signed by committee 2, advancing the sync committee. `is_next = true`.
    pub fn l1_header_next_period(&self) -> L1Header<SYNC_COMMITTEE_SIZE> {
        let execution_state_root = H256::from_slice(&[2u8; 32]);
        let execution_block_number = 200u64;
        let period_2 = self.period_1 + self.period_1;
        let signature_slot = period_2 + 11;
        let attested_slot = signature_slot - 1;
        let finalized_epoch = attested_slot / self.ctx.slots_per_epoch();

        let (consensus_update, execution_update) =
            gen_light_client_update_with_params::<SYNC_COMMITTEE_SIZE, _>(
                &self.ctx,
                signature_slot,
                attested_slot,
                finalized_epoch,
                execution_state_root,
                execution_block_number.into(),
                self.committee(2),
                self.committee(3),
                true,
                SYNC_COMMITTEE_SIZE,
            );
        let finalized_block = gen_finalized_beacon_block::<SYNC_COMMITTEE_SIZE, _>(
            &self.ctx,
            finalized_epoch,
            execution_state_root,
            execution_block_number.into(),
        );
        let payload_header = finalized_block.body.execution_payload.clone().to_header();
        let block_hash = payload_header.block_hash;
        let (_root, block_hash_branch) =
            gen_execution_payload_field_proof(&payload_header, EXECUTION_BLOCK_HASH_LEAF_INDEX)
                .unwrap();

        let consensus_update = to_consensus_update_info(consensus_update);
        let finalized_slot = consensus_update.finalized_header.0.slot;
        let timestamp = new_time(compute_timestamp_at_slot(&self.ctx, finalized_slot).0);

        L1Header {
            trusted_sync_committee: TrustedSyncCommittee {
                height: Height::new(0, 1),
                sync_committee: self.committee(2).to_committee(),
                is_next: true,
            },
            consensus_update,
            execution_update: ExecutionUpdateInfo {
                state_root: execution_update.state_root,
                state_root_branch: execution_update.state_root_branch,
                block_number: execution_update.block_number,
                block_number_branch: execution_update.block_number_branch,
                block_hash,
                block_hash_branch,
            },
            timestamp,
        }
    }

    /// The same synthetic L1 header as a proto `RawL1Header`.
    pub fn raw_l1_header(&self) -> RawL1Header {
        let h = self.l1_header();
        RawL1Header {
            trusted_sync_committee: Some(h.trusted_sync_committee.into()),
            consensus_update: Some(convert_consensus_update_to_proto(h.consensus_update).unwrap()),
            execution_update: Some(convert_execution_update_to_proto(h.execution_update)),
            timestamp: h.timestamp.as_unix_timestamp_secs() as u64,
        }
    }

    /// Host time suitable for verifying `l1_header()` (after the finalized timestamp).
    pub fn now(&self) -> u64 {
        self.genesis_time + 100_000
    }
}
