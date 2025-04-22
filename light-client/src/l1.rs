use crate::errors::Error;
use alloc::string::ToString;
use alloc::vec::Vec;
use ethereum_consensus::beacon::{BeaconBlockHeader, Epoch, Root, Slot};
use ethereum_consensus::bls::{PublicKey, Signature};
use ethereum_consensus::compute::{compute_sync_committee_period_at_slot, hash_tree_root};
use ethereum_consensus::context::ChainContext;
use ethereum_consensus::fork::ForkParameters;
use ethereum_consensus::merkle::is_valid_normalized_merkle_branch;
use ethereum_consensus::ssz_rs::{Bitvector, Deserialize, Vector};
use ethereum_consensus::sync_protocol::{SyncAggregate, SyncCommittee, SyncCommitteePeriod};
use ethereum_consensus::types::{H256, U64};
use ethereum_light_client_verifier::consensus::SyncProtocolVerifier;
use ethereum_light_client_verifier::context::{
    ChainConsensusVerificationContext, Fraction, LightClientContext,
};
use ethereum_light_client_verifier::errors::Error::IrrelevantConsensusUpdates;
use ethereum_light_client_verifier::state::LightClientStoreReader;
use ethereum_light_client_verifier::updates::{ConsensusUpdate, ExecutionUpdate};
use optimism_ibc_proto::ibc::lightclients::ethereum::v1::{
    BeaconBlockHeader as ProtoBeaconBlockHeader, ConsensusUpdate as ProtoConsensusUpdate,
    ExecutionUpdate as ProtoExecutionUpdate, SyncAggregate as ProtoSyncAggregate,
    SyncCommittee as ProtoSyncCommittee,
};
use optimism_ibc_proto::ibc::lightclients::optimism::v1::L1Header as RawL1Header;

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
    ) -> impl ChainConsensusVerificationContext {
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
pub struct L1Consensus {
    pub slot: Slot,
    pub current_sync_committee: PublicKey,
    pub next_sync_committee: PublicKey,
}

impl L1Consensus {
    pub fn current_l1_period<C: ChainContext>(&self, ctx: &C) -> SyncCommitteePeriod {
        compute_sync_committee_period_at_slot(ctx, self.slot)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConsensusUpdateInfo<const SYNC_COMMITTEE_SIZE: usize> {
    /// Header attested to by the sync committee
    pub attested_header: BeaconBlockHeader,
    /// Next sync committee contained in `attested_header.state_root`
    /// 0: sync committee
    /// 1: branch indicating the next sync committee in the tree corresponding to `attested_header.state_root`
    pub next_sync_committee: Option<(SyncCommittee<SYNC_COMMITTEE_SIZE>, Vec<H256>)>,
    /// Finalized header contained in `attested_header.state_root`
    /// 0: header
    /// 1. branch indicating the header in the tree corresponding to `attested_header.state_root`
    pub finalized_header: (BeaconBlockHeader, Vec<H256>),
    /// Sync committee aggregate signature
    pub sync_aggregate: SyncAggregate<SYNC_COMMITTEE_SIZE>,
    /// Slot at which the aggregate signature was created (untrusted)
    pub signature_slot: Slot,
    /// Execution payload contained in the finalized beacon block's body
    pub finalized_execution_root: H256,
    /// Execution payload branch indicating the payload in the tree corresponding to the finalized block's body
    pub finalized_execution_branch: Vec<H256>,
}

impl<const SYNC_COMMITTEE_SIZE: usize> ConsensusUpdate<SYNC_COMMITTEE_SIZE>
    for ConsensusUpdateInfo<SYNC_COMMITTEE_SIZE>
{
    fn attested_beacon_header(&self) -> &BeaconBlockHeader {
        &self.attested_header
    }
    fn next_sync_committee(&self) -> Option<&SyncCommittee<SYNC_COMMITTEE_SIZE>> {
        self.next_sync_committee.as_ref().map(|c| &c.0)
    }
    fn next_sync_committee_branch(&self) -> Option<Vec<H256>> {
        self.next_sync_committee.as_ref().map(|c| c.1.to_vec())
    }
    fn finalized_beacon_header(&self) -> &BeaconBlockHeader {
        &self.finalized_header.0
    }
    fn finalized_beacon_header_branch(&self) -> Vec<H256> {
        self.finalized_header.1.to_vec()
    }
    fn finalized_execution_root(&self) -> H256 {
        self.finalized_execution_root
    }
    fn finalized_execution_branch(&self) -> Vec<H256> {
        self.finalized_execution_branch.to_vec()
    }
    fn sync_aggregate(&self) -> &SyncAggregate<SYNC_COMMITTEE_SIZE> {
        &self.sync_aggregate
    }
    fn signature_slot(&self) -> Slot {
        self.signature_slot
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExecutionUpdateInfo {
    /// State root of the execution payload
    pub state_root: H256,
    /// Branch indicating the state root in the tree corresponding to the execution payload
    pub state_root_branch: Vec<H256>,
    /// Block number of the execution payload
    pub block_number: U64,
    /// Branch indicating the block number in the tree corresponding to the execution payload
    pub block_number_branch: Vec<H256>,
    /// Block hash of the execution payload
    pub block_hash: H256,
    /// Branch indicating the block hash in the tree corresponding to the execution payload
    pub block_hash_branch: Vec<H256>,
}

impl ExecutionUpdate for ExecutionUpdateInfo {
    fn state_root(&self) -> H256 {
        self.state_root
    }

    fn state_root_branch(&self) -> Vec<H256> {
        self.state_root_branch.clone()
    }

    fn block_number(&self) -> U64 {
        self.block_number
    }

    fn block_number_branch(&self) -> Vec<H256> {
        self.block_number_branch.clone()
    }
}

#[derive(Clone, Debug)]
pub struct TrustedSyncCommittee<const SYNC_COMMITTEE_SIZE: usize> {
    pub sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
    pub is_next: bool,
}

#[derive(Clone, Debug)]
pub struct L1Header<const SYNC_COMMITTEE_SIZE: usize> {
    pub trusted_sync_committee: TrustedSyncCommittee<SYNC_COMMITTEE_SIZE>,
    pub consensus_update: ConsensusUpdateInfo<SYNC_COMMITTEE_SIZE>,
    pub execution_update: ExecutionUpdateInfo,
}

impl<const SYNC_COMMITTEE_SIZE: usize> L1Header<SYNC_COMMITTEE_SIZE> {
    pub fn verify(
        &self,
        now: u64,
        l1_config: &L1Config,
        consensus_state: &L1Consensus,
    ) -> Result<(bool, L1Consensus), Error> {
        let ctx = l1_config.build_context(now);

        let l1_sync_committee = L1SyncCommittee::new(
            consensus_state,
            self.trusted_sync_committee.sync_committee.clone(),
            self.trusted_sync_committee.is_next,
        )?;
        L1Verifier::default().verify(
            &ctx,
            &l1_sync_committee,
            &self.consensus_update,
            &self.execution_update,
        )?;
        apply_updates(&ctx, consensus_state, &self.consensus_update)
    }
}

impl<const SYNC_COMMITTEE_SIZE: usize> TryFrom<RawL1Header> for L1Header<SYNC_COMMITTEE_SIZE> {
    type Error = Error;

    fn try_from(value: RawL1Header) -> Result<Self, Self::Error> {
        let consensus_update = value
            .consensus_update
            .ok_or(Error::MissingL1ConsensusUpdate)?;
        let execution_update = value
            .execution_update
            .ok_or(Error::MissingL1ExecutionUpdate)?;
        let consensus_update = convert_proto_to_consensus_update(consensus_update)?;
        let execution_update = convert_proto_to_execution_update(execution_update);
        let trusted_sync_committee = value
            .trusted_sync_committee
            .ok_or(Error::MissingTrustedSyncCommittee)?;

        Ok(Self {
            trusted_sync_committee: TrustedSyncCommittee {
                sync_committee: convert_proto_to_sync_committee(
                    trusted_sync_committee.sync_committee,
                )?,
                is_next: trusted_sync_committee.is_next,
            },
            consensus_update,
            execution_update,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct L1SyncCommittee<const SYNC_COMMITTEE_SIZE: usize> {
    slot: Slot,
    next_sync_committee: Option<SyncCommittee<SYNC_COMMITTEE_SIZE>>,
    current_sync_committee: Option<SyncCommittee<SYNC_COMMITTEE_SIZE>>,
}

impl<const SYNC_COMMITTEE_SIZE: usize> L1SyncCommittee<SYNC_COMMITTEE_SIZE> {
    pub fn new(
        consensus_state: &L1Consensus,
        sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
        is_next: bool,
    ) -> Result<Self, Error> {
        sync_committee.validate().map_err(Error::L1ConsensusError)?;
        if !is_next {
            return if sync_committee.aggregate_pubkey == consensus_state.current_sync_committee {
                Ok(Self {
                    slot: consensus_state.slot,
                    current_sync_committee: Some(sync_committee),
                    next_sync_committee: None,
                })
            } else {
                Err(Error::UnexpectedCurrentSyncCommitteeKeys(
                    sync_committee.aggregate_pubkey,
                    consensus_state.current_sync_committee.clone(),
                ))
            };
        }

        if sync_committee.aggregate_pubkey == consensus_state.next_sync_committee {
            Ok(Self {
                slot: consensus_state.slot,
                current_sync_committee: None,
                next_sync_committee: Some(sync_committee),
            })
        } else {
            Err(Error::UnexpectedNextSyncCommitteeKeys(
                sync_committee.aggregate_pubkey,
                consensus_state.next_sync_committee.clone(),
            ))
        }
    }
}

#[derive(Default)]
pub struct L1Verifier<const SYNC_COMMITTEE_SIZE: usize> {
    consensus_verifier:
        SyncProtocolVerifier<SYNC_COMMITTEE_SIZE, L1SyncCommittee<SYNC_COMMITTEE_SIZE>>,
}

impl<const SYNC_COMMITTEE_SIZE: usize> L1Verifier<SYNC_COMMITTEE_SIZE> {
    pub fn verify<CC: ChainConsensusVerificationContext>(
        &self,
        ctx: &CC,
        l1_sync_committee: &L1SyncCommittee<SYNC_COMMITTEE_SIZE>,
        consensus_update: &ConsensusUpdateInfo<SYNC_COMMITTEE_SIZE>,
        execution_update: &ExecutionUpdateInfo,
    ) -> Result<(), Error> {
        // Same L1 validation as ethereum-ibc-rs
        self.consensus_verifier
            .validate_consensus_update(ctx, l1_sync_committee, consensus_update)
            .map_err(Error::L1VerifyConsensusUpdateError)?;
        let update_fork_spec =
            ctx.compute_fork_spec(consensus_update.finalized_beacon_header().slot);
        const BLOCK_NUMBER_TO_BLOCK_HASH_DIFF: u32 = 6;
        let execution_payload_block_hash_gindex = update_fork_spec
            .execution_payload_block_number_gindex
            + BLOCK_NUMBER_TO_BLOCK_HASH_DIFF;
        let trusted_execution_root = consensus_update.finalized_execution_root();
        self.consensus_verifier
            .validate_execution_update(update_fork_spec, trusted_execution_root, execution_update)
            .map_err(Error::L1VerifyExecutionUpdateError)?;

        // Ensure valid l1 block hash because L2 derivation requires it.
        is_valid_normalized_merkle_branch(
            hash_tree_root(execution_update.block_hash)
                .unwrap()
                .0
                .into(),
            &execution_update.block_hash_branch,
            execution_payload_block_hash_gindex,
            trusted_execution_root,
        )
        .map_err(Error::InvalidExecutionBlockHashMerkleBranch)?;

        Ok(())
    }
}

impl<const SYNC_COMMITTEE_SIZE: usize> LightClientStoreReader<SYNC_COMMITTEE_SIZE>
    for L1SyncCommittee<SYNC_COMMITTEE_SIZE>
{
    fn current_period<CC: ChainContext>(&self, ctx: &CC) -> SyncCommitteePeriod {
        compute_sync_committee_period_at_slot(ctx, self.slot)
    }

    fn current_sync_committee(&self) -> Option<SyncCommittee<SYNC_COMMITTEE_SIZE>> {
        self.current_sync_committee.clone()
    }

    fn next_sync_committee(&self) -> Option<SyncCommittee<SYNC_COMMITTEE_SIZE>> {
        self.next_sync_committee.clone()
    }

    fn ensure_relevant_update<CC: ChainContext, C: ConsensusUpdate<SYNC_COMMITTEE_SIZE>>(
        &self,
        _ctx: &CC,
        update: &C,
    ) -> Result<(), ethereum_light_client_verifier::errors::Error> {
        // L2 is shorter than L1, so it is possible that only L2 is different and L1 is in the same slot.
        if self.slot > update.finalized_beacon_header().slot {
            Err(IrrelevantConsensusUpdates(
                "finalized header slot is not greater than or equal to current slot".to_string(),
            ))
        } else {
            Ok(())
        }
    }
}

fn convert_proto_to_header(header: &ProtoBeaconBlockHeader) -> Result<BeaconBlockHeader, Error> {
    Ok(BeaconBlockHeader {
        slot: header.slot.into(),
        proposer_index: header.proposer_index.into(),
        parent_root: H256::from_slice(&header.parent_root),
        state_root: H256::from_slice(&header.state_root),
        body_root: H256::from_slice(&header.body_root),
    })
}

pub fn convert_proto_to_execution_update(
    execution_update: ProtoExecutionUpdate,
) -> ExecutionUpdateInfo {
    ExecutionUpdateInfo {
        state_root: H256::from_slice(&execution_update.state_root),
        state_root_branch: execution_update
            .state_root_branch
            .into_iter()
            .map(|n| H256::from_slice(&n))
            .collect(),
        block_number: execution_update.block_number.into(),
        block_number_branch: execution_update
            .block_number_branch
            .into_iter()
            .map(|n| H256::from_slice(&n))
            .collect(),
        block_hash: H256::from_slice(&execution_update.block_hash),
        block_hash_branch: execution_update
            .block_hash_branch
            .into_iter()
            .map(|n| H256::from_slice(&n))
            .collect(),
    }
}

fn convert_proto_sync_aggregate<const SYNC_COMMITTEE_SIZE: usize>(
    sync_aggregate: ProtoSyncAggregate,
) -> Result<SyncAggregate<SYNC_COMMITTEE_SIZE>, Error> {
    Ok(SyncAggregate {
        sync_committee_bits: Bitvector::<SYNC_COMMITTEE_SIZE>::deserialize(
            sync_aggregate.sync_committee_bits.as_slice(),
        )
        .map_err(|e| Error::DeserializeSyncCommitteeBitsError {
            parent: e,
            sync_committee_size: SYNC_COMMITTEE_SIZE,
            sync_committee_bits: sync_aggregate.sync_committee_bits,
        })?,
        sync_committee_signature: Signature::try_from(sync_aggregate.sync_committee_signature)
            .map_err(Error::L1ConsensusError)?,
    })
}

fn convert_proto_to_consensus_update<const SYNC_COMMITTEE_SIZE: usize>(
    consensus_update: ProtoConsensusUpdate,
) -> Result<ConsensusUpdateInfo<SYNC_COMMITTEE_SIZE>, Error> {
    let attested_header = convert_proto_to_header(
        consensus_update
            .attested_header
            .as_ref()
            .ok_or(Error::proto_missing("attested_header"))?,
    )?;
    let finalized_header = convert_proto_to_header(
        consensus_update
            .finalized_header
            .as_ref()
            .ok_or(Error::proto_missing("finalized_header"))?,
    )?;

    let finalized_execution_branch = consensus_update
        .finalized_execution_branch
        .into_iter()
        .map(|b| H256::from_slice(&b))
        .collect::<Vec<H256>>();
    let consensus_update = ConsensusUpdateInfo {
        attested_header,
        next_sync_committee: if consensus_update.next_sync_committee.is_none()
            || consensus_update
                .next_sync_committee
                .as_ref()
                .ok_or(Error::proto_missing("next_sync_committee"))?
                .pubkeys
                .is_empty()
            || consensus_update.next_sync_committee_branch.is_empty()
        {
            None
        } else {
            Some((
                convert_proto_to_sync_committee(consensus_update.next_sync_committee)?,
                decode_branch(consensus_update.next_sync_committee_branch),
            ))
        },
        finalized_header: (
            finalized_header,
            decode_branch(consensus_update.finalized_header_branch),
        ),
        sync_aggregate: convert_proto_sync_aggregate(
            consensus_update
                .sync_aggregate
                .ok_or(Error::proto_missing("sync_aggregate"))?,
        )?,
        signature_slot: consensus_update.signature_slot.into(),
        finalized_execution_root: H256::from_slice(&consensus_update.finalized_execution_root),
        finalized_execution_branch,
    };
    Ok(consensus_update)
}

fn decode_branch(bz: Vec<Vec<u8>>) -> Vec<H256> {
    bz.into_iter().map(|b| H256::from_slice(&b)).collect()
}

fn convert_proto_to_sync_committee<const SYNC_COMMITTEE_SIZE: usize>(
    sync_committee: Option<ProtoSyncCommittee>,
) -> Result<SyncCommittee<SYNC_COMMITTEE_SIZE>, Error> {
    let sync_committee = SyncCommittee {
        pubkeys: Vector::<PublicKey, SYNC_COMMITTEE_SIZE>::from_iter(
            sync_committee
                .clone()
                .ok_or(Error::proto_missing("next_sync_committee"))?
                .pubkeys
                .into_iter()
                .map(|pk| pk.try_into())
                .collect::<Result<Vec<PublicKey>, _>>()
                .map_err(Error::L1ConsensusError)?,
        ),
        aggregate_pubkey: PublicKey::try_from(
            sync_committee
                .ok_or(Error::proto_missing("next_sync_committee"))?
                .aggregate_pubkey,
        )
        .map_err(Error::L1ConsensusError)?,
    };
    Ok(sync_committee)
}

fn apply_updates<const SYNC_COMMITTEE_SIZE: usize, CC: ChainConsensusVerificationContext>(
    ctx: &CC,
    consensus_state: &L1Consensus,
    consensus_update: &ConsensusUpdateInfo<SYNC_COMMITTEE_SIZE>,
) -> Result<(bool, L1Consensus), Error> {
    let store_period = consensus_state.current_l1_period(ctx);
    let update_finalized_slot = consensus_update.finalized_header.0.slot;
    let update_finalized_period = compute_sync_committee_period_at_slot(ctx, update_finalized_slot);

    // Let `store_period` be the period of the current sync committe of the consensus state, then the state transition is the following:
    // - If `store_period == update_finalized_period`, then the new consensus state will have the same sync committee info as the current consensus state.
    // - If `store_period + 1 == update_finalized_period`, then the new consensus state will have the current sync committee as the next sync committee of the current consensus state,
    //   and the next sync committee of the new consensus state will be the next sync committee of the update.
    if store_period == update_finalized_period {
        // store_period == finalized_period <= attested_period <= signature_period
        Ok((
            false,
            L1Consensus {
                slot: update_finalized_slot,
                current_sync_committee: consensus_state.current_sync_committee.clone(),
                next_sync_committee: consensus_state.next_sync_committee.clone(),
            },
        ))
    } else if store_period + 1 == update_finalized_period {
        // store_period + 1 == finalized_period == attested_period == signature_period
        // Why `finalized_period == attested_period == signature_period` here?
        // Because our store only have the current or next sync committee info, so the verified update's signature period must match the `store_period + 1` here.
        if let Some((update_next_sync_committee, _)) = &consensus_update.next_sync_committee {
            Ok((
                true,
                L1Consensus {
                    slot: update_finalized_slot,
                    current_sync_committee: consensus_state.next_sync_committee.clone(),
                    next_sync_committee: update_next_sync_committee.aggregate_pubkey.clone(),
                },
            ))
        } else {
            // Relayers must submit an update that contains the next sync committee if the update period is `store_period + 1`.
            Err(Error::NoNextSyncCommitteeInConsensusUpdate(
                store_period,
                update_finalized_period,
            ))
        }
    } else {
        // store_period + 1 < update_finalized_period or store_period > update_finalized_period
        // The store(=consensus state) cannot apply such updates here because the current or next sync committee corresponding to the `finalized_period` is unknown.
        Err(Error::StoreNotSupportedFinalizedPeriod(
            store_period,
            update_finalized_period,
        ))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::errors::Error;
    use crate::l1::{apply_updates, L1Config, L1Consensus, L1Header};
    use alloc::vec::Vec;
    use alloc::{format, vec};
    use alloy_primitives::hex;
    use ethereum_consensus::bls::PublicKey;
    use ethereum_consensus::types::H256;
    use optimism_ibc_proto::ibc::lightclients::optimism::v1::L1Config as RawL1Config;
    use optimism_ibc_proto::ibc::lightclients::optimism::v1::L1Header as RawL1Header;
    use prost::Message;

    pub fn get_l1_config() -> L1Config {
        // created by optimism-ibc-relay-prover
        let raw_l1_config = hex!("0a20acac7566fdf384a1ada45c01dcf9030d7eb0e1e5f5302659101d0b2a5bb590921001188edaa3bc06225e0a0400000001120e0a04010000011a0608691036183712160a04020000011a0e086910361837201928123016381c12160a04030000011a0e086910361837201928123016381c12160a04040000011a0e086910361837201928223026382c280630083808420408021003").to_vec();
        let raw_l1_config = RawL1Config::decode(&*raw_l1_config).unwrap();
        L1Config::try_from(raw_l1_config).unwrap()
    }

    pub fn get_raw_l1_header() -> RawL1Header {
        let raw_l1_header = hex!("0af90c0a02100112f20c0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b123082c0c49d5142e3f5a7340864440c61787b6741271e4ce2a21114f137a693fc4484582aee2ebbb9c6d9f9ebdae7ff73f712b6050a6808381a20211f5aa7d922e93c1866f1c0cea8fc6a771de065e5bae671c1ae0c3bade1dfae222001a6be88c2c4b4b47674808d339d7a40e8328770a0ff2104bef5551653f85f9b2a20221bdee3a03565f7f3660799694a42d8bf2a0a77152d005f8cc1cdc9747a1292226808281a203e333f3e0377a391e944c0abb605355186f9e2dca1f072be784eb3b9561f0bac2220bc1834d65587e9ae23bb5fbadeaabfd7196fab3bc21f7fee3147e4bdedc048172a20348b6124434d34a85922c835eaad38e97a1e86cebadd1ba09307077a9ad8564c2a2005000000000000000000000000000000000000000000000000000000000000002a2086220a2d72000ffb901cf75bf2918181ffea3c6567a573566d8c826e9e5674932a20f4447f38c2291142c79b90629719f2ca6f899d72623a05551eb5731fccce6d272a201e3be659143306ea1af4e87a0ced83d21a93175380c0f106d71cdb41a27c8a442a206448f99e044fe7896fab91ebd5d2b51e0628af1ff7446c5f6de0f9b47fe869562a203943159d5221c2d92c003a4441f78b14a17f46777119116263db1e3f9d15b1cc3220a422efdd16d3379f8faa1a04617ddf4cb8112334bbbc148bda3116bea01f99943a2005d2733d4658d1b357176e6e3666046e7d0f326fff6c9967fdaaf8cbf628c83c3a206c6dd63656639d153a2e86a9cab291e7a26e957ad635fec872d2836e92340c233a20db56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d713a2056802d0e20a661fab06aee2430b2d1f16e39090d6811137f2056d60323b1128242680a04ffffffff126092966f72e3b27c6a44d414c4d25ab5b60468cb0c41322377df21316d6829493dad6dedd05d21e3dc9eabf309c724ff2f0c432e6aa55b1712b8f186da84693da5d45a25019ab47db5ac7bdcff35749251d0f435423efea41d2649411f4cf8101c48391ac4040a2058fd4c8a5ddb802fc96d150aa2ae07d0b7cad4cdba820c240ef38f8923da59a9122056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b42112206a3cd137c4f65bde80892d5961b88bb7fd65ab2772f1a5c5dc909cfb6344d46212201bff56a7614f088770cc2adfe4beedabb8f20d725c40f504f1f30519c162b6c312209b7307f296f6cfe8e150341ba34163c397e16bf3fb887a365529cd94cc7d669c1220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c18282220ccea95040000000000000000000000000000000000000000000000000000000022201d3dd666c554e0b19d1911c7da8b2de157e3f9863a85e3e89e01846a2be535272220f6d24b9fc4a2cad9cd9fcfb1824e28717e8a0856e5704a523c135fd64f08692f22209b7307f296f6cfe8e150341ba34163c397e16bf3fb887a365529cd94cc7d669c2220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c2a205c0374e27beeb58b392ff4d0f61dd52f9827a5de34a5cbb8118cd9b7b3de4dea32207ffe241ea60187fdb0187bfa22de35d1f9bed7ab061d9401fd47e34a54fbede132207d00409ac38e3a99bc86c045f570dea66e115ba1d767d89c9e7f82901dfcfd88322047b868e6a4896c7843750c34cfb5e9c7a3473d5ef4b8d4b3984e182d4077390d3220f5e2b63eaf1d0292bf32b428c539f64875393ed483d0b5ad73fea0c301900edb3220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c").to_vec();
        RawL1Header::decode(&*raw_l1_header).unwrap()
    }

    pub fn get_l1_header(
    ) -> L1Header<{ ethereum_consensus::preset::minimal::PRESET.SYNC_COMMITTEE_SIZE }> {
        // created by optimism-ibc-relay-prover
        let raw_l1_header = get_raw_l1_header();
        let l1_header = L1Header::<
            { ethereum_consensus::preset::minimal::PRESET.SYNC_COMMITTEE_SIZE },
        >::try_from(raw_l1_header.clone())
        .unwrap();
        l1_header
    }

    pub fn get_l1_consensus() -> L1Consensus {
        // created by optimism-ibc-relay-prover
        L1Consensus {
            slot: 39.into(),
            current_sync_committee: PublicKey::try_from(hex!("82c0c49d5142e3f5a7340864440c61787b6741271e4ce2a21114f137a693fc4484582aee2ebbb9c6d9f9ebdae7ff73f7").to_vec()).unwrap(),
            next_sync_committee: PublicKey::default()
        }
    }

    pub fn get_time() -> u64 {
        1737027212
    }

    #[test]
    pub fn test_l1_header_verify_error_current() {
        let l1_config = get_l1_config();
        let l1_header = get_l1_header();
        let mut cons_state = get_l1_consensus();
        cons_state.current_sync_committee = PublicKey::default();

        let err = l1_header
            .verify(get_time(), &l1_config, &cons_state)
            .unwrap_err();
        match err {
            Error::UnexpectedCurrentSyncCommitteeKeys(_, _) => {}
            _ => panic!("Unexpected error: {:?}", err),
        }
    }

    #[test]
    pub fn test_l1_header_verify_error_next() {
        let l1_config = get_l1_config();
        let mut l1_header = get_l1_header();
        l1_header.trusted_sync_committee.is_next = true;

        let mut cons_state = get_l1_consensus();
        cons_state.next_sync_committee = PublicKey::default();

        let err = l1_header
            .verify(get_time(), &l1_config, &cons_state)
            .unwrap_err();
        match err {
            Error::UnexpectedNextSyncCommitteeKeys(_, _) => {}
            _ => panic!("Unexpected error: {:?}", err),
        }
    }

    #[test]
    pub fn test_l1_header_verify_error_consensus_update() {
        let l1_config = get_l1_config();
        let mut l1_header = get_l1_header();
        let cons_state = get_l1_consensus();

        l1_header.consensus_update.signature_slot = 10000.into();

        let err = l1_header
            .verify(get_time(), &l1_config, &cons_state)
            .unwrap_err();
        match err {
            Error::L1VerifyConsensusUpdateError(e) => {
                assert!(
                    format!("{:?}", e).contains("InconsistentSlotOrder"),
                    "Err {:?}",
                    e
                );
            }
            _ => panic!("Unexpected error: {:?}", err),
        }
    }

    #[test]
    pub fn test_l1_header_verify_error_execution_update() {
        let l1_config = get_l1_config();
        let mut l1_header = get_l1_header();
        let cons_state = get_l1_consensus();

        l1_header.execution_update.state_root_branch[0] = H256([0; 32]);

        let err = l1_header
            .verify(get_time(), &l1_config, &cons_state)
            .unwrap_err();
        match err {
            Error::L1VerifyExecutionUpdateError(e) => {
                assert!(
                    format!("{:?}", e).contains("InvalidExecutionStateRootMerkleBranch"),
                    "Err {:?}",
                    e
                );
            }
            _ => panic!("Unexpected error: {:?}", err),
        }
    }

    #[test]
    pub fn test_l1_header_verify_error_l1_block_hash() {
        let l1_config = get_l1_config();
        let mut l1_header = get_l1_header();
        let cons_state = get_l1_consensus();

        l1_header.execution_update.block_hash_branch[0] = H256([0; 32]);

        let err = l1_header
            .verify(get_time(), &l1_config, &cons_state)
            .unwrap_err();
        match err {
            Error::InvalidExecutionBlockHashMerkleBranch(_) => {}
            _ => panic!("Unexpected error: {:?}", err),
        }
    }

    #[test]
    pub fn test_l1_header_apply_update_error_not_adjacent_period() {
        let l1_config = get_l1_config();
        let cons_state = get_l1_consensus();
        let mut l1_header = get_l1_header();
        l1_header.consensus_update.finalized_header.0.slot = 10000.into();

        let err = apply_updates(
            &l1_config.build_context(get_time()),
            &cons_state,
            &l1_header.consensus_update,
        )
        .unwrap_err();
        match err {
            Error::StoreNotSupportedFinalizedPeriod(_, _) => {}
            _ => panic!("Unexpected error: {:?}", err),
        }
    }

    #[test]
    pub fn test_l1_header_apply_update_error_no_next_sync_committee() {
        let ctx = get_l1_config().build_context(get_time());
        let cons_state = get_l1_consensus();
        let mut l1_header = get_l1_header();
        l1_header.consensus_update.finalized_header.0.slot =
            (l1_header.consensus_update.finalized_header.0.slot + 32).into();
        l1_header.consensus_update.next_sync_committee = None;

        let err = apply_updates(&ctx, &cons_state, &l1_header.consensus_update).unwrap_err();
        match err {
            Error::NoNextSyncCommitteeInConsensusUpdate(_, _) => {}
            _ => panic!("Unexpected error: {:?}", err),
        }
    }

    #[test]
    pub fn test_l1_header_verify_success_same_period() {
        let l1_config = get_l1_config();
        let l1_header = get_l1_header();
        let cons_state = get_l1_consensus();
        let (_, l1_consensus) = l1_header
            .verify(get_time(), &l1_config, &cons_state)
            .unwrap();
        // same period : cons_state period == finalized_period
        assert_eq!(
            l1_consensus.slot,
            l1_header.consensus_update.finalized_header.0.slot
        );
        assert_eq!(
            l1_consensus.current_sync_committee,
            cons_state.current_sync_committee
        );
        assert_eq!(
            l1_consensus.next_sync_committee,
            cons_state.next_sync_committee
        );
    }

    struct TestCase {
        raw_l1_header: Vec<u8>,
        cons_slot: u64,
        cons_l1_current_sync_committee: PublicKey,
        cons_l1_next_sync_committee: PublicKey,
    }
    #[test]
    pub fn test_l1_header_verify_success_multi_period() {
        let l1_config = get_l1_config();

        let cases = vec![TestCase {
            raw_l1_header: hex!("0afb0c0a02100112f20c0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e123082c0c49d5142e3f5a7340864440c61787b6741271e4ce2a21114f137a693fc4484582aee2ebbb9c6d9f9ebdae7ff73f7180112dc130a6b08d00210021a2091b67171fa3464b6a7d0dc5c7eca05a6adbc9a33e42aa44ec77cf99fb0a5fc3a22208c63ffc183a5ecd183b8a12e39418b373d7667c963299a9b7d093d8b95cf8d532a203bbe5b6f6cb4ae24f89c61618131fe885c2a1d0c41b25c7efe788f99ed7403ba12f20c0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b123082c0c49d5142e3f5a7340864440c61787b6741271e4ce2a21114f137a693fc4484582aee2ebbb9c6d9f9ebdae7ff73f71a2070d228fb4a5adbd18ac57591ce5bc052bdb243d704a771209c0d745a91a04f6b1a2023802c2ddf941a32e514ee3a513d55312ef1019768cebfe28653c41eaa2fcba21a2077a5e4c669dc2c8d345f2968120454df50cb39ccf8dcc75a4e2d206a2a6762911a20854d01646e1db4e7d437832c22c0517a6354d62c63dbbbecf9ff56789d2f7ec31a20ac2a6481a077a5f8f4472f4190ca498a3fd4a043744e392161781c03a385a7c2226b08c00210021a20a56b23921a15c9e24de67d483a832d98615101f0755deec16358c1e2cff59b8622209d79fde7c7ee282871b577ffdd7d9c2ab05887e7f3a81a0b4af01a484c53b4712a20c4ce13a9003145a76da2f4e50470d77ff9fda87dd8bcb0c3e1307ed0d6ebf10b2a2028000000000000000000000000000000000000000000000000000000000000002a2086220a2d72000ffb901cf75bf2918181ffea3c6567a573566d8c826e9e5674932a208c8fa1c1fec22f21cb869eda077eb82a2fb543b28781ffe878a62b78019d8c882a2077a5e4c669dc2c8d345f2968120454df50cb39ccf8dcc75a4e2d206a2a6762912a20854d01646e1db4e7d437832c22c0517a6354d62c63dbbbecf9ff56789d2f7ec32a20ac2a6481a077a5f8f4472f4190ca498a3fd4a043744e392161781c03a385a7c2322040edaa30d96cb3ed867d02427ea26b32f7e0bb3af595845f17a5a077b5ddf6a63a20411e2a7d58f1a4972d6c0254e0f9854921043b28d0833277692ced7d71fe1f633a206c6dd63656639d153a2e86a9cab291e7a26e957ad635fec872d2836e92340c233a20db56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d713a20eedc1bd02d9e794ec32bbe28902ac99c6a7b18500424f155a68043eed89f361e42680a04ffffffff1260b97f202f6aa7da670b2d6e0b17f9150c5d6d2053635c70978f006055739a4bb939674d4a5eb314ce30cc590425c62f2d00d7fe60c2a9251196ac23818e4d4b4516a1abf46e1040f873777bc91a71790579a4c7aeb58b6f7db71d4d23b26c9c3d48d1021ac5040a2058fd4c8a5ddb802fc96d150aa2ae07d0b7cad4cdba820c240ef38f8923da59a9122056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421122033a45b3fd42421d76fbf4f1477d11f5e85450fd6808c928d08f5551c9c298ec812208a0ac0bbd625dd44d8ade5a7694c7a2d3dc407e9e59d9a4784cf389bd45aa7711220e10e6b84c9942f53430eaf44e71668db4b32dce878572f409b8776fd0260de831220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c18c002222090f47c03000000000000000000000000000000000000000000000000000000002220da3c5ff59d67af3f2053bc6f4efebe7280ae44d937a2932cc0f7b45680d932182220486057b85b65a3eef61eaf8a35b3d89068857b19863879cca8d8300a7e4f0b132220e10e6b84c9942f53430eaf44e71668db4b32dce878572f409b8776fd0260de832220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c2a2086ea4283bac33d355ae5683201ed6b29e97a1eb1f5340bd03ac5c16656f3a31932207ffe241ea60187fdb0187bfa22de35d1f9bed7ab061d9401fd47e34a54fbede132207d00409ac38e3a99bc86c045f570dea66e115ba1d767d89c9e7f82901dfcfd883220e7081985a48bf1e07712723e0fa06addd971da068cac57c3d8e1e5253c31c8cc322096c93cc7244782f7edc3a03dc4ddf291372f14e45c9f1b2240a46b8fade529533220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c").to_vec(),
            cons_slot: 281,
            cons_l1_current_sync_committee: PublicKey::default(),
            cons_l1_next_sync_committee: PublicKey::try_from(hex!("82c0c49d5142e3f5a7340864440c61787b6741271e4ce2a21114f137a693fc4484582aee2ebbb9c6d9f9ebdae7ff73f7").to_vec()).unwrap(),
        },TestCase {
            raw_l1_header: hex!("0afb0c0a02100112f20c0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b123082c0c49d5142e3f5a7340864440c61787b6741271e4ce2a21114f137a693fc4484582aee2ebbb9c6d9f9ebdae7ff73f7180112dc130a6b08900310031a20625d03237700c328c56704872d6a824a9180ad301c4ee042ab8feefefefc6b4f2220e5e83fe943067c7eea558f167b187060d629322f2f598aaa8e7a8fdf24f810102a201f3a343733cb8e26e0d890d0b8896494692cd45ee5c1198023c87332ae6a3f7d12f20c0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b123082c0c49d5142e3f5a7340864440c61787b6741271e4ce2a21114f137a693fc4484582aee2ebbb9c6d9f9ebdae7ff73f71a20ff94b0f1d6f6309d2572b59e2e13643673962f5ac255c3c5dabc9f07e909f0d51a200fba5b3180d77477729e9d9226cf7507e8bb919f1c53fbf891133dfbf02dcbd41a209f45ec3677b61f5d37951e1cfd93031a9e8e1ef3bb0564133edbc3e932396fa11a207f56aeea000301e37566fd2cc66d8e959f5e137a9ab35ea8573f0d99866d27bd1a207165681691e02f2417f62329eadf9d97ebd60c1d7478a18e91773a195f0371b8226b08800310021a20b9253f7138ff938a47deba94cd3ef19d270e36484ef9da0174adde3e756094162220b18ef6c5dbe3b65eaee670e86df61738b44359ce4d5f2dc41764841c23e39e492a203a5a0051f80325effe0786b185e1cfb0032f5f46d4f781460e036fa978b853422a2030000000000000000000000000000000000000000000000000000000000000002a2086220a2d72000ffb901cf75bf2918181ffea3c6567a573566d8c826e9e5674932a20cada9b1dac0806d6e8d891f2ab5ee3b28ab1a8765194dd9e82a7bf2347c91abd2a209f45ec3677b61f5d37951e1cfd93031a9e8e1ef3bb0564133edbc3e932396fa12a207f56aeea000301e37566fd2cc66d8e959f5e137a9ab35ea8573f0d99866d27bd2a207165681691e02f2417f62329eadf9d97ebd60c1d7478a18e91773a195f0371b83220050edc3ddb4789b81f25f0e36f31330147d0f9a88f05cb6ddd0bf8d0888336ac3a207139b9d87e635a9f8e1707c978f2da4871381d13f841f2acba01ebae83f0f5533a206c6dd63656639d153a2e86a9cab291e7a26e957ad635fec872d2836e92340c233a20db56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d713a20ded52e29e4dac81a6b8f6d16c745d3b5bb5ff2c2ef2a42581d8095f13fe3d1d742680a04ffffffff12608afd7ed857a1835f17d68c0c7c95ae3c8579139e96c340b4116068b9fe7d322dc9002c8fe1b0984e0c67eddcb84ae45612456c269769ad7af2a86725c46116848ab36b396a59e248b82eef8a31c558d47a15ee336712e3586b8e3e4f4399caad4891031ac5040a2058fd4c8a5ddb802fc96d150aa2ae07d0b7cad4cdba820c240ef38f8923da59a9122056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b42112203c85298c330e149337beee76b3c534812013d76b1ef91a712d69a13dfc78939e1220b54093b672c6a7bacd6a96ec621738968e66a20fb03b9f45950cbfcb8fc6e5a0122013433310e3b849a5811f6447191ba1b210b52d9f33c04d2089339f168658e79a1220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c188003222067d44603000000000000000000000000000000000000000000000000000000002220da65e920b3999323f09453b7418fa59635ae45427eb9b2f1b2d3bf232e23cc72222006941e708d0f3fc35dc6a43e77f73b7c6507f941c8b9fb3cce05c5bc04d49d33222013433310e3b849a5811f6447191ba1b210b52d9f33c04d2089339f168658e79a2220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c2a20a9d15829734620a4b66fa539ce98cee62a2d51f6c51349e3d5f125bc0ee93bf832207ffe241ea60187fdb0187bfa22de35d1f9bed7ab061d9401fd47e34a54fbede132207d00409ac38e3a99bc86c045f570dea66e115ba1d767d89c9e7f82901dfcfd883220bc6404925be7af110f69db0c700a9f0a5602afbd85338664d5481859690736b03220ca5301132d885efc5edd1e222cd4ff3754388c5ea0d60d53fe5447b87e58fdc43220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c").to_vec(),
            cons_slot: 320,
            cons_l1_current_sync_committee: PublicKey::try_from(hex!("82c0c49d5142e3f5a7340864440c61787b6741271e4ce2a21114f137a693fc4484582aee2ebbb9c6d9f9ebdae7ff73f7").to_vec()).unwrap(),
            cons_l1_next_sync_committee: PublicKey::try_from(hex!("82c0c49d5142e3f5a7340864440c61787b6741271e4ce2a21114f137a693fc4484582aee2ebbb9c6d9f9ebdae7ff73f7").to_vec()).unwrap(),
        }, TestCase {
            raw_l1_header: hex!("0afb0c0a02100112f20c0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b123082c0c49d5142e3f5a7340864440c61787b6741271e4ce2a21114f137a693fc4484582aee2ebbb9c6d9f9ebdae7ff73f7180112dc130a6b08d00310021a201897170c0d79ca5d91dd52dd645d5b354f5dcf6dd2139fce725d32149062d7bf2220333645920cb53a38c148510c719bb2fbaf19b61f5693015c9b5c6909029edd732a20ddea244b3c3fb12df3f33cc8e71d3f71bbfbcf5901a3ccc9ebc3e864c571a02d12f20c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b123082c0c49d5142e3f5a7340864440c61787b6741271e4ce2a21114f137a693fc4484582aee2ebbb9c6d9f9ebdae7ff73f71a20c713c04d75b73ee182f71471d47a772cf33b0d253812768739ba366c1df7c29d1a20f0499aaeaa03a4d6ec5c99fd4ce1bae2d88e6a0250cf4501d3decd68c74497ce1a2067941e451077892c24bfedd8e95c3862e9e5240c7d6e2c750cfce5b94d17f37e1a207bf88288e04c968e51232591125693683ae0a7d84ddab0fa25263b6f0cdeb7cd1a206e52f23a6e03a83f6c5a6e5c323d5a57aa394edd86bb1102a1307e94b8f68547226b08c00310011a203e5a75da025f94cadcb2f294837e8e53bfc245669c5319b996c26b37feaa5b852220c4787344ad06dc02062c2ff05074db8cd2bbcd9f1d894227fd43c4b0249cefe12a206489c82605c009de679cc8adfd66faa38990689036e3077a507086858636cedb2a2038000000000000000000000000000000000000000000000000000000000000002a2086220a2d72000ffb901cf75bf2918181ffea3c6567a573566d8c826e9e5674932a202f754a25129813e7ad3c40cbfde800d39cd30ce49f3a8a1bbfd2fc2575aaac6a2a2067941e451077892c24bfedd8e95c3862e9e5240c7d6e2c750cfce5b94d17f37e2a207bf88288e04c968e51232591125693683ae0a7d84ddab0fa25263b6f0cdeb7cd2a206e52f23a6e03a83f6c5a6e5c323d5a57aa394edd86bb1102a1307e94b8f685473220c3fd3fb9669ecdb7483688f286a8789af4fd1befeab310e5c27ab74e846291353a20b9949f3a3219c01992a8c017547406dceb8957fb6edc3ca8b0ea5702e9afd2213a206c6dd63656639d153a2e86a9cab291e7a26e957ad635fec872d2836e92340c233a20db56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d713a201f033787460209b16263c5928844905ce9ae3a9d82f6bbd5cd5aa652d89b921342680a04ffffffff1260a821dff37c10293603ab0047988907a7e274acd07811d961a0dede38bb17b8bc1f38738e9f45f58093033ad91c68d1031069d2883477d09b21cf656f56341d8b89b102a25d3fc56499bc06674743aeac3a2898416d04c9e6e685648fd0f42b7248d1031ac5040a2058fd4c8a5ddb802fc96d150aa2ae07d0b7cad4cdba820c240ef38f8923da59a9122056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b42112200d01c908b5e0df3ec65167c3688781d7b0e01804cfb5ac3dde21c4fd1dc0c92612204726964a4e86c01e61ddc4297ae0cb95e7bef7e5f2482d74453691e8e1df221c12206720ba4c1df4cd52c0be4a0bf49a1e469e33eab9dbaa40e44f245aafb7b20f9e1220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c18c003222024fc1303000000000000000000000000000000000000000000000000000000002220f2fccfd9f03664174179dc0ca8a5ebb3ec7ce5601a06050e56bf9aa61341ea212220a44c3f559b4bfabf3d5f0863938fd25c3f36e5b4a78f0a0660a6b0574cb69f7c22206720ba4c1df4cd52c0be4a0bf49a1e469e33eab9dbaa40e44f245aafb7b20f9e2220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c2a20cd9b13beba5602dc185b690ee9c0cc78f22ad2fae26f0dd3d9af3f2b79ce56b032207ffe241ea60187fdb0187bfa22de35d1f9bed7ab061d9401fd47e34a54fbede132207d00409ac38e3a99bc86c045f570dea66e115ba1d767d89c9e7f82901dfcfd883220612750659879dc1f0c4d06267e6a3fe95057027fd23faf32390f5800743168ba3220c500b9ea9e199ce93532ecdfe8c522313382c75a74d2201d5602d31af064ad433220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c").to_vec(),
            cons_slot: 384,
            cons_l1_current_sync_committee: PublicKey::try_from(hex!("82c0c49d5142e3f5a7340864440c61787b6741271e4ce2a21114f137a693fc4484582aee2ebbb9c6d9f9ebdae7ff73f7").to_vec()).unwrap(),
            cons_l1_next_sync_committee: PublicKey::try_from(hex!("82c0c49d5142e3f5a7340864440c61787b6741271e4ce2a21114f137a693fc4484582aee2ebbb9c6d9f9ebdae7ff73f7").to_vec()).unwrap(),
        },TestCase {
            raw_l1_header: hex!("0af90c0a02100112f20c0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b123082c0c49d5142e3f5a7340864440c61787b6741271e4ce2a21114f137a693fc4484582aee2ebbb9c6d9f9ebdae7ff73f712b9050a6908d8031a2088b3b45961405dbb80801febb647dc5f4db0ab073aba83a2d29c74006b3aabce2220e3867a7fb4e39c70b7be46896db77af4a8026ac279aa89a41d7844823875e8ba2a2017a31cc0d8b0a23b55a5ff290d0ace6f21591f02549da6016678c70189205b18226908c8031a2061af118257ecc9d081294bc73977c485768b3c40acc36cd74d0a3a7048ed020a2220ae054af30d5a651101a9caee6ddfd960984203fb14ebc5e284335cc31db9adaa2a208be64cf95fdfddcea0ac2997dfde571caacbe4a2995179874ab6917652a38b172a2039000000000000000000000000000000000000000000000000000000000000002a2086220a2d72000ffb901cf75bf2918181ffea3c6567a573566d8c826e9e5674932a202f754a25129813e7ad3c40cbfde800d39cd30ce49f3a8a1bbfd2fc2575aaac6a2a2034e1d4fad96b06a9d127a65c2548d162ac8863eadbaaa123f510f51cb46306b12a20d1f3ba68f2c284db49b26d6839d1cf2ff3352bfdf58882acd774a62c379f12512a20b399c8661da4d9e9dbd7cc289bb50d6484f7edc93f0f781ec86def9c5742cbac3220ea20d0454bcb449a1fef9c867616f2d71c3f435e4386351dde30fb580c7a0cd63a205efdfcb9b162ea14e57996a90071da44f522bc8d48654bc788e278916a8996033a206c6dd63656639d153a2e86a9cab291e7a26e957ad635fec872d2836e92340c233a20db56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d713a20468984047047f24ef8bb10933341aa89b3e389f6e21e2538ec34c74a10ccc57642680a04ffffffff1260905f4edf600f9a52f11cc30a2c1d6737851d1376b3db4f500a57647dc94e1dd93b4b9a1d4c6d9d10e7912195d1e6d321100d240201b0f1c9576477b616dc097809299d0782a2de5f1dc344ff69c8a1f0a218466ab26f568b16f136d4e436443748d9031ac5040a2058fd4c8a5ddb802fc96d150aa2ae07d0b7cad4cdba820c240ef38f8923da59a9122056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b42112200d3fb459d2d6f8a3b43549a27ec3d67ce815ff1c5a4b569ec0ef3af45dd0f43e1220a4caead2409ff6007fd87ab2361dee0ee6efc9e43bb7e93e6d454c1f0fff597e1220f209d24fb15f175f83c8d51a6d134331c5b71910b2df900f2661bfc0c33ae1b61220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c18c803222097d90d03000000000000000000000000000000000000000000000000000000002220d19af20bc85df8fef846880ee8ad64887eb3ce7d05afed8a3d5b86f9d19e738a22201302cdbf031cfa6a45d2b06c498c05bb51cf48fad316fd2fb337627badde5c142220f209d24fb15f175f83c8d51a6d134331c5b71910b2df900f2661bfc0c33ae1b62220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c2a2028a1180a681c0ea894fd20099c8ef67a58c3e1ddf97d95eedf7bca7426fce24f32207ffe241ea60187fdb0187bfa22de35d1f9bed7ab061d9401fd47e34a54fbede132207d00409ac38e3a99bc86c045f570dea66e115ba1d767d89c9e7f82901dfcfd8832208892903e3a2b6d34a9d04441788de0d9e146ff7b6d0e15db35449220bf62aa2d32204f12ec63552b884ce8bd972037b19f8b346a95f03748aa7d99ba02cffac3c14f3220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c").to_vec(),
            cons_slot: 448,
            cons_l1_current_sync_committee: PublicKey::try_from(hex!("82c0c49d5142e3f5a7340864440c61787b6741271e4ce2a21114f137a693fc4484582aee2ebbb9c6d9f9ebdae7ff73f7").to_vec()).unwrap(),
            cons_l1_next_sync_committee: PublicKey::try_from(hex!("82c0c49d5142e3f5a7340864440c61787b6741271e4ce2a21114f137a693fc4484582aee2ebbb9c6d9f9ebdae7ff73f7").to_vec()).unwrap(),
        }];

        for (i, case) in cases.iter().enumerate() {
            let raw_l1_header = RawL1Header::decode(&*case.raw_l1_header.to_vec()).unwrap();
            let l1_header = L1Header::<
                { ethereum_consensus::preset::minimal::PRESET.SYNC_COMMITTEE_SIZE },
            >::try_from(raw_l1_header.clone())
            .unwrap();
            let cons_state = L1Consensus {
                slot: case.cons_slot.into(),
                current_sync_committee: case.cons_l1_current_sync_committee.clone(),
                next_sync_committee: case.cons_l1_next_sync_committee.clone(),
            };
            let (_, l1_consensus) = l1_header
                .verify(1737033548, &l1_config, &cons_state)
                .unwrap();
            assert_eq!(
                l1_consensus.slot,
                l1_header.consensus_update.finalized_header.0.slot
            );
            if i == cases.len() - 1 {
                // last is same period( cons_state period == finalized_period )
                assert_eq!(
                    l1_consensus.current_sync_committee, cons_state.current_sync_committee,
                    "result {i}"
                );
                assert_eq!(
                    l1_consensus.next_sync_committee, cons_state.next_sync_committee,
                    "result {i}"
                );

                // Verify exactly same slot
                let (_, result) = l1_header
                    .verify(1737033548, &l1_config, &l1_consensus)
                    .unwrap();
                assert_eq!(result.slot, l1_consensus.slot);
                assert_eq!(
                    result.current_sync_committee,
                    l1_consensus.current_sync_committee
                );
                assert_eq!(result.next_sync_committee, l1_consensus.next_sync_committee);
            } else {
                assert_eq!(
                    l1_consensus.current_sync_committee, cons_state.next_sync_committee,
                    "result {i}"
                );
                assert_eq!(
                    l1_consensus.next_sync_committee,
                    l1_header
                        .consensus_update
                        .next_sync_committee
                        .unwrap()
                        .0
                        .aggregate_pubkey,
                    "result {i}"
                );
            }
        }
    }
}
