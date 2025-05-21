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

/// This file is almost the same as ethereum-ibc-rs. Because the L1 verification is same.

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

        // Ensure valid l1 block hash
        // This is not required for ethereum-elc but is required for optimism-elc.
        // Because L2 derivation requires l1 block hash.
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
        // created by optimism-ibc-relay-prover#prover_test.go#TestSetupHeadersForUpdateShort
        let raw_l1_config = hex!("0a20d61ea484febacfae5298d52a2b581f3e305a51f3112a9241b968dccf019f7b11100118b09fb4c106226f0a0410000038120e0a04200000381a0608691036183712140a04300000381a0c08691036183720192812301612140a04400000381a0c08691036183720192812301612140a04500000381a0c08691036183720192822302612150a04600000381a0d08a90110561857201928223026280630083808420408021003").to_vec();
        let raw_l1_config = RawL1Config::decode(&*raw_l1_config).unwrap();
        L1Config::try_from(raw_l1_config).unwrap()
    }

    pub fn get_raw_l1_header() -> RawL1Header {
        // created by optimism-ibc-relay-prover#prover_test.go#TestSetupHeadersForUpdateShort
        let raw_l1_header = hex!("0af50c0af20c0a3084d08d58c31bcd3cddf93e13d6f50203897384afa34644bff1135efe8e01c81c6a91ca6c234bb1e51ca32e41b828aaf90a30b27ad13afc8ff30e087797b344c8382bb0a84447549f1b0274059ddd652276e7b148ba8808a10cc45746762957d4efbe0a3084dc37ca3cd621d3da0fbdd11ca84021e0cd81a73d772dd6fcf19775b72eb64af4e573213378ccee0915dde92ac83ba60a30ad9222dec71ff8ee6bc0426ffe7b5e66f96738225db281dd20027a1556d089fdebd040abfbc2041d6c1a0d8fdcfce1830a3084a687ffdf21a0ad754d0164d1e2c03035613ab76359e7f5cf51ea4a425a6ee026725ec0a0dbd336f7dab759596f0bf80a30a54fe5c26059ed60b4f0b66ef7b0bf167580504525f83c169507dc812816df41b1da6128341c23977300dffd32a32f410a3084dc37ca3cd621d3da0fbdd11ca84021e0cd81a73d772dd6fcf19775b72eb64af4e573213378ccee0915dde92ac83ba60a30abd12678c73463ecea5867a80caf256d5c5e6ba53ff188b143a4d5be83365ad257edf39eaa1ba8753c4cdf4c632ff99e0a30ad9222dec71ff8ee6bc0426ffe7b5e66f96738225db281dd20027a1556d089fdebd040abfbc2041d6c1a0d8fdcfce1830a30b5e898a1fc06d51c695712928f44646d15451340d1b3e480a40f03250160bc07d3b6691ec94361dd524d59d9df7f76d30a308725b32751419f22a54485790f8187d1ba52d84a31ad45738a93777fcd1ccbec1652229923f82f37793ce0fc2763fb4c0a30b09cb155daf2022afd18114a352e506a84065c80573cb0c7c310cbe92e2706cdcf91f74bbd9e464f74e3d831386d50330a30b2225575d5e70da1257db7a0d1222c5041b52aac61cf161e8fc8126a3fdf5eb4f0867d98dfe272199c36cf8f02661b3d0a30a62c0205fb22df8535c0b70076486e69dfa908feddae79e4a94a9d47b97ed190d228e1c6217e84a59882bb992dacae300a30b09cb155daf2022afd18114a352e506a84065c80573cb0c7c310cbe92e2706cdcf91f74bbd9e464f74e3d831386d50330a30af61f263addfb41c46d66e60ecfb598a5942f648f58718b6b4e4c92019fdb12328efbff98703134bcf28e9c1fab4bb600a3084dc37ca3cd621d3da0fbdd11ca84021e0cd81a73d772dd6fcf19775b72eb64af4e573213378ccee0915dde92ac83ba60a3081ea9f74ef7d935b807474e38954ae3934856219a23e074954b2e860c5a3c400f9aedb42cd27cb4ceb697ca36d1e58cb0a308419cf00f2783c430dc861a710984d0429d3b3a7f6db849b4f5c05e0d87339704c5c7f5eede6adfc8776d666587b59320a30b72cb106b7bc1ecae219e0ae1830a509ed18a042b56a2779f4033419de69ba8ae8017090caed1f5377bfa685061573600a30ac69ae9e6c385a368df71d11ac68f45f05e005306df3c2bf98ed3577708256bd97f8c09d3f72115444077a9bb711d8d10a30a4ee6d37dc259cbb5237e4265429a9fd8ab5643af81628cc101e0d8b4a333ef2618a37df89ea3f92b5ea4333d8cda3930a30ad9222dec71ff8ee6bc0426ffe7b5e66f96738225db281dd20027a1556d089fdebd040abfbc2041d6c1a0d8fdcfce1830a30af61f263addfb41c46d66e60ecfb598a5942f648f58718b6b4e4c92019fdb12328efbff98703134bcf28e9c1fab4bb600a3084dc37ca3cd621d3da0fbdd11ca84021e0cd81a73d772dd6fcf19775b72eb64af4e573213378ccee0915dde92ac83ba60a30a54fe5c26059ed60b4f0b66ef7b0bf167580504525f83c169507dc812816df41b1da6128341c23977300dffd32a32f410a3081b676591b823270a3284ace7d81cbce2d6cdce55bb0e053874d7e3a08f729453009d3e662ec3130379f43c0f3210b6d0a3081fa222737fe818b43f55f209f42adaee135b2801d02709617fc88c2871852358260ace97cf323e761b5cc18bc7325b30a309763dde1b8028136a3ffd6dafd1f450e2cafb2819c7fa901f7c6e9cde8f2897ee7e9a45da6947fde1ad0d3836188eab50a3086e014747c7922ccfc2b9d4bf6c1ecf0dc800197037858d0b85ab1944b4c3c14b95e0ed325bc42a6f467bc47ec27bc7b0a309918433b8f0bc5e126da3fdef8d7b71456492dae6d2d07f2e10c7a7f852046f84ed0ce6d3bfec42200670db27dcf30370a30a54fe5c26059ed60b4f0b66ef7b0bf167580504525f83c169507dc812816df41b1da6128341c23977300dffd32a32f411230a65108de41a76af688337463456bd1cd7f49b6849b7b14ad69d347893d030e7eaacb2be238ee653e2df1dfa78e0d060912a0140a6b08d00110081a207189d31eb099bb2167cd75a13f22502074c1efa653df55db4b2354887270de8d2220419c394f863af87d83208a97b0415e1adfb0defcf339b146c4dd2e1e7b40e9762a2070fbdbd2aa84d25f2598ef9d406547070f94059d75b86abfa9a280118695a00c12f20c0a3087231421a08ed28e7d357e2b37a26a458155c8d822d829344bd1029e5d175b5edfaa78f16f784f724a2caef124944c4f0a308d8985e5dd341c9035b37bf7391c5944c28131b47c7d5359d18fca598010ba9a63e27c55e6b421a807038c320564db170a30ab72cbc6575c3179680a58c0ecd5de46d2678ccbafc016746348ee5688edcb21b4e15bd37c70c508e3ea73103c2d566b0a30b24391aa97bfff29adc935d06a2b6d583433caf82f92de1980e0192d3b270323bdbf24b86dc61520a40c419dde3df4b30a3091709ee06497b9ac049325853d64947290189a8c2322e3a500d91e23ea02dc158b6db63ae558b3b7670357a151cd60710a30958c2692b86b4d20eaea3bb45e9447ebbc5b93ccaf8d21ef659d0cefedf5c4371b31b460ae40e8243682bde505abac1e0a308dfa86c051edd28c3554a30e40531c898e5936ad3002711616ddd1b27054bc39caedd505a200c3d23a1c3f6b26c50ae90a30930743bfc7e18d3bd7351eaa74f477505268c1e4e1fd1ca3ccccdefb2595517343bbb8f5589c435c3c39323a4c0080f80a3099d83a0ba33161d8c6bbe80929fd9046d4dfdac43477ff85fea5bae925e6c179ad28eb338375ee2417acbd6576ee670a0a308aa5bbee21e98c7b9e7a4c8ea45aa99f89e22992fa4fc2d73869d77da4cc8a05b25b61931ff521986677dd7f7159e8e60a3084a687ffdf21a0ad754d0164d1e2c03035613ab76359e7f5cf51ea4a425a6ee026725ec0a0dbd336f7dab759596f0bf80a30ad9222dec71ff8ee6bc0426ffe7b5e66f96738225db281dd20027a1556d089fdebd040abfbc2041d6c1a0d8fdcfce1830a30ae940a07850cf904b44f31cbf0e44824bae5ec36dcfdb7fad858f2a39dba38de82ca12b0ae939a34fce7a02e4b9789f80a30ac69ae9e6c385a368df71d11ac68f45f05e005306df3c2bf98ed3577708256bd97f8c09d3f72115444077a9bb711d8d10a30ae940a07850cf904b44f31cbf0e44824bae5ec36dcfdb7fad858f2a39dba38de82ca12b0ae939a34fce7a02e4b9789f80a3084d08d58c31bcd3cddf93e13d6f50203897384afa34644bff1135efe8e01c81c6a91ca6c234bb1e51ca32e41b828aaf90a30a75ca9447dca3a3745ada36731187ddd1f6a152cf15d7446b785eab381e5c8562c1202a6e7a24080bc6b619a161113db0a3087231421a08ed28e7d357e2b37a26a458155c8d822d829344bd1029e5d175b5edfaa78f16f784f724a2caef124944c4f0a30ab64f900c770e2b99de6b86b4390bbd1579bd48dccec55800adbcf52e006f22128e9971bbf3a92cc0105b0974849935a0a308de5a6200cebb09b2198e69fed84bcd512ec5cf317c5f1ee99aad03d2a9a8564bf3807c08da2664222268d59c34a06e40a30b72cb106b7bc1ecae219e0ae1830a509ed18a042b56a2779f4033419de69ba8ae8017090caed1f5377bfa685061573600a30aaddb0cb69ca18f14aed7054e98a24df0ff606aeff919d489f7884fd1bd183bcb46ea54bc363146e1a88db36dc20a7a40a3081fa222737fe818b43f55f209f42adaee135b2801d02709617fc88c2871852358260ace97cf323e761b5cc18bc7325b30a30ac69ae9e6c385a368df71d11ac68f45f05e005306df3c2bf98ed3577708256bd97f8c09d3f72115444077a9bb711d8d10a30a0485d71f1f5e177f7d5bc9d98c5248a6a2d0de4554c2eaf02abae48f5a3e273b2ee7765784cf2a4cb7df84f617177c90a308aa5bbee21e98c7b9e7a4c8ea45aa99f89e22992fa4fc2d73869d77da4cc8a05b25b61931ff521986677dd7f7159e8e60a308de5a6200cebb09b2198e69fed84bcd512ec5cf317c5f1ee99aad03d2a9a8564bf3807c08da2664222268d59c34a06e40a30930743bfc7e18d3bd7351eaa74f477505268c1e4e1fd1ca3ccccdefb2595517343bbb8f5589c435c3c39323a4c0080f80a30aaf6c1251e73fb600624937760fef218aace5b253bf068ed45398aeb29d821e4d2899343ddcbbe37cb3f6cf500dff26c0a30b63f327df68581cdc02a66c1c65e906a06a1a3a8d7a6e38f7b6da944e8e6cc2db85fced5327d8c12945ceb33018272ca0a30a8fa3584a92b079c8c73ed1553e5e161a0b21325fc2fc4e24a892354a899c7fc0bfb436a97a7ed1fc71bccda438ea7150a30b570dde8ee80512e3d031caf22e775c60f7f5a6cbdeb3e52e24cf8c867d38569a53dd19cdc36a03a1bbb3a8d94b03670123099bde785aa1f1369e280f0bd188e111a28eaedb6827690fd2a1a6ffc360cdf942f9c9e0a7e9df962b522524e00d2f21a1a20b11c8dc84c17e8e95e2fc3a46d273a626eb1b7c5de4856a0ddbfc22d6e90e01e1a2091b73d16eb511319e45aa41a6c244f269fe02577a9e0877ff6b077ebc7556c431a2042ffca35fe79062ed9876ec8b4fa86a69c48217e45e2328ede8adc1d5ba097bb1a2068f2d9b31b10617419f55e95191f28f2ef78ab9a94d0345095d3d2232a422e851a201805d37240373af67897cf3d6af4ae70593bbe9309cc3c80c4cff0c9afa6428e1a20953024c6ded67e542650258c58347cef640ac2bb254c6df6bc3af9bf3c1a1f7a226b08c001103f1a20b452aae70ab0813be7b81c1cd1c6ef7c90e4d2128e3b70c01e0699e2961c9d48222007044d88ecc54c7c60190c56525fe56ceab6155182bf96a8588d73315bff6cc22a20b7622b62d85581f35c63f428e41740faa4dac825813e1837d0336cd1a4e1a3d22a2018000000000000000000000000000000000000000000000000000000000000002a205f6f02af29218292d21a69b64a794a7c0873b3e0f54611972863706e8cbdf3712a20d9e4f3ba69eaf2e1296d8d918eff8aada10117c4c93604cab83593ab5a462d7a2a2042ffca35fe79062ed9876ec8b4fa86a69c48217e45e2328ede8adc1d5ba097bb2a2068f2d9b31b10617419f55e95191f28f2ef78ab9a94d0345095d3d2232a422e852a201805d37240373af67897cf3d6af4ae70593bbe9309cc3c80c4cff0c9afa6428e2a20953024c6ded67e542650258c58347cef640ac2bb254c6df6bc3af9bf3c1a1f7a3220ffa77d35c8b70867adc0705d1f8db9c1f6c0fe9fa29a6c20f6ac014ddb05cf123a203eeb461956441b90b6ca76ea1ccd31996315806b6252b291c25d4db34f2c1aed3a20e69241c5ee14d690ddf8a0a0a26b4bbdb681b3fc2b6561a0ee85230582238b003a206e817161402150ae7a3c42df6d68062e41bf358f5966510d5be0b8c40188772d3a20eecef1c836c947c509a96014af9019d636c59422f3467c9b37aaabd6be94fe8342680a04ffffffff1260afafeb983ce31441d4a4aa6504e163801fb78d4814579626815888a774563b993f2391cd6197a13355be2f12e986f2ab043ff1a823ff2ec42a0e667f5336c0bbc5b4a5501d78892a34d46e67c4cfd131b43c9f4cb6f86bc4d64000c5877bff2d48d1011ac5040a20ff11702a0c2999a4ef84b08d5ab7ed2db5a6ebac6da7aa8dfae7bd42bdc6e0331220eaa8c40899a61ae59615cf9985f5e2194f8fd2b57d273be63bde6733e89b12ab12206fe941c7c874dca9d020171e1b824219de638fa55924b78b6235acd03f2b1d391220b62c415369647054fc054eac44a2e46cca186e2d86805e79b083d805e18f635312206e8132d203683f5f2dd0cd7491af3d14c06d5fd8bdad3944f23d7d1c522c1ef61220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c18c001222000512502000000000000000000000000000000000000000000000000000000002220d1624b516101634a84546d74746fffa082dd8b540c49d5e2fe34452fd825789022201294c89fc268110f218455c31701dc758648542eaf8d051fd2644537b36d7f8522206e8132d203683f5f2dd0cd7491af3d14c06d5fd8bdad3944f23d7d1c522c1ef62220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c2a204a383262d227b7f155424b27386f5854a5c72231c449a38ef9816cd40d0971f7322044a3d4d2edc9ce39da43849808400790e72694f7b0e147f9d31a5fd0665f20463220a09a2b87124e2c710b9d90a696327a3a76e1bde89ca3efbc730de5c19fa0eaa93220831e327da8b0af89cc8d06c41c7207edcc6cb6c3335688f979d31ba9eb7803d53220c44c12d385cad450d45a2da9c42f28e2ceee022b247d41f9a8ceefb87682cd963220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c").to_vec();
        RawL1Header::decode(&*raw_l1_header).unwrap()
    }

    pub fn get_l1_header(
    ) -> L1Header<{ ethereum_consensus::preset::minimal::PRESET.SYNC_COMMITTEE_SIZE }> {
        // created by optimism-ibc-relay-prover
        let raw_l1_header = get_raw_l1_header();

        L1Header::<{ ethereum_consensus::preset::minimal::PRESET.SYNC_COMMITTEE_SIZE }>::try_from(
            raw_l1_header.clone(),
        )
        .unwrap()
    }

    pub fn get_l1_consensus() -> L1Consensus {
        // created by optimism-ibc-relay-prover#prover_test.go#TestSetupHeadersForUpdateShort
        L1Consensus {
            slot: 192.into(),
            current_sync_committee: PublicKey::try_from(hex!("a65108de41a76af688337463456bd1cd7f49b6849b7b14ad69d347893d030e7eaacb2be238ee653e2df1dfa78e0d0609").to_vec()).unwrap(),
            next_sync_committee: PublicKey::default()
        }
    }

    pub fn get_time() -> u64 {
        1747785427
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
        l1_header.consensus_update.finalized_header.0.slot = cons_state.slot + 64;
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
        // created by optimism-ibc-relay-prover#prover_test.go#TestSetupHeadersForUpdateLong
        let l1_config = get_l1_config();

        let cases = vec![TestCase {
            raw_l1_header: hex!("0af70c0af20c0a308fda66b8607af873f4c2c8218dd3ffc7940d411047eb199b5cd010156af4845d21dd2e65b0e44cfffb5e78271e9bb29d0a30996323af7e545fb6363ace53f1538c7ddc3eb0d985b2479da3ee4ace10cbc393b518bf02d1a2ddb2f5bdf09b473933ea0a3096947de9e6068c22a7716656a2755a9551b0b66c2d1a741bf84a088fe1e840e992dc39861bf8ba3e8d5b6d21e8f57e640a30b72cb106b7bc1ecae219e0ae1830a509ed18a042b56a2779f4033419de69ba8ae8017090caed1f5377bfa685061573600a30ad9222dec71ff8ee6bc0426ffe7b5e66f96738225db281dd20027a1556d089fdebd040abfbc2041d6c1a0d8fdcfce1830a3084d08d58c31bcd3cddf93e13d6f50203897384afa34644bff1135efe8e01c81c6a91ca6c234bb1e51ca32e41b828aaf90a30a1584dfe1573df8ec88c7b74d76726b4821bfe84bf886dd3c0e3f74c2ea18aa62ca44c871fb1c63971fccf6937e6501f0a308dfa86c051edd28c3554a30e40531c898e5936ad3002711616ddd1b27054bc39caedd505a200c3d23a1c3f6b26c50ae90a30b63f327df68581cdc02a66c1c65e906a06a1a3a8d7a6e38f7b6da944e8e6cc2db85fced5327d8c12945ceb33018272ca0a30b2225575d5e70da1257db7a0d1222c5041b52aac61cf161e8fc8126a3fdf5eb4f0867d98dfe272199c36cf8f02661b3d0a3087231421a08ed28e7d357e2b37a26a458155c8d822d829344bd1029e5d175b5edfaa78f16f784f724a2caef124944c4f0a30a75ca9447dca3a3745ada36731187ddd1f6a152cf15d7446b785eab381e5c8562c1202a6e7a24080bc6b619a161113db0a3096947de9e6068c22a7716656a2755a9551b0b66c2d1a741bf84a088fe1e840e992dc39861bf8ba3e8d5b6d21e8f57e640a30996d10c3026b9344532b06c70a596f972a1e779a1f6106d3da9f6ba376bbf7ec82d2f52629e5dbf3f7d03b00f6b862af0a30b27ad13afc8ff30e087797b344c8382bb0a84447549f1b0274059ddd652276e7b148ba8808a10cc45746762957d4efbe0a3099d83a0ba33161d8c6bbe80929fd9046d4dfdac43477ff85fea5bae925e6c179ad28eb338375ee2417acbd6576ee670a0a309918433b8f0bc5e126da3fdef8d7b71456492dae6d2d07f2e10c7a7f852046f84ed0ce6d3bfec42200670db27dcf30370a30958c2692b86b4d20eaea3bb45e9447ebbc5b93ccaf8d21ef659d0cefedf5c4371b31b460ae40e8243682bde505abac1e0a30af89ab00a0eab1131645292a9cfba583a69a1e3ac58b210e262494853e67385aeb50d4af428bdd577b9399daa96d8b200a308aa5bbee21e98c7b9e7a4c8ea45aa99f89e22992fa4fc2d73869d77da4cc8a05b25b61931ff521986677dd7f7159e8e60a308d46e9aa0c1986056e407efc7013b7f271027d3c98ce96667faa98074ab0588a61681faf78644c11819a459a95689dab0a309763dde1b8028136a3ffd6dafd1f450e2cafb2819c7fa901f7c6e9cde8f2897ee7e9a45da6947fde1ad0d3836188eab50a3099d83a0ba33161d8c6bbe80929fd9046d4dfdac43477ff85fea5bae925e6c179ad28eb338375ee2417acbd6576ee670a0a3081fa222737fe818b43f55f209f42adaee135b2801d02709617fc88c2871852358260ace97cf323e761b5cc18bc7325b30a3087231421a08ed28e7d357e2b37a26a458155c8d822d829344bd1029e5d175b5edfaa78f16f784f724a2caef124944c4f0a30a1584dfe1573df8ec88c7b74d76726b4821bfe84bf886dd3c0e3f74c2ea18aa62ca44c871fb1c63971fccf6937e6501f0a30a0485d71f1f5e177f7d5bc9d98c5248a6a2d0de4554c2eaf02abae48f5a3e273b2ee7765784cf2a4cb7df84f617177c90a30ae940a07850cf904b44f31cbf0e44824bae5ec36dcfdb7fad858f2a39dba38de82ca12b0ae939a34fce7a02e4b9789f80a30a54fe5c26059ed60b4f0b66ef7b0bf167580504525f83c169507dc812816df41b1da6128341c23977300dffd32a32f410a30a2e2d8384fc87a512ee34eb43405fd82572c9d7cd96e155a382cda284e8df9eb7189c25b7473d89c63ea4e6080e10ff80a30a62c0205fb22df8535c0b70076486e69dfa908feddae79e4a94a9d47b97ed190d228e1c6217e84a59882bb992dacae300a30ae5302796cfeca685eaf37ffd5baeb32121f2f07415bee26cc0051ee513ff3932d2c365e3d9f87b0949a5980445cb64c123092dff6986fe755b71abaf421a3be14542747928e1a8a1ce1dcc59382f4d86c766bca53dd2ea7f72e982978cc723d45d5100112a0140a6b08d00410021a202257585f07dc7dc7224d0093e407e048dee787c8bc6b15dd8a2d36441bb24329222072f5c0c90abff0d64c8c50c57dc5f7151cd462b77d5dfe52d760a1e8c23bd8e82a205a1644d448595081ff84948651365c517834425e998be2086e05fe194d21401c12f20c0a30996d10c3026b9344532b06c70a596f972a1e779a1f6106d3da9f6ba376bbf7ec82d2f52629e5dbf3f7d03b00f6b862af0a309918433b8f0bc5e126da3fdef8d7b71456492dae6d2d07f2e10c7a7f852046f84ed0ce6d3bfec42200670db27dcf30370a30996d10c3026b9344532b06c70a596f972a1e779a1f6106d3da9f6ba376bbf7ec82d2f52629e5dbf3f7d03b00f6b862af0a30ab40dc1cfe273ad0da700c64f8fc94f91db253ca3acf20e336d9bd09de67eec5c7d3506285d83c7bb6a08d64b77e5f2d0a308725b32751419f22a54485790f8187d1ba52d84a31ad45738a93777fcd1ccbec1652229923f82f37793ce0fc2763fb4c0a308d46e9aa0c1986056e407efc7013b7f271027d3c98ce96667faa98074ab0588a61681faf78644c11819a459a95689dab0a3096947de9e6068c22a7716656a2755a9551b0b66c2d1a741bf84a088fe1e840e992dc39861bf8ba3e8d5b6d21e8f57e640a30a8fa3584a92b079c8c73ed1553e5e161a0b21325fc2fc4e24a892354a899c7fc0bfb436a97a7ed1fc71bccda438ea7150a308c0d15baa72bfcd317e9b9402ca9bb6e7ae1db35ffce7faccae0bd19b3c8e5de7d5524aef0377770b3a90626627a93040a30a1d9840eda3036fbf63eeea40146e4548553e6e1b2a653ab349b376f31b367c40d71fb59ff8e94b91daa99c262ec8b520a30ab72cbc6575c3179680a58c0ecd5de46d2678ccbafc016746348ee5688edcb21b4e15bd37c70c508e3ea73103c2d566b0a30b72cb106b7bc1ecae219e0ae1830a509ed18a042b56a2779f4033419de69ba8ae8017090caed1f5377bfa685061573600a30996323af7e545fb6363ace53f1538c7ddc3eb0d985b2479da3ee4ace10cbc393b518bf02d1a2ddb2f5bdf09b473933ea0a30ac69ae9e6c385a368df71d11ac68f45f05e005306df3c2bf98ed3577708256bd97f8c09d3f72115444077a9bb711d8d10a309763dde1b8028136a3ffd6dafd1f450e2cafb2819c7fa901f7c6e9cde8f2897ee7e9a45da6947fde1ad0d3836188eab50a30b72cb106b7bc1ecae219e0ae1830a509ed18a042b56a2779f4033419de69ba8ae8017090caed1f5377bfa685061573600a309763dde1b8028136a3ffd6dafd1f450e2cafb2819c7fa901f7c6e9cde8f2897ee7e9a45da6947fde1ad0d3836188eab50a30ab64f900c770e2b99de6b86b4390bbd1579bd48dccec55800adbcf52e006f22128e9971bbf3a92cc0105b0974849935a0a30b09cb155daf2022afd18114a352e506a84065c80573cb0c7c310cbe92e2706cdcf91f74bbd9e464f74e3d831386d50330a308725b32751419f22a54485790f8187d1ba52d84a31ad45738a93777fcd1ccbec1652229923f82f37793ce0fc2763fb4c0a30a54fe5c26059ed60b4f0b66ef7b0bf167580504525f83c169507dc812816df41b1da6128341c23977300dffd32a32f410a3081fa222737fe818b43f55f209f42adaee135b2801d02709617fc88c2871852358260ace97cf323e761b5cc18bc7325b30a309763dde1b8028136a3ffd6dafd1f450e2cafb2819c7fa901f7c6e9cde8f2897ee7e9a45da6947fde1ad0d3836188eab50a3091709ee06497b9ac049325853d64947290189a8c2322e3a500d91e23ea02dc158b6db63ae558b3b7670357a151cd60710a30a0485d71f1f5e177f7d5bc9d98c5248a6a2d0de4554c2eaf02abae48f5a3e273b2ee7765784cf2a4cb7df84f617177c90a30b72cb106b7bc1ecae219e0ae1830a509ed18a042b56a2779f4033419de69ba8ae8017090caed1f5377bfa685061573600a30ac69ae9e6c385a368df71d11ac68f45f05e005306df3c2bf98ed3577708256bd97f8c09d3f72115444077a9bb711d8d10a308d46e9aa0c1986056e407efc7013b7f271027d3c98ce96667faa98074ab0588a61681faf78644c11819a459a95689dab0a30a1d9840eda3036fbf63eeea40146e4548553e6e1b2a653ab349b376f31b367c40d71fb59ff8e94b91daa99c262ec8b520a30a1584dfe1573df8ec88c7b74d76726b4821bfe84bf886dd3c0e3f74c2ea18aa62ca44c871fb1c63971fccf6937e6501f0a30b72cb106b7bc1ecae219e0ae1830a509ed18a042b56a2779f4033419de69ba8ae8017090caed1f5377bfa685061573600a30a2e2d8384fc87a512ee34eb43405fd82572c9d7cd96e155a382cda284e8df9eb7189c25b7473d89c63ea4e6080e10ff81230971e9b8afd780ac17e039764f57be7713145a7e64c5e3a02f6c638e47f76acea4b2150d9f3de24d626caf97a4cad510b1a209a3035dca89d2b26e36a47e41f42855c413ac33dbe2773aff943651fcdeba9421a206e6a26de6c7f4bb953dcdeefcfa8e62bca669a50dd655e68c1101f4b4bf8f2f01a207b8e561cd7f91f137f121cd695b3afce5f6d73d2e6cbf38a03c91a79713c27c11a203b42789d30cd061eb07e86fa352d10eb9f45e5bc2ffdd7fcdf483292df09339d1a2044ae97a45e1b35cfc6e4327d2f3d9dd1508028f330095c9e159a60933838038f1a20953024c6ded67e542650258c58347cef640ac2bb254c6df6bc3af9bf3c1a1f7a226b08c00410151a2098b826203ffdac5b2c1148593130fb71805f3905e28612d0c6911aac9bf563f5222020b8f91050ba505256d69869f804250a04a342eb0c5092dc68731ea506f4274f2a2059ab6a8174a57811c33318da09ad69ddce2582e6a516481b7ab91fa1d6214fad2a2048000000000000000000000000000000000000000000000000000000000000002a205f6f02af29218292d21a69b64a794a7c0873b3e0f54611972863706e8cbdf3712a201367a77242435cb76ba746986b1db1bea356aee045b7b16d1342de8acbec1b932a207b8e561cd7f91f137f121cd695b3afce5f6d73d2e6cbf38a03c91a79713c27c12a203b42789d30cd061eb07e86fa352d10eb9f45e5bc2ffdd7fcdf483292df09339d2a2044ae97a45e1b35cfc6e4327d2f3d9dd1508028f330095c9e159a60933838038f2a20953024c6ded67e542650258c58347cef640ac2bb254c6df6bc3af9bf3c1a1f7a32200b60296e81f0de2e81340450d44adca5a6f1f531b154cd1f96e1f793e8d9e5a23a207a5230b69e3b9ffc87b51a7e034d840ce7ec6b4bc04003f9d2b45606c54a41723a206fd8ccfa2a8fada77e46e215fbda3255d2be3049d231a8a1c7fa98f98a93c9543a206e817161402150ae7a3c42df6d68062e41bf358f5966510d5be0b8c40188772d3a2007bd408c6f1d2565fa780c7264c4ec1afaea390313a917a239fa159e5e59e0ae42680a04ffffffff1260b0c6f877801d650510d370821bde1568d68a86f0a298a9984168b9bdac521977c862d24c85f024b508708b61d7e610730a2e3c67498a6bee1c5a947faf57ef3061da4362dbfd9fd72a98637f27ae6a816eae06be5dd3959249d615b7fc0cb50548d1041ac5040a204ad88299828623474c2c566e827df8e7318fe1638205c59b65ba9cfeab6690ce1220eaa8c40899a61ae59615cf9985f5e2194f8fd2b57d273be63bde6733e89b12ab122037cc3b3fe10278e11ffccc138beb2a39f1482a78bf0a0b56bbed7d6ac9b9a478122084e823881272470ef7d562174e0068fc7190782be3c7b64de094ce73e099490b1220cc3e15cf991c3eba48e44f529523091bb9cf45a7e6b416640b93a9554efef18e1220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c18c004222000512502000000000000000000000000000000000000000000000000000000002220f5300c9e8e826a73bcfba0b6f0859850c64f264cc65eb8aa0b26345e186cfa952220186947cbb41358fc417ba286bcf8180623f2da18766bbf6d675ba34e0aea43b72220cc3e15cf991c3eba48e44f529523091bb9cf45a7e6b416640b93a9554efef18e2220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c2a20218ec8fcd6f7d9577dd3004faa9997f30832007a950e2fc9633ec65225bf0060322055c34b051e9d9d24e05a11db3ef2cfad81f97d0b159128b3f897f6e390105c643220a09a2b87124e2c710b9d90a696327a3a76e1bde89ca3efbc730de5c19fa0eaa93220c005495cc9d80a0f290a4aabea137490a692e4654524cf80867d286bb17cc377322075204abaa5caffefc92d0ccb77db82618b6424a86fc2f2c7d898ceabc83c27d03220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c").to_vec(),
            cons_slot: 512,
            cons_l1_current_sync_committee: PublicKey::try_from(hex!("a98e2bedad76a68d3a8a4e49428cc019ba81d2aa8ce9df312459fedaf2b4cef999edd43795b18e07d2401b9bf54f5234").to_vec()).unwrap(),
            cons_l1_next_sync_committee: PublicKey::try_from(hex!("92dff6986fe755b71abaf421a3be14542747928e1a8a1ce1dcc59382f4d86c766bca53dd2ea7f72e982978cc723d45d5").to_vec()).unwrap(),
        },TestCase {
            raw_l1_header: hex!("0af70c0af20c0a30996d10c3026b9344532b06c70a596f972a1e779a1f6106d3da9f6ba376bbf7ec82d2f52629e5dbf3f7d03b00f6b862af0a309918433b8f0bc5e126da3fdef8d7b71456492dae6d2d07f2e10c7a7f852046f84ed0ce6d3bfec42200670db27dcf30370a30996d10c3026b9344532b06c70a596f972a1e779a1f6106d3da9f6ba376bbf7ec82d2f52629e5dbf3f7d03b00f6b862af0a30ab40dc1cfe273ad0da700c64f8fc94f91db253ca3acf20e336d9bd09de67eec5c7d3506285d83c7bb6a08d64b77e5f2d0a308725b32751419f22a54485790f8187d1ba52d84a31ad45738a93777fcd1ccbec1652229923f82f37793ce0fc2763fb4c0a308d46e9aa0c1986056e407efc7013b7f271027d3c98ce96667faa98074ab0588a61681faf78644c11819a459a95689dab0a3096947de9e6068c22a7716656a2755a9551b0b66c2d1a741bf84a088fe1e840e992dc39861bf8ba3e8d5b6d21e8f57e640a30a8fa3584a92b079c8c73ed1553e5e161a0b21325fc2fc4e24a892354a899c7fc0bfb436a97a7ed1fc71bccda438ea7150a308c0d15baa72bfcd317e9b9402ca9bb6e7ae1db35ffce7faccae0bd19b3c8e5de7d5524aef0377770b3a90626627a93040a30a1d9840eda3036fbf63eeea40146e4548553e6e1b2a653ab349b376f31b367c40d71fb59ff8e94b91daa99c262ec8b520a30ab72cbc6575c3179680a58c0ecd5de46d2678ccbafc016746348ee5688edcb21b4e15bd37c70c508e3ea73103c2d566b0a30b72cb106b7bc1ecae219e0ae1830a509ed18a042b56a2779f4033419de69ba8ae8017090caed1f5377bfa685061573600a30996323af7e545fb6363ace53f1538c7ddc3eb0d985b2479da3ee4ace10cbc393b518bf02d1a2ddb2f5bdf09b473933ea0a30ac69ae9e6c385a368df71d11ac68f45f05e005306df3c2bf98ed3577708256bd97f8c09d3f72115444077a9bb711d8d10a309763dde1b8028136a3ffd6dafd1f450e2cafb2819c7fa901f7c6e9cde8f2897ee7e9a45da6947fde1ad0d3836188eab50a30b72cb106b7bc1ecae219e0ae1830a509ed18a042b56a2779f4033419de69ba8ae8017090caed1f5377bfa685061573600a309763dde1b8028136a3ffd6dafd1f450e2cafb2819c7fa901f7c6e9cde8f2897ee7e9a45da6947fde1ad0d3836188eab50a30ab64f900c770e2b99de6b86b4390bbd1579bd48dccec55800adbcf52e006f22128e9971bbf3a92cc0105b0974849935a0a30b09cb155daf2022afd18114a352e506a84065c80573cb0c7c310cbe92e2706cdcf91f74bbd9e464f74e3d831386d50330a308725b32751419f22a54485790f8187d1ba52d84a31ad45738a93777fcd1ccbec1652229923f82f37793ce0fc2763fb4c0a30a54fe5c26059ed60b4f0b66ef7b0bf167580504525f83c169507dc812816df41b1da6128341c23977300dffd32a32f410a3081fa222737fe818b43f55f209f42adaee135b2801d02709617fc88c2871852358260ace97cf323e761b5cc18bc7325b30a309763dde1b8028136a3ffd6dafd1f450e2cafb2819c7fa901f7c6e9cde8f2897ee7e9a45da6947fde1ad0d3836188eab50a3091709ee06497b9ac049325853d64947290189a8c2322e3a500d91e23ea02dc158b6db63ae558b3b7670357a151cd60710a30a0485d71f1f5e177f7d5bc9d98c5248a6a2d0de4554c2eaf02abae48f5a3e273b2ee7765784cf2a4cb7df84f617177c90a30b72cb106b7bc1ecae219e0ae1830a509ed18a042b56a2779f4033419de69ba8ae8017090caed1f5377bfa685061573600a30ac69ae9e6c385a368df71d11ac68f45f05e005306df3c2bf98ed3577708256bd97f8c09d3f72115444077a9bb711d8d10a308d46e9aa0c1986056e407efc7013b7f271027d3c98ce96667faa98074ab0588a61681faf78644c11819a459a95689dab0a30a1d9840eda3036fbf63eeea40146e4548553e6e1b2a653ab349b376f31b367c40d71fb59ff8e94b91daa99c262ec8b520a30a1584dfe1573df8ec88c7b74d76726b4821bfe84bf886dd3c0e3f74c2ea18aa62ca44c871fb1c63971fccf6937e6501f0a30b72cb106b7bc1ecae219e0ae1830a509ed18a042b56a2779f4033419de69ba8ae8017090caed1f5377bfa685061573600a30a2e2d8384fc87a512ee34eb43405fd82572c9d7cd96e155a382cda284e8df9eb7189c25b7473d89c63ea4e6080e10ff81230971e9b8afd780ac17e039764f57be7713145a7e64c5e3a02f6c638e47f76acea4b2150d9f3de24d626caf97a4cad510b100112a0140a6b089005100b1a20d2eb47a13829b4d13a766ac9cc928bec146d3c4fa1ddee384c15aeedcb881a6a22201f83c5339a24b19b19beff8d383ac7c577bc1f746983967060706ed2abb2cf092a202fb8faeb9bae4b46401fe188b1fda2399ae49481f69580088056da5cb84e10bf12f20c0a3091709ee06497b9ac049325853d64947290189a8c2322e3a500d91e23ea02dc158b6db63ae558b3b7670357a151cd60710a309918433b8f0bc5e126da3fdef8d7b71456492dae6d2d07f2e10c7a7f852046f84ed0ce6d3bfec42200670db27dcf30370a308d46e9aa0c1986056e407efc7013b7f271027d3c98ce96667faa98074ab0588a61681faf78644c11819a459a95689dab0a30afa10af166a0dbf3a25ff86cd6f8e44cccc818c5e70cd70e4e98e226b158f3563450b3fb184d2649adbb11e53080d1ca0a30a54fe5c26059ed60b4f0b66ef7b0bf167580504525f83c169507dc812816df41b1da6128341c23977300dffd32a32f410a30aaddb0cb69ca18f14aed7054e98a24df0ff606aeff919d489f7884fd1bd183bcb46ea54bc363146e1a88db36dc20a7a40a30a759f6bcca8f35fcaadc406cc4b828c016c0ed23882987a79f52f2933b5cedefe24e31df6fd0d38e8a802dbafd750d010a308d8985e5dd341c9035b37bf7391c5944c28131b47c7d5359d18fca598010ba9a63e27c55e6b421a807038c320564db170a308419cf00f2783c430dc861a710984d0429d3b3a7f6db849b4f5c05e0d87339704c5c7f5eede6adfc8776d666587b59320a30a759f6bcca8f35fcaadc406cc4b828c016c0ed23882987a79f52f2933b5cedefe24e31df6fd0d38e8a802dbafd750d010a308d028a021c5c31a1aa1e18eda74cfaf0fba1c454c17c2e0fc730dd07a19d0c77f7a905d54017292f3e800ca06b6977cd0a30b63f327df68581cdc02a66c1c65e906a06a1a3a8d7a6e38f7b6da944e8e6cc2db85fced5327d8c12945ceb33018272ca0a30a1584dfe1573df8ec88c7b74d76726b4821bfe84bf886dd3c0e3f74c2ea18aa62ca44c871fb1c63971fccf6937e6501f0a308de5a6200cebb09b2198e69fed84bcd512ec5cf317c5f1ee99aad03d2a9a8564bf3807c08da2664222268d59c34a06e40a30a1d9840eda3036fbf63eeea40146e4548553e6e1b2a653ab349b376f31b367c40d71fb59ff8e94b91daa99c262ec8b520a3096947de9e6068c22a7716656a2755a9551b0b66c2d1a741bf84a088fe1e840e992dc39861bf8ba3e8d5b6d21e8f57e640a308d8985e5dd341c9035b37bf7391c5944c28131b47c7d5359d18fca598010ba9a63e27c55e6b421a807038c320564db170a308c0d15baa72bfcd317e9b9402ca9bb6e7ae1db35ffce7faccae0bd19b3c8e5de7d5524aef0377770b3a90626627a93040a308a8bb292bcc481070d3afdbbc8789e2ab4b29c9603936e6d85f5ff71e23fc5b6d61009f0fa636b5d5b2dc309d39e3d750a30ab72cbc6575c3179680a58c0ecd5de46d2678ccbafc016746348ee5688edcb21b4e15bd37c70c508e3ea73103c2d566b0a30930743bfc7e18d3bd7351eaa74f477505268c1e4e1fd1ca3ccccdefb2595517343bbb8f5589c435c3c39323a4c0080f80a308d46e9aa0c1986056e407efc7013b7f271027d3c98ce96667faa98074ab0588a61681faf78644c11819a459a95689dab0a308dfa86c051edd28c3554a30e40531c898e5936ad3002711616ddd1b27054bc39caedd505a200c3d23a1c3f6b26c50ae90a308725b32751419f22a54485790f8187d1ba52d84a31ad45738a93777fcd1ccbec1652229923f82f37793ce0fc2763fb4c0a308fda66b8607af873f4c2c8218dd3ffc7940d411047eb199b5cd010156af4845d21dd2e65b0e44cfffb5e78271e9bb29d0a308fda66b8607af873f4c2c8218dd3ffc7940d411047eb199b5cd010156af4845d21dd2e65b0e44cfffb5e78271e9bb29d0a308aec5129a518010912215e1887191da94be419b4e75904c2ea745e2d253d707c088fa5b2c46dade1d162affe9f7ab17b0a30ae940a07850cf904b44f31cbf0e44824bae5ec36dcfdb7fad858f2a39dba38de82ca12b0ae939a34fce7a02e4b9789f80a309918433b8f0bc5e126da3fdef8d7b71456492dae6d2d07f2e10c7a7f852046f84ed0ce6d3bfec42200670db27dcf30370a3087231421a08ed28e7d357e2b37a26a458155c8d822d829344bd1029e5d175b5edfaa78f16f784f724a2caef124944c4f0a30ac69ae9e6c385a368df71d11ac68f45f05e005306df3c2bf98ed3577708256bd97f8c09d3f72115444077a9bb711d8d10a308a8bb292bcc481070d3afdbbc8789e2ab4b29c9603936e6d85f5ff71e23fc5b6d61009f0fa636b5d5b2dc309d39e3d751230a347267daf6b2170f61702d0d0a38393ce5083277e021c39e10da29eb6f30e9193b6f8cf5cba880911581f5ee007d8681a20f0b54366b393c69fa37151dfd06d910f9f7517571dc42c634832da28454e5a5e1a202fdbcf15827ef28e1cc117032bcb3c259edc001033c70caf16adb72838a8fcd31a20d3d088de5484a2ba0b25ac5c1b1f01ab8d3f3619028557d05c8584da495810ef1a20532ff17f8bcacd134d480178c80d63accd42dd59e9f50bdafb0ed89734e517f91a20f62981c4883c30798755e416999bf659df86b41f9be33bbf039fe2e857dde0051a20953024c6ded67e542650258c58347cef640ac2bb254c6df6bc3af9bf3c1a1f7a226b08800510101a203e4808f89c187e17ced0019eb0cbc9a5ff4962cfe83e9acdaf75d7d663faaaf02220ceb4f6816d2b4fda15d93a10baff312a098d03939f0e6221fc1583410fe3eade2a20c82c82e85109ebfa3aeae48e9cea10555c35c636ab71dc920dfb6a987fb9d54c2a2050000000000000000000000000000000000000000000000000000000000000002a205f6f02af29218292d21a69b64a794a7c0873b3e0f54611972863706e8cbdf3712a2064cac2ca12f168b2fd74c643fe4c6ee47ee810304a80241f179f6cf6fab7beba2a20d3d088de5484a2ba0b25ac5c1b1f01ab8d3f3619028557d05c8584da495810ef2a20532ff17f8bcacd134d480178c80d63accd42dd59e9f50bdafb0ed89734e517f92a20f62981c4883c30798755e416999bf659df86b41f9be33bbf039fe2e857dde0052a20953024c6ded67e542650258c58347cef640ac2bb254c6df6bc3af9bf3c1a1f7a32203f0da4aef4d63e2421db3488546ffd4e1b1277a9b90db8daf9230c45972160663a20dad89fa8845eb1273a34b76d5fc94038472c75f9da4e57b7e8da8c484a92cdef3a20df0c16fb1d6160bc649b3e31df72928ec2e822d2408d6ff070a5fd177d5fab943a206e817161402150ae7a3c42df6d68062e41bf358f5966510d5be0b8c40188772d3a2016fe2c2b72b0d112eaa187b36483376f61a1a6472ea7f3469ad26b56eeced69342680a04ffffffff1260acf5389542fd5b93dff4140f96477767867912392207bedc7c6ff48975ec8dc421304f4c116f96c15be30c847edc997d008f90d233ce071a21925769a21b16812d2da996c6ae7f4291248be27cec656b42b5d8a8600e5971856c988ebd9b609b4891051ac5040a201ba86de91bb0840b58af86a3d2d5576ddb8936e4f5b4b292bbe66453102d38c81220eaa8c40899a61ae59615cf9985f5e2194f8fd2b57d273be63bde6733e89b12ab1220998e8e977ef1a905342070f317deeb8dc8ca35baad1737b8c3cf88054ce1c3d61220ca685961b2d32844714f39ed2ea0c73bd7c22c152c14421a8d9e99c9c83056d91220a7039cc6f3f232a64399caafdf3b14fb18ca6fa7af8344ff62a126e809a2a3751220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c188005222000512502000000000000000000000000000000000000000000000000000000002220f83220fa233a08c1af9ec20a41e463a85df7b35227488bc25b65b0435b631d2722202af4e755cfc956089dfe26ef4db29f9fe790d8103a158346b4513fd05c8c48f72220a7039cc6f3f232a64399caafdf3b14fb18ca6fa7af8344ff62a126e809a2a3752220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c2a20eb039fe47d8dd76c8b98a4df67175b9aca7815623d03a89698de0759bf31b0f33220ae8c6534c104356e188f1922a3bc83eabf6cfa1dab6e1abb10f2cab61a97a0d93220a09a2b87124e2c710b9d90a696327a3a76e1bde89ca3efbc730de5c19fa0eaa93220c027725bfa1251679218e75a14cfbd0b41df4b6ec9b18caba823f2c3c919d44232208d6df7e9585074a10ae7280aeabaac2d9e6f5e89437b62d681c05f05074326a23220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c").to_vec(),
            cons_slot: 576,
            cons_l1_current_sync_committee: PublicKey::try_from(hex!("92dff6986fe755b71abaf421a3be14542747928e1a8a1ce1dcc59382f4d86c766bca53dd2ea7f72e982978cc723d45d5").to_vec()).unwrap(),
            cons_l1_next_sync_committee: PublicKey::try_from(hex!("971e9b8afd780ac17e039764f57be7713145a7e64c5e3a02f6c638e47f76acea4b2150d9f3de24d626caf97a4cad510b").to_vec()).unwrap(),
        }, TestCase {
            raw_l1_header: hex!("0af70c0af20c0a3091709ee06497b9ac049325853d64947290189a8c2322e3a500d91e23ea02dc158b6db63ae558b3b7670357a151cd60710a309918433b8f0bc5e126da3fdef8d7b71456492dae6d2d07f2e10c7a7f852046f84ed0ce6d3bfec42200670db27dcf30370a308d46e9aa0c1986056e407efc7013b7f271027d3c98ce96667faa98074ab0588a61681faf78644c11819a459a95689dab0a30afa10af166a0dbf3a25ff86cd6f8e44cccc818c5e70cd70e4e98e226b158f3563450b3fb184d2649adbb11e53080d1ca0a30a54fe5c26059ed60b4f0b66ef7b0bf167580504525f83c169507dc812816df41b1da6128341c23977300dffd32a32f410a30aaddb0cb69ca18f14aed7054e98a24df0ff606aeff919d489f7884fd1bd183bcb46ea54bc363146e1a88db36dc20a7a40a30a759f6bcca8f35fcaadc406cc4b828c016c0ed23882987a79f52f2933b5cedefe24e31df6fd0d38e8a802dbafd750d010a308d8985e5dd341c9035b37bf7391c5944c28131b47c7d5359d18fca598010ba9a63e27c55e6b421a807038c320564db170a308419cf00f2783c430dc861a710984d0429d3b3a7f6db849b4f5c05e0d87339704c5c7f5eede6adfc8776d666587b59320a30a759f6bcca8f35fcaadc406cc4b828c016c0ed23882987a79f52f2933b5cedefe24e31df6fd0d38e8a802dbafd750d010a308d028a021c5c31a1aa1e18eda74cfaf0fba1c454c17c2e0fc730dd07a19d0c77f7a905d54017292f3e800ca06b6977cd0a30b63f327df68581cdc02a66c1c65e906a06a1a3a8d7a6e38f7b6da944e8e6cc2db85fced5327d8c12945ceb33018272ca0a30a1584dfe1573df8ec88c7b74d76726b4821bfe84bf886dd3c0e3f74c2ea18aa62ca44c871fb1c63971fccf6937e6501f0a308de5a6200cebb09b2198e69fed84bcd512ec5cf317c5f1ee99aad03d2a9a8564bf3807c08da2664222268d59c34a06e40a30a1d9840eda3036fbf63eeea40146e4548553e6e1b2a653ab349b376f31b367c40d71fb59ff8e94b91daa99c262ec8b520a3096947de9e6068c22a7716656a2755a9551b0b66c2d1a741bf84a088fe1e840e992dc39861bf8ba3e8d5b6d21e8f57e640a308d8985e5dd341c9035b37bf7391c5944c28131b47c7d5359d18fca598010ba9a63e27c55e6b421a807038c320564db170a308c0d15baa72bfcd317e9b9402ca9bb6e7ae1db35ffce7faccae0bd19b3c8e5de7d5524aef0377770b3a90626627a93040a308a8bb292bcc481070d3afdbbc8789e2ab4b29c9603936e6d85f5ff71e23fc5b6d61009f0fa636b5d5b2dc309d39e3d750a30ab72cbc6575c3179680a58c0ecd5de46d2678ccbafc016746348ee5688edcb21b4e15bd37c70c508e3ea73103c2d566b0a30930743bfc7e18d3bd7351eaa74f477505268c1e4e1fd1ca3ccccdefb2595517343bbb8f5589c435c3c39323a4c0080f80a308d46e9aa0c1986056e407efc7013b7f271027d3c98ce96667faa98074ab0588a61681faf78644c11819a459a95689dab0a308dfa86c051edd28c3554a30e40531c898e5936ad3002711616ddd1b27054bc39caedd505a200c3d23a1c3f6b26c50ae90a308725b32751419f22a54485790f8187d1ba52d84a31ad45738a93777fcd1ccbec1652229923f82f37793ce0fc2763fb4c0a308fda66b8607af873f4c2c8218dd3ffc7940d411047eb199b5cd010156af4845d21dd2e65b0e44cfffb5e78271e9bb29d0a308fda66b8607af873f4c2c8218dd3ffc7940d411047eb199b5cd010156af4845d21dd2e65b0e44cfffb5e78271e9bb29d0a308aec5129a518010912215e1887191da94be419b4e75904c2ea745e2d253d707c088fa5b2c46dade1d162affe9f7ab17b0a30ae940a07850cf904b44f31cbf0e44824bae5ec36dcfdb7fad858f2a39dba38de82ca12b0ae939a34fce7a02e4b9789f80a309918433b8f0bc5e126da3fdef8d7b71456492dae6d2d07f2e10c7a7f852046f84ed0ce6d3bfec42200670db27dcf30370a3087231421a08ed28e7d357e2b37a26a458155c8d822d829344bd1029e5d175b5edfaa78f16f784f724a2caef124944c4f0a30ac69ae9e6c385a368df71d11ac68f45f05e005306df3c2bf98ed3577708256bd97f8c09d3f72115444077a9bb711d8d10a308a8bb292bcc481070d3afdbbc8789e2ab4b29c9603936e6d85f5ff71e23fc5b6d61009f0fa636b5d5b2dc309d39e3d751230a347267daf6b2170f61702d0d0a38393ce5083277e021c39e10da29eb6f30e9193b6f8cf5cba880911581f5ee007d868100112a0140a6b08d00510121a209dc96711bf0457051089f6d27ea5eb8fd289462919af3cf6e9ae0fc2c6b31dc82220ea52b95fa96711343b3d15b7a031477e4d8cf1088ab15d6a3f4ffe9af2c8f0a62a2086ee16a5cb373104cc6c91fde52c77762ebfe311a7a3dcc899abbb5130ea012712f20c0a308419cf00f2783c430dc861a710984d0429d3b3a7f6db849b4f5c05e0d87339704c5c7f5eede6adfc8776d666587b59320a308aec5129a518010912215e1887191da94be419b4e75904c2ea745e2d253d707c088fa5b2c46dade1d162affe9f7ab17b0a30996323af7e545fb6363ace53f1538c7ddc3eb0d985b2479da3ee4ace10cbc393b518bf02d1a2ddb2f5bdf09b473933ea0a308725b32751419f22a54485790f8187d1ba52d84a31ad45738a93777fcd1ccbec1652229923f82f37793ce0fc2763fb4c0a3081b676591b823270a3284ace7d81cbce2d6cdce55bb0e053874d7e3a08f729453009d3e662ec3130379f43c0f3210b6d0a30ab72cbc6575c3179680a58c0ecd5de46d2678ccbafc016746348ee5688edcb21b4e15bd37c70c508e3ea73103c2d566b0a30b5e898a1fc06d51c695712928f44646d15451340d1b3e480a40f03250160bc07d3b6691ec94361dd524d59d9df7f76d30a3099d83a0ba33161d8c6bbe80929fd9046d4dfdac43477ff85fea5bae925e6c179ad28eb338375ee2417acbd6576ee670a0a308419cf00f2783c430dc861a710984d0429d3b3a7f6db849b4f5c05e0d87339704c5c7f5eede6adfc8776d666587b59320a30ae940a07850cf904b44f31cbf0e44824bae5ec36dcfdb7fad858f2a39dba38de82ca12b0ae939a34fce7a02e4b9789f80a30a759f6bcca8f35fcaadc406cc4b828c016c0ed23882987a79f52f2933b5cedefe24e31df6fd0d38e8a802dbafd750d010a3081ea9f74ef7d935b807474e38954ae3934856219a23e074954b2e860c5a3c400f9aedb42cd27cb4ceb697ca36d1e58cb0a30958c2692b86b4d20eaea3bb45e9447ebbc5b93ccaf8d21ef659d0cefedf5c4371b31b460ae40e8243682bde505abac1e0a30b5e898a1fc06d51c695712928f44646d15451340d1b3e480a40f03250160bc07d3b6691ec94361dd524d59d9df7f76d30a308dfa86c051edd28c3554a30e40531c898e5936ad3002711616ddd1b27054bc39caedd505a200c3d23a1c3f6b26c50ae90a308de5a6200cebb09b2198e69fed84bcd512ec5cf317c5f1ee99aad03d2a9a8564bf3807c08da2664222268d59c34a06e40a3081b676591b823270a3284ace7d81cbce2d6cdce55bb0e053874d7e3a08f729453009d3e662ec3130379f43c0f3210b6d0a30996d10c3026b9344532b06c70a596f972a1e779a1f6106d3da9f6ba376bbf7ec82d2f52629e5dbf3f7d03b00f6b862af0a309763dde1b8028136a3ffd6dafd1f450e2cafb2819c7fa901f7c6e9cde8f2897ee7e9a45da6947fde1ad0d3836188eab50a30af61f263addfb41c46d66e60ecfb598a5942f648f58718b6b4e4c92019fdb12328efbff98703134bcf28e9c1fab4bb600a308419cf00f2783c430dc861a710984d0429d3b3a7f6db849b4f5c05e0d87339704c5c7f5eede6adfc8776d666587b59320a30a1584dfe1573df8ec88c7b74d76726b4821bfe84bf886dd3c0e3f74c2ea18aa62ca44c871fb1c63971fccf6937e6501f0a30a03c2a82374e04b2e0594c4ce14fb3f225b46f13188f0d8002a523c7dcfb939ae4856053c2c9c695374d7c3685df1ca50a308c0d15baa72bfcd317e9b9402ca9bb6e7ae1db35ffce7faccae0bd19b3c8e5de7d5524aef0377770b3a90626627a93040a30afa10af166a0dbf3a25ff86cd6f8e44cccc818c5e70cd70e4e98e226b158f3563450b3fb184d2649adbb11e53080d1ca0a3081ea9f74ef7d935b807474e38954ae3934856219a23e074954b2e860c5a3c400f9aedb42cd27cb4ceb697ca36d1e58cb0a308c0d15baa72bfcd317e9b9402ca9bb6e7ae1db35ffce7faccae0bd19b3c8e5de7d5524aef0377770b3a90626627a93040a3084d08d58c31bcd3cddf93e13d6f50203897384afa34644bff1135efe8e01c81c6a91ca6c234bb1e51ca32e41b828aaf90a30b24391aa97bfff29adc935d06a2b6d583433caf82f92de1980e0192d3b270323bdbf24b86dc61520a40c419dde3df4b30a30abd12678c73463ecea5867a80caf256d5c5e6ba53ff188b143a4d5be83365ad257edf39eaa1ba8753c4cdf4c632ff99e0a30aaddb0cb69ca18f14aed7054e98a24df0ff606aeff919d489f7884fd1bd183bcb46ea54bc363146e1a88db36dc20a7a40a308aec5129a518010912215e1887191da94be419b4e75904c2ea745e2d253d707c088fa5b2c46dade1d162affe9f7ab17b12308f16c4598feaf2e2e76881e417e04899085108b7a9d4f0ec6ecc780ef4bf5587ab6365f9f1cbfa7dc5d4e5b97660559b1a2030b29a801570e5fbd7fa1fe51db6288344d3a895ae524cf5a2d648068765ec7a1a209d7ae422cf5c38b5bb8a030ff03070dc1a8c96855da00e7ffaaa85cdaed231a31a20178bb630b5b40278e3ff8b556729c345759fb1b2d117179aa3a7ee0fe26394111a202483cdff2ec5e92cbdc6d9d6351a02a6344b1e8e544c9429abd164f3110706d71a207577f3d6d968ae1534ba9cc635680443a45ccc84f234324b6a08873d00214c931a20953024c6ded67e542650258c58347cef640ac2bb254c6df6bc3af9bf3c1a1f7a226b08c005103d1a20c0304dc886eb20af0541bca8850e7d80d1ec0f8d1306118b6658d8efaa956937222095989c595bf80fe0354b63867836b1d72e6eef621eeb79097b0b5d91523ff3292a20490c4e659f110b87f650c3d9a297105d2be4c1795649e1bf66a91a0c78df78582a2058000000000000000000000000000000000000000000000000000000000000002a205f6f02af29218292d21a69b64a794a7c0873b3e0f54611972863706e8cbdf3712a203d98ff53fee97f9d20a6a3a1c1e9b34e96ec8e041ae1d4fb912a47fb78e4a32a2a20178bb630b5b40278e3ff8b556729c345759fb1b2d117179aa3a7ee0fe26394112a202483cdff2ec5e92cbdc6d9d6351a02a6344b1e8e544c9429abd164f3110706d72a207577f3d6d968ae1534ba9cc635680443a45ccc84f234324b6a08873d00214c932a20953024c6ded67e542650258c58347cef640ac2bb254c6df6bc3af9bf3c1a1f7a3220bb7fced900c44155a131c2b07d38ad23f21041e4cf42083b9d07b25da0db01e73a20b970bffeca02a8cf418da501b117fcec2447427847b38d3745bca80e8ee4ebc83a20984583c7e774d9d27515347e0769a6723ecf52186a8ade0495229698cb6e194c3a206e817161402150ae7a3c42df6d68062e41bf358f5966510d5be0b8c40188772d3a202d918e0d3493dd8f11340f56151e47ec9951e3eab3bb38b1d7a31023e5c5380c42680a04ffffffff12608d158dfa32280968a180e696e74688bc2e123fb398fae7ac22467fa9b6113bcb68bccb23fee4572889df71606f75223f170e6ec0ba928d6081e72b1620cca45e0f16a9ec097a67f67a90fa5f6953e205211356c0543a8583bb9ddfcd819a407d48d1051ac5040a20b05c0c19cdf50c145c0a8ff11b7595f902ca0743c190ebc19697271f01b8cdf81220eaa8c40899a61ae59615cf9985f5e2194f8fd2b57d273be63bde6733e89b12ab1220c6fb1c6db12a5e7e13df9d0ca5630288a0c914abd86d623df6ab2b1abb397ef112207cbba12e848e6ee5dbaeffa7fa9f4bfc0b6245f37f17d142c10bf006ef1257291220afb90060ed291e971fa95c162ae785eb7478c9e8e44626664a9def739ac4e9e71220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c18c0052220005125020000000000000000000000000000000000000000000000000000000022204a72777507df52a385084a6c295eb2999ba65cfc7eeb2da31ebef55c84a11791222036ac1e2728eb9f6ad8ecf84a991b1fa552f35737edccafd53c3ec7bd7ec467362220afb90060ed291e971fa95c162ae785eb7478c9e8e44626664a9def739ac4e9e72220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c2a204b9aeba598f30b44efd85bb8aa5b3bf5bee9b4d68890919384442890bff8ff8f32204783945e1cc103330a7bc9208db8f92dfb3b6d07737384f66b8fb71ee7134ab73220a09a2b87124e2c710b9d90a696327a3a76e1bde89ca3efbc730de5c19fa0eaa93220c1234758f45f2f40f0991e1da8ef573159c758d1b8ab94c2772f4236f4cdd0b53220dc872904ce87bd6bcd526e1f0af10e17dc5c5e51fa9c4ee3614b82ab84bec9d73220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c").to_vec(),
            cons_slot: 640,
            cons_l1_current_sync_committee: PublicKey::try_from(hex!("971e9b8afd780ac17e039764f57be7713145a7e64c5e3a02f6c638e47f76acea4b2150d9f3de24d626caf97a4cad510b").to_vec()).unwrap(),
            cons_l1_next_sync_committee: PublicKey::try_from(hex!("a347267daf6b2170f61702d0d0a38393ce5083277e021c39e10da29eb6f30e9193b6f8cf5cba880911581f5ee007d868").to_vec()).unwrap(),
        }, TestCase {
            raw_l1_header: hex!("0af50c0af20c0a3091709ee06497b9ac049325853d64947290189a8c2322e3a500d91e23ea02dc158b6db63ae558b3b7670357a151cd60710a309918433b8f0bc5e126da3fdef8d7b71456492dae6d2d07f2e10c7a7f852046f84ed0ce6d3bfec42200670db27dcf30370a308d46e9aa0c1986056e407efc7013b7f271027d3c98ce96667faa98074ab0588a61681faf78644c11819a459a95689dab0a30afa10af166a0dbf3a25ff86cd6f8e44cccc818c5e70cd70e4e98e226b158f3563450b3fb184d2649adbb11e53080d1ca0a30a54fe5c26059ed60b4f0b66ef7b0bf167580504525f83c169507dc812816df41b1da6128341c23977300dffd32a32f410a30aaddb0cb69ca18f14aed7054e98a24df0ff606aeff919d489f7884fd1bd183bcb46ea54bc363146e1a88db36dc20a7a40a30a759f6bcca8f35fcaadc406cc4b828c016c0ed23882987a79f52f2933b5cedefe24e31df6fd0d38e8a802dbafd750d010a308d8985e5dd341c9035b37bf7391c5944c28131b47c7d5359d18fca598010ba9a63e27c55e6b421a807038c320564db170a308419cf00f2783c430dc861a710984d0429d3b3a7f6db849b4f5c05e0d87339704c5c7f5eede6adfc8776d666587b59320a30a759f6bcca8f35fcaadc406cc4b828c016c0ed23882987a79f52f2933b5cedefe24e31df6fd0d38e8a802dbafd750d010a308d028a021c5c31a1aa1e18eda74cfaf0fba1c454c17c2e0fc730dd07a19d0c77f7a905d54017292f3e800ca06b6977cd0a30b63f327df68581cdc02a66c1c65e906a06a1a3a8d7a6e38f7b6da944e8e6cc2db85fced5327d8c12945ceb33018272ca0a30a1584dfe1573df8ec88c7b74d76726b4821bfe84bf886dd3c0e3f74c2ea18aa62ca44c871fb1c63971fccf6937e6501f0a308de5a6200cebb09b2198e69fed84bcd512ec5cf317c5f1ee99aad03d2a9a8564bf3807c08da2664222268d59c34a06e40a30a1d9840eda3036fbf63eeea40146e4548553e6e1b2a653ab349b376f31b367c40d71fb59ff8e94b91daa99c262ec8b520a3096947de9e6068c22a7716656a2755a9551b0b66c2d1a741bf84a088fe1e840e992dc39861bf8ba3e8d5b6d21e8f57e640a308d8985e5dd341c9035b37bf7391c5944c28131b47c7d5359d18fca598010ba9a63e27c55e6b421a807038c320564db170a308c0d15baa72bfcd317e9b9402ca9bb6e7ae1db35ffce7faccae0bd19b3c8e5de7d5524aef0377770b3a90626627a93040a308a8bb292bcc481070d3afdbbc8789e2ab4b29c9603936e6d85f5ff71e23fc5b6d61009f0fa636b5d5b2dc309d39e3d750a30ab72cbc6575c3179680a58c0ecd5de46d2678ccbafc016746348ee5688edcb21b4e15bd37c70c508e3ea73103c2d566b0a30930743bfc7e18d3bd7351eaa74f477505268c1e4e1fd1ca3ccccdefb2595517343bbb8f5589c435c3c39323a4c0080f80a308d46e9aa0c1986056e407efc7013b7f271027d3c98ce96667faa98074ab0588a61681faf78644c11819a459a95689dab0a308dfa86c051edd28c3554a30e40531c898e5936ad3002711616ddd1b27054bc39caedd505a200c3d23a1c3f6b26c50ae90a308725b32751419f22a54485790f8187d1ba52d84a31ad45738a93777fcd1ccbec1652229923f82f37793ce0fc2763fb4c0a308fda66b8607af873f4c2c8218dd3ffc7940d411047eb199b5cd010156af4845d21dd2e65b0e44cfffb5e78271e9bb29d0a308fda66b8607af873f4c2c8218dd3ffc7940d411047eb199b5cd010156af4845d21dd2e65b0e44cfffb5e78271e9bb29d0a308aec5129a518010912215e1887191da94be419b4e75904c2ea745e2d253d707c088fa5b2c46dade1d162affe9f7ab17b0a30ae940a07850cf904b44f31cbf0e44824bae5ec36dcfdb7fad858f2a39dba38de82ca12b0ae939a34fce7a02e4b9789f80a309918433b8f0bc5e126da3fdef8d7b71456492dae6d2d07f2e10c7a7f852046f84ed0ce6d3bfec42200670db27dcf30370a3087231421a08ed28e7d357e2b37a26a458155c8d822d829344bd1029e5d175b5edfaa78f16f784f724a2caef124944c4f0a30ac69ae9e6c385a368df71d11ac68f45f05e005306df3c2bf98ed3577708256bd97f8c09d3f72115444077a9bb711d8d10a308a8bb292bcc481070d3afdbbc8789e2ab4b29c9603936e6d85f5ff71e23fc5b6d61009f0fa636b5d5b2dc309d39e3d751230a347267daf6b2170f61702d0d0a38393ce5083277e021c39e10da29eb6f30e9193b6f8cf5cba880911581f5ee007d86812a0140a6b08d00510121a209dc96711bf0457051089f6d27ea5eb8fd289462919af3cf6e9ae0fc2c6b31dc82220ea52b95fa96711343b3d15b7a031477e4d8cf1088ab15d6a3f4ffe9af2c8f0a62a2086ee16a5cb373104cc6c91fde52c77762ebfe311a7a3dcc899abbb5130ea012712f20c0a308419cf00f2783c430dc861a710984d0429d3b3a7f6db849b4f5c05e0d87339704c5c7f5eede6adfc8776d666587b59320a308aec5129a518010912215e1887191da94be419b4e75904c2ea745e2d253d707c088fa5b2c46dade1d162affe9f7ab17b0a30996323af7e545fb6363ace53f1538c7ddc3eb0d985b2479da3ee4ace10cbc393b518bf02d1a2ddb2f5bdf09b473933ea0a308725b32751419f22a54485790f8187d1ba52d84a31ad45738a93777fcd1ccbec1652229923f82f37793ce0fc2763fb4c0a3081b676591b823270a3284ace7d81cbce2d6cdce55bb0e053874d7e3a08f729453009d3e662ec3130379f43c0f3210b6d0a30ab72cbc6575c3179680a58c0ecd5de46d2678ccbafc016746348ee5688edcb21b4e15bd37c70c508e3ea73103c2d566b0a30b5e898a1fc06d51c695712928f44646d15451340d1b3e480a40f03250160bc07d3b6691ec94361dd524d59d9df7f76d30a3099d83a0ba33161d8c6bbe80929fd9046d4dfdac43477ff85fea5bae925e6c179ad28eb338375ee2417acbd6576ee670a0a308419cf00f2783c430dc861a710984d0429d3b3a7f6db849b4f5c05e0d87339704c5c7f5eede6adfc8776d666587b59320a30ae940a07850cf904b44f31cbf0e44824bae5ec36dcfdb7fad858f2a39dba38de82ca12b0ae939a34fce7a02e4b9789f80a30a759f6bcca8f35fcaadc406cc4b828c016c0ed23882987a79f52f2933b5cedefe24e31df6fd0d38e8a802dbafd750d010a3081ea9f74ef7d935b807474e38954ae3934856219a23e074954b2e860c5a3c400f9aedb42cd27cb4ceb697ca36d1e58cb0a30958c2692b86b4d20eaea3bb45e9447ebbc5b93ccaf8d21ef659d0cefedf5c4371b31b460ae40e8243682bde505abac1e0a30b5e898a1fc06d51c695712928f44646d15451340d1b3e480a40f03250160bc07d3b6691ec94361dd524d59d9df7f76d30a308dfa86c051edd28c3554a30e40531c898e5936ad3002711616ddd1b27054bc39caedd505a200c3d23a1c3f6b26c50ae90a308de5a6200cebb09b2198e69fed84bcd512ec5cf317c5f1ee99aad03d2a9a8564bf3807c08da2664222268d59c34a06e40a3081b676591b823270a3284ace7d81cbce2d6cdce55bb0e053874d7e3a08f729453009d3e662ec3130379f43c0f3210b6d0a30996d10c3026b9344532b06c70a596f972a1e779a1f6106d3da9f6ba376bbf7ec82d2f52629e5dbf3f7d03b00f6b862af0a309763dde1b8028136a3ffd6dafd1f450e2cafb2819c7fa901f7c6e9cde8f2897ee7e9a45da6947fde1ad0d3836188eab50a30af61f263addfb41c46d66e60ecfb598a5942f648f58718b6b4e4c92019fdb12328efbff98703134bcf28e9c1fab4bb600a308419cf00f2783c430dc861a710984d0429d3b3a7f6db849b4f5c05e0d87339704c5c7f5eede6adfc8776d666587b59320a30a1584dfe1573df8ec88c7b74d76726b4821bfe84bf886dd3c0e3f74c2ea18aa62ca44c871fb1c63971fccf6937e6501f0a30a03c2a82374e04b2e0594c4ce14fb3f225b46f13188f0d8002a523c7dcfb939ae4856053c2c9c695374d7c3685df1ca50a308c0d15baa72bfcd317e9b9402ca9bb6e7ae1db35ffce7faccae0bd19b3c8e5de7d5524aef0377770b3a90626627a93040a30afa10af166a0dbf3a25ff86cd6f8e44cccc818c5e70cd70e4e98e226b158f3563450b3fb184d2649adbb11e53080d1ca0a3081ea9f74ef7d935b807474e38954ae3934856219a23e074954b2e860c5a3c400f9aedb42cd27cb4ceb697ca36d1e58cb0a308c0d15baa72bfcd317e9b9402ca9bb6e7ae1db35ffce7faccae0bd19b3c8e5de7d5524aef0377770b3a90626627a93040a3084d08d58c31bcd3cddf93e13d6f50203897384afa34644bff1135efe8e01c81c6a91ca6c234bb1e51ca32e41b828aaf90a30b24391aa97bfff29adc935d06a2b6d583433caf82f92de1980e0192d3b270323bdbf24b86dc61520a40c419dde3df4b30a30abd12678c73463ecea5867a80caf256d5c5e6ba53ff188b143a4d5be83365ad257edf39eaa1ba8753c4cdf4c632ff99e0a30aaddb0cb69ca18f14aed7054e98a24df0ff606aeff919d489f7884fd1bd183bcb46ea54bc363146e1a88db36dc20a7a40a308aec5129a518010912215e1887191da94be419b4e75904c2ea745e2d253d707c088fa5b2c46dade1d162affe9f7ab17b12308f16c4598feaf2e2e76881e417e04899085108b7a9d4f0ec6ecc780ef4bf5587ab6365f9f1cbfa7dc5d4e5b97660559b1a2030b29a801570e5fbd7fa1fe51db6288344d3a895ae524cf5a2d648068765ec7a1a209d7ae422cf5c38b5bb8a030ff03070dc1a8c96855da00e7ffaaa85cdaed231a31a20178bb630b5b40278e3ff8b556729c345759fb1b2d117179aa3a7ee0fe26394111a202483cdff2ec5e92cbdc6d9d6351a02a6344b1e8e544c9429abd164f3110706d71a207577f3d6d968ae1534ba9cc635680443a45ccc84f234324b6a08873d00214c931a20953024c6ded67e542650258c58347cef640ac2bb254c6df6bc3af9bf3c1a1f7a226b08c005103d1a20c0304dc886eb20af0541bca8850e7d80d1ec0f8d1306118b6658d8efaa956937222095989c595bf80fe0354b63867836b1d72e6eef621eeb79097b0b5d91523ff3292a20490c4e659f110b87f650c3d9a297105d2be4c1795649e1bf66a91a0c78df78582a2058000000000000000000000000000000000000000000000000000000000000002a205f6f02af29218292d21a69b64a794a7c0873b3e0f54611972863706e8cbdf3712a203d98ff53fee97f9d20a6a3a1c1e9b34e96ec8e041ae1d4fb912a47fb78e4a32a2a20178bb630b5b40278e3ff8b556729c345759fb1b2d117179aa3a7ee0fe26394112a202483cdff2ec5e92cbdc6d9d6351a02a6344b1e8e544c9429abd164f3110706d72a207577f3d6d968ae1534ba9cc635680443a45ccc84f234324b6a08873d00214c932a20953024c6ded67e542650258c58347cef640ac2bb254c6df6bc3af9bf3c1a1f7a3220bb7fced900c44155a131c2b07d38ad23f21041e4cf42083b9d07b25da0db01e73a20b970bffeca02a8cf418da501b117fcec2447427847b38d3745bca80e8ee4ebc83a20984583c7e774d9d27515347e0769a6723ecf52186a8ade0495229698cb6e194c3a206e817161402150ae7a3c42df6d68062e41bf358f5966510d5be0b8c40188772d3a202d918e0d3493dd8f11340f56151e47ec9951e3eab3bb38b1d7a31023e5c5380c42680a04ffffffff12608d158dfa32280968a180e696e74688bc2e123fb398fae7ac22467fa9b6113bcb68bccb23fee4572889df71606f75223f170e6ec0ba928d6081e72b1620cca45e0f16a9ec097a67f67a90fa5f6953e205211356c0543a8583bb9ddfcd819a407d48d1051ac5040a20b05c0c19cdf50c145c0a8ff11b7595f902ca0743c190ebc19697271f01b8cdf81220eaa8c40899a61ae59615cf9985f5e2194f8fd2b57d273be63bde6733e89b12ab1220c6fb1c6db12a5e7e13df9d0ca5630288a0c914abd86d623df6ab2b1abb397ef112207cbba12e848e6ee5dbaeffa7fa9f4bfc0b6245f37f17d142c10bf006ef1257291220afb90060ed291e971fa95c162ae785eb7478c9e8e44626664a9def739ac4e9e71220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c18c0052220005125020000000000000000000000000000000000000000000000000000000022204a72777507df52a385084a6c295eb2999ba65cfc7eeb2da31ebef55c84a11791222036ac1e2728eb9f6ad8ecf84a991b1fa552f35737edccafd53c3ec7bd7ec467362220afb90060ed291e971fa95c162ae785eb7478c9e8e44626664a9def739ac4e9e72220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c2a204b9aeba598f30b44efd85bb8aa5b3bf5bee9b4d68890919384442890bff8ff8f32204783945e1cc103330a7bc9208db8f92dfb3b6d07737384f66b8fb71ee7134ab73220a09a2b87124e2c710b9d90a696327a3a76e1bde89ca3efbc730de5c19fa0eaa93220c1234758f45f2f40f0991e1da8ef573159c758d1b8ab94c2772f4236f4cdd0b53220dc872904ce87bd6bcd526e1f0af10e17dc5c5e51fa9c4ee3614b82ab84bec9d73220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c").to_vec(),
            cons_slot: 704,
            cons_l1_current_sync_committee: PublicKey::try_from(hex!("a347267daf6b2170f61702d0d0a38393ce5083277e021c39e10da29eb6f30e9193b6f8cf5cba880911581f5ee007d868").to_vec()).unwrap(),
            cons_l1_next_sync_committee: PublicKey::try_from(hex!("8f16c4598feaf2e2e76881e417e04899085108b7a9d4f0ec6ecc780ef4bf5587ab6365f9f1cbfa7dc5d4e5b97660559b").to_vec()).unwrap(),
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
                .verify(1747788332, &l1_config, &cons_state)
                .unwrap();
            assert_eq!(
                l1_consensus.slot,
                l1_header.consensus_update.finalized_header.0.slot
            );
            if l1_header.trusted_sync_committee.is_next {
                assert_eq!(
                    l1_consensus.current_sync_committee, cons_state.next_sync_committee,
                    "result {i}"
                );
            } else {
                assert_eq!(
                    l1_consensus.current_sync_committee, cons_state.current_sync_committee,
                    "result {i}"
                );
            }
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
