use crate::errors::Error;
use crate::misc::new_timestamp;
use alloc::string::ToString;
use alloc::vec::Vec;
use ethereum_consensus::beacon::{BeaconBlockHeader, Epoch, Root, Slot};
use ethereum_consensus::bls::{PublicKey, Signature};
use ethereum_consensus::compute::{
    compute_sync_committee_period_at_slot, compute_timestamp_at_slot, hash_tree_root,
};
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
use light_client::types::Time;
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
    pub timestamp: Time,
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

impl<const SYNC_COMMITTEE_SIZE: usize> TrustedSyncCommittee<SYNC_COMMITTEE_SIZE> {
    pub fn validate(&self) -> Result<(), Error> {
        self.sync_committee
            .validate()
            .map_err(Error::SyncCommitteeValidateError)?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct L1Header<const SYNC_COMMITTEE_SIZE: usize> {
    pub trusted_sync_committee: TrustedSyncCommittee<SYNC_COMMITTEE_SIZE>,
    pub consensus_update: ConsensusUpdateInfo<SYNC_COMMITTEE_SIZE>,
    pub execution_update: ExecutionUpdateInfo,
    pub timestamp: Time,
}

impl<const SYNC_COMMITTEE_SIZE: usize> L1Header<SYNC_COMMITTEE_SIZE> {
    pub fn validate<C: ChainContext>(&self, ctx: &C) -> Result<(), Error> {
        self.trusted_sync_committee.validate()?;
        if self.execution_update.block_number == U64(0) {
            return Err(Error::ZeroL1ExecutionBlockNumberError);
        }
        let header_timestamp_nanos = self.timestamp.as_unix_timestamp_nanos();
        let timestamp_secs =
            compute_timestamp_at_slot(ctx, self.consensus_update.finalized_beacon_header().slot);
        let timestamp_nanos = u128::from(timestamp_secs.0)
            .checked_mul(1_000_000_000)
            .ok_or_else(|| Error::TimestampOverflowError(timestamp_secs.0))?;
        if header_timestamp_nanos != timestamp_nanos {
            return Err(Error::UnexpectedL1Timestamp(
                timestamp_nanos,
                header_timestamp_nanos,
            ));
        }
        Ok(())
    }
}

impl<const SYNC_COMMITTEE_SIZE: usize> L1Header<SYNC_COMMITTEE_SIZE> {
    pub fn verify(
        &self,
        now: u64,
        l1_config: &L1Config,
        consensus_state: &L1Consensus,
    ) -> Result<(bool, L1Consensus), Error> {
        let ctx = l1_config.build_context(now);

        self.validate(&ctx)?;

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
        apply_updates(
            &ctx,
            consensus_state,
            &self.consensus_update,
            self.timestamp,
        )
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
            timestamp: new_timestamp(value.timestamp)?,
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
    header_timestamp: Time,
) -> Result<(bool, L1Consensus), Error> {
    let store_period = consensus_state.current_l1_period(ctx);
    let header = &consensus_update.finalized_header.0;
    let update_finalized_slot = header.slot;
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
                timestamp: header_timestamp,
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
                    timestamp: header_timestamp,
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
    use light_client::types::Time;
    use optimism_ibc_proto::ibc::lightclients::optimism::v1::L1Config as RawL1Config;
    use optimism_ibc_proto::ibc::lightclients::optimism::v1::L1Header as RawL1Header;
    use prost::Message;

    pub fn get_l1_config() -> L1Config {
        // created by optimism-ibc-relay-prover#prover_test.go#TestSetupHeadersForUpdateShort
        let raw_l1_config = hex!("0a20d61ea484febacfae5298d52a2b581f3e305a51f3112a9241b968dccf019f7b11100118b0d6cec106226f0a0410000038120e0a04200000381a0608691036183712140a04300000381a0c08691036183720192812301612140a04400000381a0c08691036183720192812301612140a04500000381a0c08691036183720192822302612150a04600000381a0d08a90110561857201928223026280630083808420408021003").to_vec();
        let raw_l1_config = RawL1Config::decode(&*raw_l1_config).unwrap();
        L1Config::try_from(raw_l1_config).unwrap()
    }

    pub fn get_raw_l1_header() -> RawL1Header {
        // created by optimism-ibc-relay-prover#prover_test.go#TestSetupHeadersForUpdateShort
        let raw_l1_header = hex!("0af50c0af20c0a308d028a021c5c31a1aa1e18eda74cfaf0fba1c454c17c2e0fc730dd07a19d0c77f7a905d54017292f3e800ca06b6977cd0a30930743bfc7e18d3bd7351eaa74f477505268c1e4e1fd1ca3ccccdefb2595517343bbb8f5589c435c3c39323a4c0080f80a3081ea9f74ef7d935b807474e38954ae3934856219a23e074954b2e860c5a3c400f9aedb42cd27cb4ceb697ca36d1e58cb0a30a35c6004f387430c3797ab0157af7b824c8fe106241c7cdeb897d900c0f9e4bb945ff2a6b88cbd10e35ec48aaa554ecb0a30abd12678c73463ecea5867a80caf256d5c5e6ba53ff188b143a4d5be83365ad257edf39eaa1ba8753c4cdf4c632ff99e0a30ab64f900c770e2b99de6b86b4390bbd1579bd48dccec55800adbcf52e006f22128e9971bbf3a92cc0105b0974849935a0a30a35c6004f387430c3797ab0157af7b824c8fe106241c7cdeb897d900c0f9e4bb945ff2a6b88cbd10e35ec48aaa554ecb0a30af61f263addfb41c46d66e60ecfb598a5942f648f58718b6b4e4c92019fdb12328efbff98703134bcf28e9c1fab4bb600a30ab72cbc6575c3179680a58c0ecd5de46d2678ccbafc016746348ee5688edcb21b4e15bd37c70c508e3ea73103c2d566b0a3086e014747c7922ccfc2b9d4bf6c1ecf0dc800197037858d0b85ab1944b4c3c14b95e0ed325bc42a6f467bc47ec27bc7b0a3081fa222737fe818b43f55f209f42adaee135b2801d02709617fc88c2871852358260ace97cf323e761b5cc18bc7325b30a30b63f327df68581cdc02a66c1c65e906a06a1a3a8d7a6e38f7b6da944e8e6cc2db85fced5327d8c12945ceb33018272ca0a30996d10c3026b9344532b06c70a596f972a1e779a1f6106d3da9f6ba376bbf7ec82d2f52629e5dbf3f7d03b00f6b862af0a30b570dde8ee80512e3d031caf22e775c60f7f5a6cbdeb3e52e24cf8c867d38569a53dd19cdc36a03a1bbb3a8d94b036700a308725b32751419f22a54485790f8187d1ba52d84a31ad45738a93777fcd1ccbec1652229923f82f37793ce0fc2763fb4c0a30a2e2d8384fc87a512ee34eb43405fd82572c9d7cd96e155a382cda284e8df9eb7189c25b7473d89c63ea4e6080e10ff80a30a8fa3584a92b079c8c73ed1553e5e161a0b21325fc2fc4e24a892354a899c7fc0bfb436a97a7ed1fc71bccda438ea7150a30b27ad13afc8ff30e087797b344c8382bb0a84447549f1b0274059ddd652276e7b148ba8808a10cc45746762957d4efbe0a30a2e2d8384fc87a512ee34eb43405fd82572c9d7cd96e155a382cda284e8df9eb7189c25b7473d89c63ea4e6080e10ff80a30ad9222dec71ff8ee6bc0426ffe7b5e66f96738225db281dd20027a1556d089fdebd040abfbc2041d6c1a0d8fdcfce1830a308fda66b8607af873f4c2c8218dd3ffc7940d411047eb199b5cd010156af4845d21dd2e65b0e44cfffb5e78271e9bb29d0a3081ea9f74ef7d935b807474e38954ae3934856219a23e074954b2e860c5a3c400f9aedb42cd27cb4ceb697ca36d1e58cb0a30ad9222dec71ff8ee6bc0426ffe7b5e66f96738225db281dd20027a1556d089fdebd040abfbc2041d6c1a0d8fdcfce1830a30ac69ae9e6c385a368df71d11ac68f45f05e005306df3c2bf98ed3577708256bd97f8c09d3f72115444077a9bb711d8d10a30a804e4fa8d1391a9d078aa93985a12503b84ce4f6f1f9e70ab7fca421e1cf972538666299d4c1bfc39327b469b2db7a80a3081b676591b823270a3284ace7d81cbce2d6cdce55bb0e053874d7e3a08f729453009d3e662ec3130379f43c0f3210b6d0a30a804e4fa8d1391a9d078aa93985a12503b84ce4f6f1f9e70ab7fca421e1cf972538666299d4c1bfc39327b469b2db7a80a30ab72cbc6575c3179680a58c0ecd5de46d2678ccbafc016746348ee5688edcb21b4e15bd37c70c508e3ea73103c2d566b0a308de5a6200cebb09b2198e69fed84bcd512ec5cf317c5f1ee99aad03d2a9a8564bf3807c08da2664222268d59c34a06e40a30b24391aa97bfff29adc935d06a2b6d583433caf82f92de1980e0192d3b270323bdbf24b86dc61520a40c419dde3df4b30a308aec5129a518010912215e1887191da94be419b4e75904c2ea745e2d253d707c088fa5b2c46dade1d162affe9f7ab17b0a3081fa222737fe818b43f55f209f42adaee135b2801d02709617fc88c2871852358260ace97cf323e761b5cc18bc7325b3123085adc9a2503bd8fe2295a0472b9bf5d49a0be1ccc3da908b990c2f2de52b47fc26307a8f72ec4580078be8179cc81aa912a0140a6b08900110041a20e568005eb8b8fea56152da67847361ce051cdb2c2aebb4c3199743e2c375243122204950949bf0a046d37d0621bb8438ec314dfd78b1ee51b7307cfa99357efc4cbb2a20b2d2cfe8455274742d4672d7d5bb05fce696aee8eb26d99f6d45e059130a537d12f20c0a308dfa86c051edd28c3554a30e40531c898e5936ad3002711616ddd1b27054bc39caedd505a200c3d23a1c3f6b26c50ae90a30a03c2a82374e04b2e0594c4ce14fb3f225b46f13188f0d8002a523c7dcfb939ae4856053c2c9c695374d7c3685df1ca50a30ad9222dec71ff8ee6bc0426ffe7b5e66f96738225db281dd20027a1556d089fdebd040abfbc2041d6c1a0d8fdcfce1830a30b09cb155daf2022afd18114a352e506a84065c80573cb0c7c310cbe92e2706cdcf91f74bbd9e464f74e3d831386d50330a308d8985e5dd341c9035b37bf7391c5944c28131b47c7d5359d18fca598010ba9a63e27c55e6b421a807038c320564db170a30958c2692b86b4d20eaea3bb45e9447ebbc5b93ccaf8d21ef659d0cefedf5c4371b31b460ae40e8243682bde505abac1e0a3099d83a0ba33161d8c6bbe80929fd9046d4dfdac43477ff85fea5bae925e6c179ad28eb338375ee2417acbd6576ee670a0a3099d83a0ba33161d8c6bbe80929fd9046d4dfdac43477ff85fea5bae925e6c179ad28eb338375ee2417acbd6576ee670a0a30ae5302796cfeca685eaf37ffd5baeb32121f2f07415bee26cc0051ee513ff3932d2c365e3d9f87b0949a5980445cb64c0a3081fa222737fe818b43f55f209f42adaee135b2801d02709617fc88c2871852358260ace97cf323e761b5cc18bc7325b30a308dfa86c051edd28c3554a30e40531c898e5936ad3002711616ddd1b27054bc39caedd505a200c3d23a1c3f6b26c50ae90a3081ea9f74ef7d935b807474e38954ae3934856219a23e074954b2e860c5a3c400f9aedb42cd27cb4ceb697ca36d1e58cb0a308de5a6200cebb09b2198e69fed84bcd512ec5cf317c5f1ee99aad03d2a9a8564bf3807c08da2664222268d59c34a06e40a309918433b8f0bc5e126da3fdef8d7b71456492dae6d2d07f2e10c7a7f852046f84ed0ce6d3bfec42200670db27dcf30370a30b24391aa97bfff29adc935d06a2b6d583433caf82f92de1980e0192d3b270323bdbf24b86dc61520a40c419dde3df4b30a30ae5302796cfeca685eaf37ffd5baeb32121f2f07415bee26cc0051ee513ff3932d2c365e3d9f87b0949a5980445cb64c0a30af61f263addfb41c46d66e60ecfb598a5942f648f58718b6b4e4c92019fdb12328efbff98703134bcf28e9c1fab4bb600a30ab72cbc6575c3179680a58c0ecd5de46d2678ccbafc016746348ee5688edcb21b4e15bd37c70c508e3ea73103c2d566b0a30a759f6bcca8f35fcaadc406cc4b828c016c0ed23882987a79f52f2933b5cedefe24e31df6fd0d38e8a802dbafd750d010a30996323af7e545fb6363ace53f1538c7ddc3eb0d985b2479da3ee4ace10cbc393b518bf02d1a2ddb2f5bdf09b473933ea0a308dfa86c051edd28c3554a30e40531c898e5936ad3002711616ddd1b27054bc39caedd505a200c3d23a1c3f6b26c50ae90a30a75ca9447dca3a3745ada36731187ddd1f6a152cf15d7446b785eab381e5c8562c1202a6e7a24080bc6b619a161113db0a30abd12678c73463ecea5867a80caf256d5c5e6ba53ff188b143a4d5be83365ad257edf39eaa1ba8753c4cdf4c632ff99e0a30a75ca9447dca3a3745ada36731187ddd1f6a152cf15d7446b785eab381e5c8562c1202a6e7a24080bc6b619a161113db0a3081fa222737fe818b43f55f209f42adaee135b2801d02709617fc88c2871852358260ace97cf323e761b5cc18bc7325b30a30ae940a07850cf904b44f31cbf0e44824bae5ec36dcfdb7fad858f2a39dba38de82ca12b0ae939a34fce7a02e4b9789f80a30ab40dc1cfe273ad0da700c64f8fc94f91db253ca3acf20e336d9bd09de67eec5c7d3506285d83c7bb6a08d64b77e5f2d0a30a62c0205fb22df8535c0b70076486e69dfa908feddae79e4a94a9d47b97ed190d228e1c6217e84a59882bb992dacae300a3084d08d58c31bcd3cddf93e13d6f50203897384afa34644bff1135efe8e01c81c6a91ca6c234bb1e51ca32e41b828aaf90a30a35c6004f387430c3797ab0157af7b824c8fe106241c7cdeb897d900c0f9e4bb945ff2a6b88cbd10e35ec48aaa554ecb0a309763dde1b8028136a3ffd6dafd1f450e2cafb2819c7fa901f7c6e9cde8f2897ee7e9a45da6947fde1ad0d3836188eab50a30af89ab00a0eab1131645292a9cfba583a69a1e3ac58b210e262494853e67385aeb50d4af428bdd577b9399daa96d8b20123085f0c0ae9270a95db7038bf1119fa392dd924ac9e53441c9d4689d5e34f00f2728480b26124fc2164890661974275c2e1a20022473f12830724d352adb61f2987b0b589320ef97a21e9bdef7701be164af421a200058efaad25a313e94cf9dcdb3aa0f09c2734d4dfb255d1589fbddfb2a3708b21a20fb4ba48e23eecd090c2be74b1636c9c59a0548acb19d1631244151fc571e28ac1a20824ea955b2b1f8f2747f8ba118f70638cda86a9f7dbba3012f71a776280413481a2042ae940f8d70f48450976cb4176cb48d18767862dbb7fea59fc215200c915bfa1a20953024c6ded67e542650258c58347cef640ac2bb254c6df6bc3af9bf3c1a1f7a226b08800110371a207888b746688c0590d777376ee1a40d2561a54a3796122276dbe349bff5d8979d2220a0fde9f90d3bb44c0a83f8ca3b93a3dc05ac3a224c94de85e9b8caeca9a80fe12a203d4cfcb07bbfd80be4de22f685c72f9e412a7c705c599049ed2700236b7613d02a2010000000000000000000000000000000000000000000000000000000000000002a205f6f02af29218292d21a69b64a794a7c0873b3e0f54611972863706e8cbdf3712a20455dcc2cf133a8ecc1bb0be8288a2a4627b319c27133aa7b4a6fa603f55348bb2a20fb4ba48e23eecd090c2be74b1636c9c59a0548acb19d1631244151fc571e28ac2a20824ea955b2b1f8f2747f8ba118f70638cda86a9f7dbba3012f71a776280413482a2042ae940f8d70f48450976cb4176cb48d18767862dbb7fea59fc215200c915bfa2a20953024c6ded67e542650258c58347cef640ac2bb254c6df6bc3af9bf3c1a1f7a3220e5b01b5373ec4626434156e4395b7e2df8482e37db873141bf4f882cdaff71f43a2057736b4ddc3880e823134c5a63fb9a12c422d0bafa2d20c101576a798c63ff823a203e9469a0c2885a4e8e6621b323f05c211f6aa6f13fb5cbabf94eb64d0ae8d5173a206e817161402150ae7a3c42df6d68062e41bf358f5966510d5be0b8c40188772d3a20b18033102b68eed8fbf258ea7505eb3d54856b1c62e6a7e12368fcdde03edab642680a04ffffffff1260b17fb03138cea9966a12c4932fd332bec53cc93024cd0ad963078ecb0115581921bbf089e724145ebbf705b16175380a122154088a98ff86d26b8c9ef44d83566cf5cd48d315cf7d264f84fbf631235969532fad5f5e2c8b71a694bc652f66634891011ac5040a2094bb8ffc162d8cba0be2997c2dacfb91aff59877bedc0209ddcec2ce98ec4ae0122056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b42112208616e186386466f9f7a3233ddfa6785ff7639e21407cd1ed27f1192d18e8dec01220cd68c64d32571e9bcfd6fde0e8c6e4571ae634e6c00a78f1935c3730ae275c201220f01001e7db925582526307c4f98b08c0a2ff423abe9f67aee294bce2ebfc19c51220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c1880012220f4ad06020000000000000000000000000000000000000000000000000000000022205f3fbb610adbcfa90038371fcf703ec56f0343b7459292ff5c037c9a3ba0e39e22207f5efbf7e9f2ab6625679331fea95211bb74ce86669759a4d78f4ae57da0a4362220f01001e7db925582526307c4f98b08c0a2ff423abe9f67aee294bce2ebfc19c52220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c2a209d3a76fdf6ebc5ac40907e94ca44894469131ecd8fb54ebf185f32a8b9f196ba32207ffe241ea60187fdb0187bfa22de35d1f9bed7ab061d9401fd47e34a54fbede132207d00409ac38e3a99bc86c045f570dea66e115ba1d767d89c9e7f82901dfcfd883220cbc784d580d574d79cefc434bca4575f5456f88fd4a1c8cf63f1d23e0ad88c2c3220f1ccd8ad44f82cc7926bb9a57db9741ce9598a881ac834824b8cf7883814e6153220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c20b0dccec106").to_vec();
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
            slot: 128.into(),
            current_sync_committee: PublicKey::try_from(hex!("85adc9a2503bd8fe2295a0472b9bf5d49a0be1ccc3da908b990c2f2de52b47fc26307a8f72ec4580078be8179cc81aa9").to_vec()).unwrap(),
            next_sync_committee: PublicKey::default(),
            timestamp: Time::from_unix_timestamp(1748220080, 0).unwrap(),
        }
    }

    pub fn get_time() -> u64 {
        1748221319
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
            l1_header.timestamp,
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

        let err = apply_updates(
            &ctx,
            &cons_state,
            &l1_header.consensus_update,
            l1_header.timestamp,
        )
        .unwrap_err();
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
        cons_l1_timestamp: Time,
    }
    #[test]
    pub fn test_l1_header_verify_success_multi_period() {
        // created by optimism-ibc-relay-prover#prover_test.go#TestSetupHeadersForUpdateLong
        let raw_l1_config = hex!("0a20d61ea484febacfae5298d52a2b581f3e305a51f3112a9241b968dccf019f7b11100118e59fd0c106226f0a0410000038120e0a04200000381a0608691036183712140a04300000381a0c08691036183720192812301612140a04400000381a0c08691036183720192812301612140a04500000381a0c08691036183720192822302612150a04600000381a0d08a90110561857201928223026280630083808420408021003").to_vec();
        let raw_l1_config = RawL1Config::decode(&*raw_l1_config).unwrap();
        let l1_config = L1Config::try_from(raw_l1_config).unwrap();

        let cases = vec![TestCase {
            raw_l1_header: hex!("0af70c0af20c0a30996323af7e545fb6363ace53f1538c7ddc3eb0d985b2479da3ee4ace10cbc393b518bf02d1a2ddb2f5bdf09b473933ea0a308d46e9aa0c1986056e407efc7013b7f271027d3c98ce96667faa98074ab0588a61681faf78644c11819a459a95689dab0a308725b32751419f22a54485790f8187d1ba52d84a31ad45738a93777fcd1ccbec1652229923f82f37793ce0fc2763fb4c0a30b2225575d5e70da1257db7a0d1222c5041b52aac61cf161e8fc8126a3fdf5eb4f0867d98dfe272199c36cf8f02661b3d0a3091709ee06497b9ac049325853d64947290189a8c2322e3a500d91e23ea02dc158b6db63ae558b3b7670357a151cd60710a30ac69ae9e6c385a368df71d11ac68f45f05e005306df3c2bf98ed3577708256bd97f8c09d3f72115444077a9bb711d8d10a308aa5bbee21e98c7b9e7a4c8ea45aa99f89e22992fa4fc2d73869d77da4cc8a05b25b61931ff521986677dd7f7159e8e60a30b2225575d5e70da1257db7a0d1222c5041b52aac61cf161e8fc8126a3fdf5eb4f0867d98dfe272199c36cf8f02661b3d0a3096947de9e6068c22a7716656a2755a9551b0b66c2d1a741bf84a088fe1e840e992dc39861bf8ba3e8d5b6d21e8f57e640a30996d10c3026b9344532b06c70a596f972a1e779a1f6106d3da9f6ba376bbf7ec82d2f52629e5dbf3f7d03b00f6b862af0a30b570dde8ee80512e3d031caf22e775c60f7f5a6cbdeb3e52e24cf8c867d38569a53dd19cdc36a03a1bbb3a8d94b036700a308aa5bbee21e98c7b9e7a4c8ea45aa99f89e22992fa4fc2d73869d77da4cc8a05b25b61931ff521986677dd7f7159e8e60a3081b676591b823270a3284ace7d81cbce2d6cdce55bb0e053874d7e3a08f729453009d3e662ec3130379f43c0f3210b6d0a30a759f6bcca8f35fcaadc406cc4b828c016c0ed23882987a79f52f2933b5cedefe24e31df6fd0d38e8a802dbafd750d010a308fda66b8607af873f4c2c8218dd3ffc7940d411047eb199b5cd010156af4845d21dd2e65b0e44cfffb5e78271e9bb29d0a30ab72cbc6575c3179680a58c0ecd5de46d2678ccbafc016746348ee5688edcb21b4e15bd37c70c508e3ea73103c2d566b0a3081b676591b823270a3284ace7d81cbce2d6cdce55bb0e053874d7e3a08f729453009d3e662ec3130379f43c0f3210b6d0a3084d08d58c31bcd3cddf93e13d6f50203897384afa34644bff1135efe8e01c81c6a91ca6c234bb1e51ca32e41b828aaf90a308aec5129a518010912215e1887191da94be419b4e75904c2ea745e2d253d707c088fa5b2c46dade1d162affe9f7ab17b0a3084dc37ca3cd621d3da0fbdd11ca84021e0cd81a73d772dd6fcf19775b72eb64af4e573213378ccee0915dde92ac83ba60a30a1584dfe1573df8ec88c7b74d76726b4821bfe84bf886dd3c0e3f74c2ea18aa62ca44c871fb1c63971fccf6937e6501f0a30a0485d71f1f5e177f7d5bc9d98c5248a6a2d0de4554c2eaf02abae48f5a3e273b2ee7765784cf2a4cb7df84f617177c90a30b5e898a1fc06d51c695712928f44646d15451340d1b3e480a40f03250160bc07d3b6691ec94361dd524d59d9df7f76d30a3096947de9e6068c22a7716656a2755a9551b0b66c2d1a741bf84a088fe1e840e992dc39861bf8ba3e8d5b6d21e8f57e640a308dfa86c051edd28c3554a30e40531c898e5936ad3002711616ddd1b27054bc39caedd505a200c3d23a1c3f6b26c50ae90a3081ea9f74ef7d935b807474e38954ae3934856219a23e074954b2e860c5a3c400f9aedb42cd27cb4ceb697ca36d1e58cb0a30ae940a07850cf904b44f31cbf0e44824bae5ec36dcfdb7fad858f2a39dba38de82ca12b0ae939a34fce7a02e4b9789f80a30a804e4fa8d1391a9d078aa93985a12503b84ce4f6f1f9e70ab7fca421e1cf972538666299d4c1bfc39327b469b2db7a80a3084dc37ca3cd621d3da0fbdd11ca84021e0cd81a73d772dd6fcf19775b72eb64af4e573213378ccee0915dde92ac83ba60a3091709ee06497b9ac049325853d64947290189a8c2322e3a500d91e23ea02dc158b6db63ae558b3b7670357a151cd60710a30ab64f900c770e2b99de6b86b4390bbd1579bd48dccec55800adbcf52e006f22128e9971bbf3a92cc0105b0974849935a0a3084dc37ca3cd621d3da0fbdd11ca84021e0cd81a73d772dd6fcf19775b72eb64af4e573213378ccee0915dde92ac83ba61230909a7ba5c94addc5a2a8a3ec7e9f7a27bf2dfe698b859e136d2a55442a2dd4f5d29abdee6391e8afe1f7b588fb5b3c60100112a0140a6b089002100e1a20dec58a55279a052c0e2c2b66a6d150e44c26a1e3c6796bed7a01bb70cdcd28e622209d809dac96a225a9c916bb721fda91d2c50ea5b6efa6ef26f7f65d27bd8275652a20d08393de3e56ca3293e01b95955b0d29c842ea2bb5102a9b1fa2ac66ea58e0a012f20c0a308d8985e5dd341c9035b37bf7391c5944c28131b47c7d5359d18fca598010ba9a63e27c55e6b421a807038c320564db170a308dfa86c051edd28c3554a30e40531c898e5936ad3002711616ddd1b27054bc39caedd505a200c3d23a1c3f6b26c50ae90a308d028a021c5c31a1aa1e18eda74cfaf0fba1c454c17c2e0fc730dd07a19d0c77f7a905d54017292f3e800ca06b6977cd0a30ab40dc1cfe273ad0da700c64f8fc94f91db253ca3acf20e336d9bd09de67eec5c7d3506285d83c7bb6a08d64b77e5f2d0a30ac69ae9e6c385a368df71d11ac68f45f05e005306df3c2bf98ed3577708256bd97f8c09d3f72115444077a9bb711d8d10a308725b32751419f22a54485790f8187d1ba52d84a31ad45738a93777fcd1ccbec1652229923f82f37793ce0fc2763fb4c0a30b63f327df68581cdc02a66c1c65e906a06a1a3a8d7a6e38f7b6da944e8e6cc2db85fced5327d8c12945ceb33018272ca0a3096947de9e6068c22a7716656a2755a9551b0b66c2d1a741bf84a088fe1e840e992dc39861bf8ba3e8d5b6d21e8f57e640a30a759f6bcca8f35fcaadc406cc4b828c016c0ed23882987a79f52f2933b5cedefe24e31df6fd0d38e8a802dbafd750d010a308fda66b8607af873f4c2c8218dd3ffc7940d411047eb199b5cd010156af4845d21dd2e65b0e44cfffb5e78271e9bb29d0a30b570dde8ee80512e3d031caf22e775c60f7f5a6cbdeb3e52e24cf8c867d38569a53dd19cdc36a03a1bbb3a8d94b036700a30aaf6c1251e73fb600624937760fef218aace5b253bf068ed45398aeb29d821e4d2899343ddcbbe37cb3f6cf500dff26c0a308d46e9aa0c1986056e407efc7013b7f271027d3c98ce96667faa98074ab0588a61681faf78644c11819a459a95689dab0a30930743bfc7e18d3bd7351eaa74f477505268c1e4e1fd1ca3ccccdefb2595517343bbb8f5589c435c3c39323a4c0080f80a30ab72cbc6575c3179680a58c0ecd5de46d2678ccbafc016746348ee5688edcb21b4e15bd37c70c508e3ea73103c2d566b0a30ae940a07850cf904b44f31cbf0e44824bae5ec36dcfdb7fad858f2a39dba38de82ca12b0ae939a34fce7a02e4b9789f80a30af61f263addfb41c46d66e60ecfb598a5942f648f58718b6b4e4c92019fdb12328efbff98703134bcf28e9c1fab4bb600a30ab40dc1cfe273ad0da700c64f8fc94f91db253ca3acf20e336d9bd09de67eec5c7d3506285d83c7bb6a08d64b77e5f2d0a30996323af7e545fb6363ace53f1538c7ddc3eb0d985b2479da3ee4ace10cbc393b518bf02d1a2ddb2f5bdf09b473933ea0a30abd12678c73463ecea5867a80caf256d5c5e6ba53ff188b143a4d5be83365ad257edf39eaa1ba8753c4cdf4c632ff99e0a30af89ab00a0eab1131645292a9cfba583a69a1e3ac58b210e262494853e67385aeb50d4af428bdd577b9399daa96d8b200a30958c2692b86b4d20eaea3bb45e9447ebbc5b93ccaf8d21ef659d0cefedf5c4371b31b460ae40e8243682bde505abac1e0a30ad9222dec71ff8ee6bc0426ffe7b5e66f96738225db281dd20027a1556d089fdebd040abfbc2041d6c1a0d8fdcfce1830a30996d10c3026b9344532b06c70a596f972a1e779a1f6106d3da9f6ba376bbf7ec82d2f52629e5dbf3f7d03b00f6b862af0a30896a51e0b0de0f29029af38b796db1f1e6d0f9f9085ade40a313a60cb723fa3d58f6587175570086c4fbf0fe5331f1c80a30930743bfc7e18d3bd7351eaa74f477505268c1e4e1fd1ca3ccccdefb2595517343bbb8f5589c435c3c39323a4c0080f80a30af61f263addfb41c46d66e60ecfb598a5942f648f58718b6b4e4c92019fdb12328efbff98703134bcf28e9c1fab4bb600a30a2e2d8384fc87a512ee34eb43405fd82572c9d7cd96e155a382cda284e8df9eb7189c25b7473d89c63ea4e6080e10ff80a30996323af7e545fb6363ace53f1538c7ddc3eb0d985b2479da3ee4ace10cbc393b518bf02d1a2ddb2f5bdf09b473933ea0a30ae5302796cfeca685eaf37ffd5baeb32121f2f07415bee26cc0051ee513ff3932d2c365e3d9f87b0949a5980445cb64c0a30af61f263addfb41c46d66e60ecfb598a5942f648f58718b6b4e4c92019fdb12328efbff98703134bcf28e9c1fab4bb600a30ab40dc1cfe273ad0da700c64f8fc94f91db253ca3acf20e336d9bd09de67eec5c7d3506285d83c7bb6a08d64b77e5f2d1230986815fb51b2cadaa0686315bd467d0d074ec3e2dccd4529eb4e32a4313281e87721972ae136b47e9f892eb09fc806f71a20534fe19c39f2c48fb5a635694a822683794e5eaad2697ddd7d4e7e03244b0d3f1a2045a23a43f86c2b6aaf0253859014e4037a12c5feaf64654c229646e36856799b1a20881a29f0ef774a39db20577808de67929b688ba7453778efcbdd14294f93c08b1a20a8b2993fb1b0596fcdaf188ba3050a521b8de0560ec28dd0e9f381c2aa13b0ca1a204a729f03f24c304fb6ec5be0592dd32239db9455549c483a8dfcf737abf7eec21a20953024c6ded67e542650258c58347cef640ac2bb254c6df6bc3af9bf3c1a1f7a226b08800210041a2025bf428187774848a8b3e43a029b6dfa1c1157f48c6cddde305f79d7ff49d3b02220e575001ada0a9e95a2ed8a573117617bafaa1f4fd90f729106b32758ecdae4e22a20c9e883d5ff0f309f448bc9108a783f4ac0bcde1eb95463b224ffe1adecc2f2f42a2020000000000000000000000000000000000000000000000000000000000000002a205f6f02af29218292d21a69b64a794a7c0873b3e0f54611972863706e8cbdf3712a2029b409841b4f9c1b7060c625bd895fa17ed53c4d38163e578431c1422716b3e82a20881a29f0ef774a39db20577808de67929b688ba7453778efcbdd14294f93c08b2a20a8b2993fb1b0596fcdaf188ba3050a521b8de0560ec28dd0e9f381c2aa13b0ca2a204a729f03f24c304fb6ec5be0592dd32239db9455549c483a8dfcf737abf7eec22a20953024c6ded67e542650258c58347cef640ac2bb254c6df6bc3af9bf3c1a1f7a3220b4090d9cf4ac9f5b26c7ef1a6ee45f0a94d8c497ed319797157169cfb5e224413a2014546d6c8ed7b6140d00f6a1862a43d38b89e2fb0352daeeae2d65b5c29209123a202a37b83065f7815f9e4cccea40d17a695b2134c6b0ea067f08ef71e4a1ef5df63a206e817161402150ae7a3c42df6d68062e41bf358f5966510d5be0b8c40188772d3a20244688081e0bef7c5f74fd769e11f07fffb380449145b7e75685040b27e30f5642680a04ffffffff1260abce3ffc9111bd0c06b17d3e688bab47cd418677881c029893849a22233dec4409a89a610e73a41bce1bc4cd883e546105050542478a648465ef700055aab7cd71982bfc66175563c281979c09d4f4cae2e432c51446e228ddc6f5a77512537c4891021ac5040a20e831354055325ed30284ad44a6c8986797cf7fc66a0835c275aab748eb0052791220eaa8c40899a61ae59615cf9985f5e2194f8fd2b57d273be63bde6733e89b12ab12204512ec095cf2afad9c3d7debe2419d2471240f5ae98dab69687c161bdd41b3ba1220cd6e22507c35ee752d69de20e9742201a3d653312a8c3e77b257ba482bea20521220ee233bd69db88b205c3a28d4f8ab428bea01cc268ea452d9463cc7c1aaf1f8551220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c1880022220005125020000000000000000000000000000000000000000000000000000000022200ea01bca0957b3d6c4c9938d78593ffe296e39e5a85d005ad57f9f2a58e3e91022208d62d04141ed36fa7ca44ed7dcce19ceebeced7839b7d764551878eef28d692a2220ee233bd69db88b205c3a28d4f8ab428bea01cc268ea452d9463cc7c1aaf1f8552220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c2a2011562c72d16f06e7ca9864d6a5917b8e72232f53669062658c1fc8608467464b3220f645efbe8f65e6f388666f45396715c9ef0d9f0e707b34c92f28c8be30ecd3b23220a09a2b87124e2c710b9d90a696327a3a76e1bde89ca3efbc730de5c19fa0eaa93220355c3dd87fa350e11a4c2b65264057a8a73cd2fd0c795e5fd858073e9111519a322066bfb169e15ff6e2fc92ce4f11721dda3868e7cceacbc80da8a6108155b68c913220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c20e5abd0c106").to_vec(),
            cons_slot: 192,
            cons_l1_current_sync_committee: PublicKey::try_from(hex!("94347c15287607593d8e6ad4f5d2d19469126c8b4fe14c6b0d4e5d16790ef6165c6ba7903df6be270572b6136f6fbb02").to_vec()).unwrap(),
            cons_l1_next_sync_committee: PublicKey::try_from(hex!("909a7ba5c94addc5a2a8a3ec7e9f7a27bf2dfe698b859e136d2a55442a2dd4f5d29abdee6391e8afe1f7b588fb5b3c60").to_vec()).unwrap(),
            cons_l1_timestamp: Time::from_unix_timestamp(1748243821, 0).unwrap(),
        },TestCase {
            raw_l1_header: hex!("0af70c0af20c0a308d8985e5dd341c9035b37bf7391c5944c28131b47c7d5359d18fca598010ba9a63e27c55e6b421a807038c320564db170a308dfa86c051edd28c3554a30e40531c898e5936ad3002711616ddd1b27054bc39caedd505a200c3d23a1c3f6b26c50ae90a308d028a021c5c31a1aa1e18eda74cfaf0fba1c454c17c2e0fc730dd07a19d0c77f7a905d54017292f3e800ca06b6977cd0a30ab40dc1cfe273ad0da700c64f8fc94f91db253ca3acf20e336d9bd09de67eec5c7d3506285d83c7bb6a08d64b77e5f2d0a30ac69ae9e6c385a368df71d11ac68f45f05e005306df3c2bf98ed3577708256bd97f8c09d3f72115444077a9bb711d8d10a308725b32751419f22a54485790f8187d1ba52d84a31ad45738a93777fcd1ccbec1652229923f82f37793ce0fc2763fb4c0a30b63f327df68581cdc02a66c1c65e906a06a1a3a8d7a6e38f7b6da944e8e6cc2db85fced5327d8c12945ceb33018272ca0a3096947de9e6068c22a7716656a2755a9551b0b66c2d1a741bf84a088fe1e840e992dc39861bf8ba3e8d5b6d21e8f57e640a30a759f6bcca8f35fcaadc406cc4b828c016c0ed23882987a79f52f2933b5cedefe24e31df6fd0d38e8a802dbafd750d010a308fda66b8607af873f4c2c8218dd3ffc7940d411047eb199b5cd010156af4845d21dd2e65b0e44cfffb5e78271e9bb29d0a30b570dde8ee80512e3d031caf22e775c60f7f5a6cbdeb3e52e24cf8c867d38569a53dd19cdc36a03a1bbb3a8d94b036700a30aaf6c1251e73fb600624937760fef218aace5b253bf068ed45398aeb29d821e4d2899343ddcbbe37cb3f6cf500dff26c0a308d46e9aa0c1986056e407efc7013b7f271027d3c98ce96667faa98074ab0588a61681faf78644c11819a459a95689dab0a30930743bfc7e18d3bd7351eaa74f477505268c1e4e1fd1ca3ccccdefb2595517343bbb8f5589c435c3c39323a4c0080f80a30ab72cbc6575c3179680a58c0ecd5de46d2678ccbafc016746348ee5688edcb21b4e15bd37c70c508e3ea73103c2d566b0a30ae940a07850cf904b44f31cbf0e44824bae5ec36dcfdb7fad858f2a39dba38de82ca12b0ae939a34fce7a02e4b9789f80a30af61f263addfb41c46d66e60ecfb598a5942f648f58718b6b4e4c92019fdb12328efbff98703134bcf28e9c1fab4bb600a30ab40dc1cfe273ad0da700c64f8fc94f91db253ca3acf20e336d9bd09de67eec5c7d3506285d83c7bb6a08d64b77e5f2d0a30996323af7e545fb6363ace53f1538c7ddc3eb0d985b2479da3ee4ace10cbc393b518bf02d1a2ddb2f5bdf09b473933ea0a30abd12678c73463ecea5867a80caf256d5c5e6ba53ff188b143a4d5be83365ad257edf39eaa1ba8753c4cdf4c632ff99e0a30af89ab00a0eab1131645292a9cfba583a69a1e3ac58b210e262494853e67385aeb50d4af428bdd577b9399daa96d8b200a30958c2692b86b4d20eaea3bb45e9447ebbc5b93ccaf8d21ef659d0cefedf5c4371b31b460ae40e8243682bde505abac1e0a30ad9222dec71ff8ee6bc0426ffe7b5e66f96738225db281dd20027a1556d089fdebd040abfbc2041d6c1a0d8fdcfce1830a30996d10c3026b9344532b06c70a596f972a1e779a1f6106d3da9f6ba376bbf7ec82d2f52629e5dbf3f7d03b00f6b862af0a30896a51e0b0de0f29029af38b796db1f1e6d0f9f9085ade40a313a60cb723fa3d58f6587175570086c4fbf0fe5331f1c80a30930743bfc7e18d3bd7351eaa74f477505268c1e4e1fd1ca3ccccdefb2595517343bbb8f5589c435c3c39323a4c0080f80a30af61f263addfb41c46d66e60ecfb598a5942f648f58718b6b4e4c92019fdb12328efbff98703134bcf28e9c1fab4bb600a30a2e2d8384fc87a512ee34eb43405fd82572c9d7cd96e155a382cda284e8df9eb7189c25b7473d89c63ea4e6080e10ff80a30996323af7e545fb6363ace53f1538c7ddc3eb0d985b2479da3ee4ace10cbc393b518bf02d1a2ddb2f5bdf09b473933ea0a30ae5302796cfeca685eaf37ffd5baeb32121f2f07415bee26cc0051ee513ff3932d2c365e3d9f87b0949a5980445cb64c0a30af61f263addfb41c46d66e60ecfb598a5942f648f58718b6b4e4c92019fdb12328efbff98703134bcf28e9c1fab4bb600a30ab40dc1cfe273ad0da700c64f8fc94f91db253ca3acf20e336d9bd09de67eec5c7d3506285d83c7bb6a08d64b77e5f2d1230986815fb51b2cadaa0686315bd467d0d074ec3e2dccd4529eb4e32a4313281e87721972ae136b47e9f892eb09fc806f7100112a0140a6b08d002102a1a20642377d0a7fecc0be64c1f45f1c95a566f9af48889b58ad199be89c82424d2782220703a552dd1a2e7d0b706022d5732f2ae95c26da2ff8a2dd16a86d893afdd6b792a203a530f561fad0baa2d6bb7aae022df2a59bfac571cd15277f936986f416eeba412f20c0a30af61f263addfb41c46d66e60ecfb598a5942f648f58718b6b4e4c92019fdb12328efbff98703134bcf28e9c1fab4bb600a309918433b8f0bc5e126da3fdef8d7b71456492dae6d2d07f2e10c7a7f852046f84ed0ce6d3bfec42200670db27dcf30370a30ab40dc1cfe273ad0da700c64f8fc94f91db253ca3acf20e336d9bd09de67eec5c7d3506285d83c7bb6a08d64b77e5f2d0a30abd12678c73463ecea5867a80caf256d5c5e6ba53ff188b143a4d5be83365ad257edf39eaa1ba8753c4cdf4c632ff99e0a308d8985e5dd341c9035b37bf7391c5944c28131b47c7d5359d18fca598010ba9a63e27c55e6b421a807038c320564db170a30ae940a07850cf904b44f31cbf0e44824bae5ec36dcfdb7fad858f2a39dba38de82ca12b0ae939a34fce7a02e4b9789f80a3086e014747c7922ccfc2b9d4bf6c1ecf0dc800197037858d0b85ab1944b4c3c14b95e0ed325bc42a6f467bc47ec27bc7b0a30996d10c3026b9344532b06c70a596f972a1e779a1f6106d3da9f6ba376bbf7ec82d2f52629e5dbf3f7d03b00f6b862af0a3084dc37ca3cd621d3da0fbdd11ca84021e0cd81a73d772dd6fcf19775b72eb64af4e573213378ccee0915dde92ac83ba60a30af89ab00a0eab1131645292a9cfba583a69a1e3ac58b210e262494853e67385aeb50d4af428bdd577b9399daa96d8b200a30aaddb0cb69ca18f14aed7054e98a24df0ff606aeff919d489f7884fd1bd183bcb46ea54bc363146e1a88db36dc20a7a40a30896a51e0b0de0f29029af38b796db1f1e6d0f9f9085ade40a313a60cb723fa3d58f6587175570086c4fbf0fe5331f1c80a30b63f327df68581cdc02a66c1c65e906a06a1a3a8d7a6e38f7b6da944e8e6cc2db85fced5327d8c12945ceb33018272ca0a309918433b8f0bc5e126da3fdef8d7b71456492dae6d2d07f2e10c7a7f852046f84ed0ce6d3bfec42200670db27dcf30370a30a2e2d8384fc87a512ee34eb43405fd82572c9d7cd96e155a382cda284e8df9eb7189c25b7473d89c63ea4e6080e10ff80a3084dc37ca3cd621d3da0fbdd11ca84021e0cd81a73d772dd6fcf19775b72eb64af4e573213378ccee0915dde92ac83ba60a30b72cb106b7bc1ecae219e0ae1830a509ed18a042b56a2779f4033419de69ba8ae8017090caed1f5377bfa685061573600a30930743bfc7e18d3bd7351eaa74f477505268c1e4e1fd1ca3ccccdefb2595517343bbb8f5589c435c3c39323a4c0080f80a308aa5bbee21e98c7b9e7a4c8ea45aa99f89e22992fa4fc2d73869d77da4cc8a05b25b61931ff521986677dd7f7159e8e60a308aa5bbee21e98c7b9e7a4c8ea45aa99f89e22992fa4fc2d73869d77da4cc8a05b25b61931ff521986677dd7f7159e8e60a308aec5129a518010912215e1887191da94be419b4e75904c2ea745e2d253d707c088fa5b2c46dade1d162affe9f7ab17b0a30ab72cbc6575c3179680a58c0ecd5de46d2678ccbafc016746348ee5688edcb21b4e15bd37c70c508e3ea73103c2d566b0a30a35c6004f387430c3797ab0157af7b824c8fe106241c7cdeb897d900c0f9e4bb945ff2a6b88cbd10e35ec48aaa554ecb0a30b570dde8ee80512e3d031caf22e775c60f7f5a6cbdeb3e52e24cf8c867d38569a53dd19cdc36a03a1bbb3a8d94b036700a30a1d9840eda3036fbf63eeea40146e4548553e6e1b2a653ab349b376f31b367c40d71fb59ff8e94b91daa99c262ec8b520a308de5a6200cebb09b2198e69fed84bcd512ec5cf317c5f1ee99aad03d2a9a8564bf3807c08da2664222268d59c34a06e40a30afa10af166a0dbf3a25ff86cd6f8e44cccc818c5e70cd70e4e98e226b158f3563450b3fb184d2649adbb11e53080d1ca0a30ad9222dec71ff8ee6bc0426ffe7b5e66f96738225db281dd20027a1556d089fdebd040abfbc2041d6c1a0d8fdcfce1830a308725b32751419f22a54485790f8187d1ba52d84a31ad45738a93777fcd1ccbec1652229923f82f37793ce0fc2763fb4c0a308fda66b8607af873f4c2c8218dd3ffc7940d411047eb199b5cd010156af4845d21dd2e65b0e44cfffb5e78271e9bb29d0a30996d10c3026b9344532b06c70a596f972a1e779a1f6106d3da9f6ba376bbf7ec82d2f52629e5dbf3f7d03b00f6b862af0a30a62c0205fb22df8535c0b70076486e69dfa908feddae79e4a94a9d47b97ed190d228e1c6217e84a59882bb992dacae301230abde95cc2a437b24c91a0ed91f0a62173fafd69d6e551e88ddfe50ba016a0739611a5b32266e994213566b5e9df80df81a201646959c6b0b01c20514cd9d257474597c27f09f8917232901de1e4425ce1a141a207df86bed22bb4fde1ceab3ae915dd8a3fa684adca2968a3deb0dd90cc3a13f6c1a20eb3064db637e72129627ca13d3bd3cbebe146b60143e809454ec2ce9342618361a20989a5e4a49f775dcb88d30a1bde88f0fffcc88514c0dd03836b6eea74e6bc4b71a209516ffacc13711b0ba17d9f5b8ee523f8690cbb916fb66d05a34800681207ff71a20953024c6ded67e542650258c58347cef640ac2bb254c6df6bc3af9bf3c1a1f7a226b08c00210021a2017a1ebc9450c381f72e74fbe80aff486ef8a4bec9a4d72ce8772bdc3e1f6ec85222077eb38da11ba189f5dc22ebd298168b4588d74dc55549eef249b9e40098024c92a2007e6f192198f1930428393a85be7be304150d2a49ac7d1c70a447d955d00df972a2028000000000000000000000000000000000000000000000000000000000000002a205f6f02af29218292d21a69b64a794a7c0873b3e0f54611972863706e8cbdf3712a208d2b0fa0f81fa565438e5356bcb250393276206bd36814c1295dac5cff6e17d32a20eb3064db637e72129627ca13d3bd3cbebe146b60143e809454ec2ce9342618362a20989a5e4a49f775dcb88d30a1bde88f0fffcc88514c0dd03836b6eea74e6bc4b72a209516ffacc13711b0ba17d9f5b8ee523f8690cbb916fb66d05a34800681207ff72a20953024c6ded67e542650258c58347cef640ac2bb254c6df6bc3af9bf3c1a1f7a3220d6490050dda6cdb76742592aa7c16607f65e5f3d39169c9292caa76e6a6ef32e3a203acc6935be7e39dcd35ac35b510aa1be606a0cb8880e055c90b999c5e7325eec3a206a79ee2094e192197c683f12a96f723a6ab9d7614433583b831e1e776f8b75553a206e817161402150ae7a3c42df6d68062e41bf358f5966510d5be0b8c40188772d3a20e6ed57781e3c00c29b25383a43267b98ac355a6abdb06e324d3a2de6282786eb42680a04ffffffff1260b026dc4df5016aa79cfbfa7b30e631499adbcac20e076e9d392a03b0889cdb76a4555d0c8cb0581316a43434be612256038fb3a981e350611613d68321424a6a0d23cd319ee3b0d0f5c48998ce6e344a8192992c716b5e7851ecda2562e2dcb448d1021ac5040a205b729c4a121dee459098a913109ee01291d9650a15a85190153b24b83d593c011220eaa8c40899a61ae59615cf9985f5e2194f8fd2b57d273be63bde6733e89b12ab1220f9a5c1be324b4f8eca0d61c30caadd0489cbb1f70e4b9759c0bf75d70f571926122075fd4fdbd5bdda8474bfc8473fe1b3fd20c8b4cca50c0be013f7b0d36b11664d12203c681ef10d02b84bdcb4a41071a25172e2c2f9ac30809058e7a41d99c4fca77f1220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c18c002222000512502000000000000000000000000000000000000000000000000000000002220323a32e40d9c6577e6260a7d3cb2da85f02e1056e5c3a39dfd4b18e70bf67c2d2220ead3be07bc0ac609a7be39cb54eb5a9b9b5d21a9c68a32deb7e73c47d0fe498722203c681ef10d02b84bdcb4a41071a25172e2c2f9ac30809058e7a41d99c4fca77f2220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c2a206fe001a43677115c59a4f7feb4df38a61b4ec757a94d769ed5e38e441996c1b23220a2db0b19e6e23c27df802777694e4d02ee83bc844c6ae89d185eaa82217f4c323220a09a2b87124e2c710b9d90a696327a3a76e1bde89ca3efbc730de5c19fa0eaa93220a8794c226257423e1df8a388c4b63e93e9b3d496cc04b0102ee00ceec96bc3d33220ee81cb1ce2c84c1c6f3ad1c444b563c2287a2bedba0bf0635c9c313d175a69633220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c20e5aed0c106").to_vec(),
            cons_slot: 256,
            cons_l1_current_sync_committee: PublicKey::try_from(hex!("909a7ba5c94addc5a2a8a3ec7e9f7a27bf2dfe698b859e136d2a55442a2dd4f5d29abdee6391e8afe1f7b588fb5b3c60").to_vec()).unwrap(),
            cons_l1_next_sync_committee: PublicKey::try_from(hex!("986815fb51b2cadaa0686315bd467d0d074ec3e2dccd4529eb4e32a4313281e87721972ae136b47e9f892eb09fc806f7").to_vec()).unwrap(),
            cons_l1_timestamp: Time::from_unix_timestamp(1748243941, 0).unwrap(),
        }, TestCase {
            raw_l1_header: hex!("0af70c0af20c0a30af61f263addfb41c46d66e60ecfb598a5942f648f58718b6b4e4c92019fdb12328efbff98703134bcf28e9c1fab4bb600a309918433b8f0bc5e126da3fdef8d7b71456492dae6d2d07f2e10c7a7f852046f84ed0ce6d3bfec42200670db27dcf30370a30ab40dc1cfe273ad0da700c64f8fc94f91db253ca3acf20e336d9bd09de67eec5c7d3506285d83c7bb6a08d64b77e5f2d0a30abd12678c73463ecea5867a80caf256d5c5e6ba53ff188b143a4d5be83365ad257edf39eaa1ba8753c4cdf4c632ff99e0a308d8985e5dd341c9035b37bf7391c5944c28131b47c7d5359d18fca598010ba9a63e27c55e6b421a807038c320564db170a30ae940a07850cf904b44f31cbf0e44824bae5ec36dcfdb7fad858f2a39dba38de82ca12b0ae939a34fce7a02e4b9789f80a3086e014747c7922ccfc2b9d4bf6c1ecf0dc800197037858d0b85ab1944b4c3c14b95e0ed325bc42a6f467bc47ec27bc7b0a30996d10c3026b9344532b06c70a596f972a1e779a1f6106d3da9f6ba376bbf7ec82d2f52629e5dbf3f7d03b00f6b862af0a3084dc37ca3cd621d3da0fbdd11ca84021e0cd81a73d772dd6fcf19775b72eb64af4e573213378ccee0915dde92ac83ba60a30af89ab00a0eab1131645292a9cfba583a69a1e3ac58b210e262494853e67385aeb50d4af428bdd577b9399daa96d8b200a30aaddb0cb69ca18f14aed7054e98a24df0ff606aeff919d489f7884fd1bd183bcb46ea54bc363146e1a88db36dc20a7a40a30896a51e0b0de0f29029af38b796db1f1e6d0f9f9085ade40a313a60cb723fa3d58f6587175570086c4fbf0fe5331f1c80a30b63f327df68581cdc02a66c1c65e906a06a1a3a8d7a6e38f7b6da944e8e6cc2db85fced5327d8c12945ceb33018272ca0a309918433b8f0bc5e126da3fdef8d7b71456492dae6d2d07f2e10c7a7f852046f84ed0ce6d3bfec42200670db27dcf30370a30a2e2d8384fc87a512ee34eb43405fd82572c9d7cd96e155a382cda284e8df9eb7189c25b7473d89c63ea4e6080e10ff80a3084dc37ca3cd621d3da0fbdd11ca84021e0cd81a73d772dd6fcf19775b72eb64af4e573213378ccee0915dde92ac83ba60a30b72cb106b7bc1ecae219e0ae1830a509ed18a042b56a2779f4033419de69ba8ae8017090caed1f5377bfa685061573600a30930743bfc7e18d3bd7351eaa74f477505268c1e4e1fd1ca3ccccdefb2595517343bbb8f5589c435c3c39323a4c0080f80a308aa5bbee21e98c7b9e7a4c8ea45aa99f89e22992fa4fc2d73869d77da4cc8a05b25b61931ff521986677dd7f7159e8e60a308aa5bbee21e98c7b9e7a4c8ea45aa99f89e22992fa4fc2d73869d77da4cc8a05b25b61931ff521986677dd7f7159e8e60a308aec5129a518010912215e1887191da94be419b4e75904c2ea745e2d253d707c088fa5b2c46dade1d162affe9f7ab17b0a30ab72cbc6575c3179680a58c0ecd5de46d2678ccbafc016746348ee5688edcb21b4e15bd37c70c508e3ea73103c2d566b0a30a35c6004f387430c3797ab0157af7b824c8fe106241c7cdeb897d900c0f9e4bb945ff2a6b88cbd10e35ec48aaa554ecb0a30b570dde8ee80512e3d031caf22e775c60f7f5a6cbdeb3e52e24cf8c867d38569a53dd19cdc36a03a1bbb3a8d94b036700a30a1d9840eda3036fbf63eeea40146e4548553e6e1b2a653ab349b376f31b367c40d71fb59ff8e94b91daa99c262ec8b520a308de5a6200cebb09b2198e69fed84bcd512ec5cf317c5f1ee99aad03d2a9a8564bf3807c08da2664222268d59c34a06e40a30afa10af166a0dbf3a25ff86cd6f8e44cccc818c5e70cd70e4e98e226b158f3563450b3fb184d2649adbb11e53080d1ca0a30ad9222dec71ff8ee6bc0426ffe7b5e66f96738225db281dd20027a1556d089fdebd040abfbc2041d6c1a0d8fdcfce1830a308725b32751419f22a54485790f8187d1ba52d84a31ad45738a93777fcd1ccbec1652229923f82f37793ce0fc2763fb4c0a308fda66b8607af873f4c2c8218dd3ffc7940d411047eb199b5cd010156af4845d21dd2e65b0e44cfffb5e78271e9bb29d0a30996d10c3026b9344532b06c70a596f972a1e779a1f6106d3da9f6ba376bbf7ec82d2f52629e5dbf3f7d03b00f6b862af0a30a62c0205fb22df8535c0b70076486e69dfa908feddae79e4a94a9d47b97ed190d228e1c6217e84a59882bb992dacae301230abde95cc2a437b24c91a0ed91f0a62173fafd69d6e551e88ddfe50ba016a0739611a5b32266e994213566b5e9df80df8100112a0140a6b089003103a1a2027e3b65156b2c0f9aff0a6345cf30da2469788452198813065d19f8ff4b51ae22220c68f795349face97893830be79d2069c29641f205ade8108feb5f25d64b2df4b2a20092e0598939f390b76d07b233177504a3cbe640c9a0b1a61f594368c97a99eef12f20c0a30930743bfc7e18d3bd7351eaa74f477505268c1e4e1fd1ca3ccccdefb2595517343bbb8f5589c435c3c39323a4c0080f80a30ae940a07850cf904b44f31cbf0e44824bae5ec36dcfdb7fad858f2a39dba38de82ca12b0ae939a34fce7a02e4b9789f80a30996d10c3026b9344532b06c70a596f972a1e779a1f6106d3da9f6ba376bbf7ec82d2f52629e5dbf3f7d03b00f6b862af0a30a54fe5c26059ed60b4f0b66ef7b0bf167580504525f83c169507dc812816df41b1da6128341c23977300dffd32a32f410a30b63f327df68581cdc02a66c1c65e906a06a1a3a8d7a6e38f7b6da944e8e6cc2db85fced5327d8c12945ceb33018272ca0a30a759f6bcca8f35fcaadc406cc4b828c016c0ed23882987a79f52f2933b5cedefe24e31df6fd0d38e8a802dbafd750d010a3081ea9f74ef7d935b807474e38954ae3934856219a23e074954b2e860c5a3c400f9aedb42cd27cb4ceb697ca36d1e58cb0a30b72cb106b7bc1ecae219e0ae1830a509ed18a042b56a2779f4033419de69ba8ae8017090caed1f5377bfa685061573600a30996d10c3026b9344532b06c70a596f972a1e779a1f6106d3da9f6ba376bbf7ec82d2f52629e5dbf3f7d03b00f6b862af0a30a1d9840eda3036fbf63eeea40146e4548553e6e1b2a653ab349b376f31b367c40d71fb59ff8e94b91daa99c262ec8b520a30a0485d71f1f5e177f7d5bc9d98c5248a6a2d0de4554c2eaf02abae48f5a3e273b2ee7765784cf2a4cb7df84f617177c90a3096947de9e6068c22a7716656a2755a9551b0b66c2d1a741bf84a088fe1e840e992dc39861bf8ba3e8d5b6d21e8f57e640a30b63f327df68581cdc02a66c1c65e906a06a1a3a8d7a6e38f7b6da944e8e6cc2db85fced5327d8c12945ceb33018272ca0a30aaddb0cb69ca18f14aed7054e98a24df0ff606aeff919d489f7884fd1bd183bcb46ea54bc363146e1a88db36dc20a7a40a30ae5302796cfeca685eaf37ffd5baeb32121f2f07415bee26cc0051ee513ff3932d2c365e3d9f87b0949a5980445cb64c0a30a2e2d8384fc87a512ee34eb43405fd82572c9d7cd96e155a382cda284e8df9eb7189c25b7473d89c63ea4e6080e10ff80a309763dde1b8028136a3ffd6dafd1f450e2cafb2819c7fa901f7c6e9cde8f2897ee7e9a45da6947fde1ad0d3836188eab50a30a03c2a82374e04b2e0594c4ce14fb3f225b46f13188f0d8002a523c7dcfb939ae4856053c2c9c695374d7c3685df1ca50a30ad9222dec71ff8ee6bc0426ffe7b5e66f96738225db281dd20027a1556d089fdebd040abfbc2041d6c1a0d8fdcfce1830a30a4ee6d37dc259cbb5237e4265429a9fd8ab5643af81628cc101e0d8b4a333ef2618a37df89ea3f92b5ea4333d8cda3930a309763dde1b8028136a3ffd6dafd1f450e2cafb2819c7fa901f7c6e9cde8f2897ee7e9a45da6947fde1ad0d3836188eab50a30a804e4fa8d1391a9d078aa93985a12503b84ce4f6f1f9e70ab7fca421e1cf972538666299d4c1bfc39327b469b2db7a80a3081b676591b823270a3284ace7d81cbce2d6cdce55bb0e053874d7e3a08f729453009d3e662ec3130379f43c0f3210b6d0a308c0d15baa72bfcd317e9b9402ca9bb6e7ae1db35ffce7faccae0bd19b3c8e5de7d5524aef0377770b3a90626627a93040a30abd12678c73463ecea5867a80caf256d5c5e6ba53ff188b143a4d5be83365ad257edf39eaa1ba8753c4cdf4c632ff99e0a30ab64f900c770e2b99de6b86b4390bbd1579bd48dccec55800adbcf52e006f22128e9971bbf3a92cc0105b0974849935a0a309763dde1b8028136a3ffd6dafd1f450e2cafb2819c7fa901f7c6e9cde8f2897ee7e9a45da6947fde1ad0d3836188eab50a30a4ee6d37dc259cbb5237e4265429a9fd8ab5643af81628cc101e0d8b4a333ef2618a37df89ea3f92b5ea4333d8cda3930a30aaddb0cb69ca18f14aed7054e98a24df0ff606aeff919d489f7884fd1bd183bcb46ea54bc363146e1a88db36dc20a7a40a30b63f327df68581cdc02a66c1c65e906a06a1a3a8d7a6e38f7b6da944e8e6cc2db85fced5327d8c12945ceb33018272ca0a308d46e9aa0c1986056e407efc7013b7f271027d3c98ce96667faa98074ab0588a61681faf78644c11819a459a95689dab0a308c0d15baa72bfcd317e9b9402ca9bb6e7ae1db35ffce7faccae0bd19b3c8e5de7d5524aef0377770b3a90626627a9304123088391b708918624976075fcd3e3b610557da97b18968e066eaa02d6ba4fd02c38a6b99896b9e58b72d36c69cb32796081a202d0ff46d57d290181ae8bb992f61420532f44fa2d62141de5c0ca13c5fc8ffc51a20a6c2965e6cab291735d34a7c2737104ee09715dd866f59ffbba086739e3c374e1a206d56b1dbefcf0bd7801d03eb87c49fb203df270fbfa2032ba6042aa278c80c101a20b3e0492ec44a659317d8c751bda70eb1cc0e85c5f3fcb84b30ccc4b6c95afe261a20a075fac025d75b8b170b0d96aa462da0b248f25fd25896edde920e7b785c07f01a20953024c6ded67e542650258c58347cef640ac2bb254c6df6bc3af9bf3c1a1f7a226b08800310091a20b7193222aeeaa3af612d09c268bc3b6cc74a9b93619c0c41d1cba5490ff7c90122201ef3e5ad38c6d40a1fa8c2eeb23aa3e459340f6a9656006bffdccc46599081de2a208ebde83fef3bae246e5fe634237e5770f60a139c335edfb9a7f1d13a328aede42a2030000000000000000000000000000000000000000000000000000000000000002a205f6f02af29218292d21a69b64a794a7c0873b3e0f54611972863706e8cbdf3712a2068ff503af5c0cf6707dfb2c120f2ddfa42190b3b3a58f535f1abaabc0a28b7da2a206d56b1dbefcf0bd7801d03eb87c49fb203df270fbfa2032ba6042aa278c80c102a20b3e0492ec44a659317d8c751bda70eb1cc0e85c5f3fcb84b30ccc4b6c95afe262a20a075fac025d75b8b170b0d96aa462da0b248f25fd25896edde920e7b785c07f02a20953024c6ded67e542650258c58347cef640ac2bb254c6df6bc3af9bf3c1a1f7a3220251f933f7d9b82a12a04c920495f64856c523a972255d7a687693b5af413e3473a20c47f6b6fc334b47d4307bf940df7d671d85289bacd84069c3b05dacc469a760e3a203e9469a0c2885a4e8e6621b323f05c211f6aa6f13fb5cbabf94eb64d0ae8d5173a206e817161402150ae7a3c42df6d68062e41bf358f5966510d5be0b8c40188772d3a20a47bbc5f9902437662873af615c35adc47b17b7faf4873ec267da9461423dffc42680a04ffffffff1260b3aa0a550fae96dcf2637160a9991206f7214cbf44c71e3168a8247e652cfbb80793fba4b7bc7b6bcc493c6e21238bc10856516397be2fe4d7224095750c9a32894f44d2322c21e960a1b9daad971e15c8954f2c09b0a0ed4e7225510653eac84891031ac5040a20a5124b258be5e9c952d06db9ae9f7abf8bb7eee08c89eee4a218e2bcbb6e317a122056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421122052a3019818ce967316008fe9d8f02513bff78b961cd42ca749e1dd656a78f6d51220efc0490ae0eb21dc0d39cf5c167ed235636e522fe3e5d413e31a85e2c60748251220d3d6c0d521711815014d2032466035eb2359fe5067a717e7b7978700b18baf9d1220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c188003222000512502000000000000000000000000000000000000000000000000000000002220729573cc500dc7b0c0747785db664cb876ba94122af0ecc427e5fbde3d429a4122209516703b40c7ededd7e27923fbdac813a42a0ab44b6a0bda8ab89c6836fa1a322220d3d6c0d521711815014d2032466035eb2359fe5067a717e7b7978700b18baf9d2220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c2a201da83f8fc95f7e04051af0809ebcae7a07fa18150c4459b6c251313e749ea4ca32207ffe241ea60187fdb0187bfa22de35d1f9bed7ab061d9401fd47e34a54fbede132207d00409ac38e3a99bc86c045f570dea66e115ba1d767d89c9e7f82901dfcfd883220de59448f5ea86115a913d2a3c1f5f9d5c1d1c9acf0eee7412f36dcfefe6742b232202b493819ebdd7b071e65439bb3d1c7062f3fec8a9a1061824a4bfc808806203b3220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c20e5b1d0c106").to_vec(),
            cons_slot: 320,
            cons_l1_current_sync_committee: PublicKey::try_from(hex!("986815fb51b2cadaa0686315bd467d0d074ec3e2dccd4529eb4e32a4313281e87721972ae136b47e9f892eb09fc806f7").to_vec()).unwrap(),
            cons_l1_next_sync_committee: PublicKey::try_from(hex!("abde95cc2a437b24c91a0ed91f0a62173fafd69d6e551e88ddfe50ba016a0739611a5b32266e994213566b5e9df80df8").to_vec()).unwrap(),
            cons_l1_timestamp: Time::from_unix_timestamp(1748244325, 0).unwrap(),
        }, TestCase {
            raw_l1_header: hex!("0af50c0af20c0a30af61f263addfb41c46d66e60ecfb598a5942f648f58718b6b4e4c92019fdb12328efbff98703134bcf28e9c1fab4bb600a309918433b8f0bc5e126da3fdef8d7b71456492dae6d2d07f2e10c7a7f852046f84ed0ce6d3bfec42200670db27dcf30370a30ab40dc1cfe273ad0da700c64f8fc94f91db253ca3acf20e336d9bd09de67eec5c7d3506285d83c7bb6a08d64b77e5f2d0a30abd12678c73463ecea5867a80caf256d5c5e6ba53ff188b143a4d5be83365ad257edf39eaa1ba8753c4cdf4c632ff99e0a308d8985e5dd341c9035b37bf7391c5944c28131b47c7d5359d18fca598010ba9a63e27c55e6b421a807038c320564db170a30ae940a07850cf904b44f31cbf0e44824bae5ec36dcfdb7fad858f2a39dba38de82ca12b0ae939a34fce7a02e4b9789f80a3086e014747c7922ccfc2b9d4bf6c1ecf0dc800197037858d0b85ab1944b4c3c14b95e0ed325bc42a6f467bc47ec27bc7b0a30996d10c3026b9344532b06c70a596f972a1e779a1f6106d3da9f6ba376bbf7ec82d2f52629e5dbf3f7d03b00f6b862af0a3084dc37ca3cd621d3da0fbdd11ca84021e0cd81a73d772dd6fcf19775b72eb64af4e573213378ccee0915dde92ac83ba60a30af89ab00a0eab1131645292a9cfba583a69a1e3ac58b210e262494853e67385aeb50d4af428bdd577b9399daa96d8b200a30aaddb0cb69ca18f14aed7054e98a24df0ff606aeff919d489f7884fd1bd183bcb46ea54bc363146e1a88db36dc20a7a40a30896a51e0b0de0f29029af38b796db1f1e6d0f9f9085ade40a313a60cb723fa3d58f6587175570086c4fbf0fe5331f1c80a30b63f327df68581cdc02a66c1c65e906a06a1a3a8d7a6e38f7b6da944e8e6cc2db85fced5327d8c12945ceb33018272ca0a309918433b8f0bc5e126da3fdef8d7b71456492dae6d2d07f2e10c7a7f852046f84ed0ce6d3bfec42200670db27dcf30370a30a2e2d8384fc87a512ee34eb43405fd82572c9d7cd96e155a382cda284e8df9eb7189c25b7473d89c63ea4e6080e10ff80a3084dc37ca3cd621d3da0fbdd11ca84021e0cd81a73d772dd6fcf19775b72eb64af4e573213378ccee0915dde92ac83ba60a30b72cb106b7bc1ecae219e0ae1830a509ed18a042b56a2779f4033419de69ba8ae8017090caed1f5377bfa685061573600a30930743bfc7e18d3bd7351eaa74f477505268c1e4e1fd1ca3ccccdefb2595517343bbb8f5589c435c3c39323a4c0080f80a308aa5bbee21e98c7b9e7a4c8ea45aa99f89e22992fa4fc2d73869d77da4cc8a05b25b61931ff521986677dd7f7159e8e60a308aa5bbee21e98c7b9e7a4c8ea45aa99f89e22992fa4fc2d73869d77da4cc8a05b25b61931ff521986677dd7f7159e8e60a308aec5129a518010912215e1887191da94be419b4e75904c2ea745e2d253d707c088fa5b2c46dade1d162affe9f7ab17b0a30ab72cbc6575c3179680a58c0ecd5de46d2678ccbafc016746348ee5688edcb21b4e15bd37c70c508e3ea73103c2d566b0a30a35c6004f387430c3797ab0157af7b824c8fe106241c7cdeb897d900c0f9e4bb945ff2a6b88cbd10e35ec48aaa554ecb0a30b570dde8ee80512e3d031caf22e775c60f7f5a6cbdeb3e52e24cf8c867d38569a53dd19cdc36a03a1bbb3a8d94b036700a30a1d9840eda3036fbf63eeea40146e4548553e6e1b2a653ab349b376f31b367c40d71fb59ff8e94b91daa99c262ec8b520a308de5a6200cebb09b2198e69fed84bcd512ec5cf317c5f1ee99aad03d2a9a8564bf3807c08da2664222268d59c34a06e40a30afa10af166a0dbf3a25ff86cd6f8e44cccc818c5e70cd70e4e98e226b158f3563450b3fb184d2649adbb11e53080d1ca0a30ad9222dec71ff8ee6bc0426ffe7b5e66f96738225db281dd20027a1556d089fdebd040abfbc2041d6c1a0d8fdcfce1830a308725b32751419f22a54485790f8187d1ba52d84a31ad45738a93777fcd1ccbec1652229923f82f37793ce0fc2763fb4c0a308fda66b8607af873f4c2c8218dd3ffc7940d411047eb199b5cd010156af4845d21dd2e65b0e44cfffb5e78271e9bb29d0a30996d10c3026b9344532b06c70a596f972a1e779a1f6106d3da9f6ba376bbf7ec82d2f52629e5dbf3f7d03b00f6b862af0a30a62c0205fb22df8535c0b70076486e69dfa908feddae79e4a94a9d47b97ed190d228e1c6217e84a59882bb992dacae301230abde95cc2a437b24c91a0ed91f0a62173fafd69d6e551e88ddfe50ba016a0739611a5b32266e994213566b5e9df80df812a0140a6b089003103a1a2027e3b65156b2c0f9aff0a6345cf30da2469788452198813065d19f8ff4b51ae22220c68f795349face97893830be79d2069c29641f205ade8108feb5f25d64b2df4b2a20092e0598939f390b76d07b233177504a3cbe640c9a0b1a61f594368c97a99eef12f20c0a30930743bfc7e18d3bd7351eaa74f477505268c1e4e1fd1ca3ccccdefb2595517343bbb8f5589c435c3c39323a4c0080f80a30ae940a07850cf904b44f31cbf0e44824bae5ec36dcfdb7fad858f2a39dba38de82ca12b0ae939a34fce7a02e4b9789f80a30996d10c3026b9344532b06c70a596f972a1e779a1f6106d3da9f6ba376bbf7ec82d2f52629e5dbf3f7d03b00f6b862af0a30a54fe5c26059ed60b4f0b66ef7b0bf167580504525f83c169507dc812816df41b1da6128341c23977300dffd32a32f410a30b63f327df68581cdc02a66c1c65e906a06a1a3a8d7a6e38f7b6da944e8e6cc2db85fced5327d8c12945ceb33018272ca0a30a759f6bcca8f35fcaadc406cc4b828c016c0ed23882987a79f52f2933b5cedefe24e31df6fd0d38e8a802dbafd750d010a3081ea9f74ef7d935b807474e38954ae3934856219a23e074954b2e860c5a3c400f9aedb42cd27cb4ceb697ca36d1e58cb0a30b72cb106b7bc1ecae219e0ae1830a509ed18a042b56a2779f4033419de69ba8ae8017090caed1f5377bfa685061573600a30996d10c3026b9344532b06c70a596f972a1e779a1f6106d3da9f6ba376bbf7ec82d2f52629e5dbf3f7d03b00f6b862af0a30a1d9840eda3036fbf63eeea40146e4548553e6e1b2a653ab349b376f31b367c40d71fb59ff8e94b91daa99c262ec8b520a30a0485d71f1f5e177f7d5bc9d98c5248a6a2d0de4554c2eaf02abae48f5a3e273b2ee7765784cf2a4cb7df84f617177c90a3096947de9e6068c22a7716656a2755a9551b0b66c2d1a741bf84a088fe1e840e992dc39861bf8ba3e8d5b6d21e8f57e640a30b63f327df68581cdc02a66c1c65e906a06a1a3a8d7a6e38f7b6da944e8e6cc2db85fced5327d8c12945ceb33018272ca0a30aaddb0cb69ca18f14aed7054e98a24df0ff606aeff919d489f7884fd1bd183bcb46ea54bc363146e1a88db36dc20a7a40a30ae5302796cfeca685eaf37ffd5baeb32121f2f07415bee26cc0051ee513ff3932d2c365e3d9f87b0949a5980445cb64c0a30a2e2d8384fc87a512ee34eb43405fd82572c9d7cd96e155a382cda284e8df9eb7189c25b7473d89c63ea4e6080e10ff80a309763dde1b8028136a3ffd6dafd1f450e2cafb2819c7fa901f7c6e9cde8f2897ee7e9a45da6947fde1ad0d3836188eab50a30a03c2a82374e04b2e0594c4ce14fb3f225b46f13188f0d8002a523c7dcfb939ae4856053c2c9c695374d7c3685df1ca50a30ad9222dec71ff8ee6bc0426ffe7b5e66f96738225db281dd20027a1556d089fdebd040abfbc2041d6c1a0d8fdcfce1830a30a4ee6d37dc259cbb5237e4265429a9fd8ab5643af81628cc101e0d8b4a333ef2618a37df89ea3f92b5ea4333d8cda3930a309763dde1b8028136a3ffd6dafd1f450e2cafb2819c7fa901f7c6e9cde8f2897ee7e9a45da6947fde1ad0d3836188eab50a30a804e4fa8d1391a9d078aa93985a12503b84ce4f6f1f9e70ab7fca421e1cf972538666299d4c1bfc39327b469b2db7a80a3081b676591b823270a3284ace7d81cbce2d6cdce55bb0e053874d7e3a08f729453009d3e662ec3130379f43c0f3210b6d0a308c0d15baa72bfcd317e9b9402ca9bb6e7ae1db35ffce7faccae0bd19b3c8e5de7d5524aef0377770b3a90626627a93040a30abd12678c73463ecea5867a80caf256d5c5e6ba53ff188b143a4d5be83365ad257edf39eaa1ba8753c4cdf4c632ff99e0a30ab64f900c770e2b99de6b86b4390bbd1579bd48dccec55800adbcf52e006f22128e9971bbf3a92cc0105b0974849935a0a309763dde1b8028136a3ffd6dafd1f450e2cafb2819c7fa901f7c6e9cde8f2897ee7e9a45da6947fde1ad0d3836188eab50a30a4ee6d37dc259cbb5237e4265429a9fd8ab5643af81628cc101e0d8b4a333ef2618a37df89ea3f92b5ea4333d8cda3930a30aaddb0cb69ca18f14aed7054e98a24df0ff606aeff919d489f7884fd1bd183bcb46ea54bc363146e1a88db36dc20a7a40a30b63f327df68581cdc02a66c1c65e906a06a1a3a8d7a6e38f7b6da944e8e6cc2db85fced5327d8c12945ceb33018272ca0a308d46e9aa0c1986056e407efc7013b7f271027d3c98ce96667faa98074ab0588a61681faf78644c11819a459a95689dab0a308c0d15baa72bfcd317e9b9402ca9bb6e7ae1db35ffce7faccae0bd19b3c8e5de7d5524aef0377770b3a90626627a9304123088391b708918624976075fcd3e3b610557da97b18968e066eaa02d6ba4fd02c38a6b99896b9e58b72d36c69cb32796081a202d0ff46d57d290181ae8bb992f61420532f44fa2d62141de5c0ca13c5fc8ffc51a20a6c2965e6cab291735d34a7c2737104ee09715dd866f59ffbba086739e3c374e1a206d56b1dbefcf0bd7801d03eb87c49fb203df270fbfa2032ba6042aa278c80c101a20b3e0492ec44a659317d8c751bda70eb1cc0e85c5f3fcb84b30ccc4b6c95afe261a20a075fac025d75b8b170b0d96aa462da0b248f25fd25896edde920e7b785c07f01a20953024c6ded67e542650258c58347cef640ac2bb254c6df6bc3af9bf3c1a1f7a226b08800310091a20b7193222aeeaa3af612d09c268bc3b6cc74a9b93619c0c41d1cba5490ff7c90122201ef3e5ad38c6d40a1fa8c2eeb23aa3e459340f6a9656006bffdccc46599081de2a208ebde83fef3bae246e5fe634237e5770f60a139c335edfb9a7f1d13a328aede42a2030000000000000000000000000000000000000000000000000000000000000002a205f6f02af29218292d21a69b64a794a7c0873b3e0f54611972863706e8cbdf3712a2068ff503af5c0cf6707dfb2c120f2ddfa42190b3b3a58f535f1abaabc0a28b7da2a206d56b1dbefcf0bd7801d03eb87c49fb203df270fbfa2032ba6042aa278c80c102a20b3e0492ec44a659317d8c751bda70eb1cc0e85c5f3fcb84b30ccc4b6c95afe262a20a075fac025d75b8b170b0d96aa462da0b248f25fd25896edde920e7b785c07f02a20953024c6ded67e542650258c58347cef640ac2bb254c6df6bc3af9bf3c1a1f7a3220251f933f7d9b82a12a04c920495f64856c523a972255d7a687693b5af413e3473a20c47f6b6fc334b47d4307bf940df7d671d85289bacd84069c3b05dacc469a760e3a203e9469a0c2885a4e8e6621b323f05c211f6aa6f13fb5cbabf94eb64d0ae8d5173a206e817161402150ae7a3c42df6d68062e41bf358f5966510d5be0b8c40188772d3a20a47bbc5f9902437662873af615c35adc47b17b7faf4873ec267da9461423dffc42680a04ffffffff1260b3aa0a550fae96dcf2637160a9991206f7214cbf44c71e3168a8247e652cfbb80793fba4b7bc7b6bcc493c6e21238bc10856516397be2fe4d7224095750c9a32894f44d2322c21e960a1b9daad971e15c8954f2c09b0a0ed4e7225510653eac84891031ac5040a20a5124b258be5e9c952d06db9ae9f7abf8bb7eee08c89eee4a218e2bcbb6e317a122056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421122052a3019818ce967316008fe9d8f02513bff78b961cd42ca749e1dd656a78f6d51220efc0490ae0eb21dc0d39cf5c167ed235636e522fe3e5d413e31a85e2c60748251220d3d6c0d521711815014d2032466035eb2359fe5067a717e7b7978700b18baf9d1220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c188003222000512502000000000000000000000000000000000000000000000000000000002220729573cc500dc7b0c0747785db664cb876ba94122af0ecc427e5fbde3d429a4122209516703b40c7ededd7e27923fbdac813a42a0ab44b6a0bda8ab89c6836fa1a322220d3d6c0d521711815014d2032466035eb2359fe5067a717e7b7978700b18baf9d2220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c2a201da83f8fc95f7e04051af0809ebcae7a07fa18150c4459b6c251313e749ea4ca32207ffe241ea60187fdb0187bfa22de35d1f9bed7ab061d9401fd47e34a54fbede132207d00409ac38e3a99bc86c045f570dea66e115ba1d767d89c9e7f82901dfcfd883220de59448f5ea86115a913d2a3c1f5f9d5c1d1c9acf0eee7412f36dcfefe6742b232202b493819ebdd7b071e65439bb3d1c7062f3fec8a9a1061824a4bfc808806203b3220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c20e5b1d0c106").to_vec(),
            cons_slot: 384,
            cons_l1_current_sync_committee: PublicKey::try_from(hex!("abde95cc2a437b24c91a0ed91f0a62173fafd69d6e551e88ddfe50ba016a0739611a5b32266e994213566b5e9df80df8").to_vec()).unwrap(),
            cons_l1_next_sync_committee: PublicKey::try_from(hex!("88391b708918624976075fcd3e3b610557da97b18968e066eaa02d6ba4fd02c38a6b99896b9e58b72d36c69cb3279608").to_vec()).unwrap(),
            cons_l1_timestamp: Time::from_unix_timestamp(1748244709, 0).unwrap(),
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
                timestamp: case.cons_l1_timestamp,
            };
            let (_, l1_consensus) = l1_header
                .verify(1748245356, &l1_config, &cons_state)
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
