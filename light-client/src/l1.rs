use crate::errors::Error;
use crate::misc::new_timestamp;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::str::FromStr;
use core::time::Duration;
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
use ethereum_light_client_verifier::misbehaviour::{
    FinalizedHeaderMisbehaviour, Misbehaviour as MisbehaviourData, NextSyncCommitteeMisbehaviour,
};
use ethereum_light_client_verifier::state::LightClientStoreReader;
use ethereum_light_client_verifier::updates::{ConsensusUpdate, ExecutionUpdate};
use light_client::types::{ClientId, Height, Time};
use optimism_ibc_proto::google::protobuf::Any as IBCAny;
use optimism_ibc_proto::ibc::lightclients::ethereum::v1::{
    BeaconBlockHeader as ProtoBeaconBlockHeader, ConsensusUpdate as ProtoConsensusUpdate,
    ExecutionUpdate as ProtoExecutionUpdate, SyncAggregate as ProtoSyncAggregate,
    SyncCommittee as ProtoSyncCommittee,
};
use optimism_ibc_proto::ibc::lightclients::ethereum::v1::{
    FinalizedHeaderMisbehaviour as RawFinalizedHeaderMisbehaviour,
    NextSyncCommitteeMisbehaviour as RawNextSyncCommitteeMisbehaviour,
};
use optimism_ibc_proto::ibc::lightclients::optimism::v1::L1Header as RawL1Header;
use prost::Message;

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

    ///Light Client parameters
    pub trusting_period: Duration,
    pub max_clock_drift: Duration,
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
    pub(crate) slot: Slot,
    pub(crate) next_sync_committee: Option<SyncCommittee<SYNC_COMMITTEE_SIZE>>,
    pub(crate) current_sync_committee: Option<SyncCommittee<SYNC_COMMITTEE_SIZE>>,
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

    pub fn verify_misbehaviour<CC: ChainConsensusVerificationContext>(
        &self,
        ctx: &CC,
        l1_sync_committee: &L1SyncCommittee<SYNC_COMMITTEE_SIZE>,
        data: MisbehaviourData<SYNC_COMMITTEE_SIZE, ConsensusUpdateInfo<SYNC_COMMITTEE_SIZE>>,
    ) -> Result<(), Error> {
        self.consensus_verifier
            .validate_misbehaviour(ctx, l1_sync_committee, data)
            .map_err(Error::L1VerifyMisbehaviourError)
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

fn convert_proto_to_sync_aggregate<const SYNC_COMMITTEE_SIZE: usize>(
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
        sync_aggregate: convert_proto_to_sync_aggregate(
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

const ETHEREUM_FINALIZED_HEADER_MISBEHAVIOUR_TYPE_URL: &str =
    "/ibc.lightclients.ethereum.v1.FinalizedHeaderMisbehaviour";
const ETHEREUM_NEXT_SYNC_COMMITTEE_MISBEHAVIOUR_TYPE_URL: &str =
    "/ibc.lightclients.ethereum.v1.NextSyncCommitteeMisbehaviour";

#[derive(Clone, Debug)]
pub struct Misbehaviour<const SYNC_COMMITTEE_SIZE: usize> {
    pub client_id: ClientId,
    pub trusted_height: Height,
    /// The sync committee related to the misbehaviour
    pub trusted_sync_committee: TrustedSyncCommittee<SYNC_COMMITTEE_SIZE>,
    /// The misbehaviour data
    pub data: MisbehaviourData<SYNC_COMMITTEE_SIZE, ConsensusUpdateInfo<SYNC_COMMITTEE_SIZE>>,
}

impl<const SYNC_COMMITTEE_SIZE: usize> TryFrom<RawFinalizedHeaderMisbehaviour>
    for Misbehaviour<SYNC_COMMITTEE_SIZE>
{
    type Error = Error;
    fn try_from(value: RawFinalizedHeaderMisbehaviour) -> Result<Self, Self::Error> {
        let trusted_sync_committee = value
            .trusted_sync_committee
            .ok_or(Error::MissingTrustedSyncCommittee)?;
        Ok(Self {
            client_id: ClientId::from_str(&value.client_id).map_err(Error::UnexpectedClientId)?,
            trusted_height: value
                .trusted_height
                .ok_or(Error::MissingTrustedHeight)?
                .into(),
            trusted_sync_committee: TrustedSyncCommittee {
                sync_committee: convert_proto_to_sync_committee(
                    trusted_sync_committee.sync_committee,
                )?,
                is_next: trusted_sync_committee.is_next,
            },
            data: MisbehaviourData::FinalizedHeader(FinalizedHeaderMisbehaviour {
                consensus_update_1: convert_proto_to_consensus_update(
                    value
                        .consensus_update_1
                        .ok_or(Error::proto_missing("consensus_update_1"))?,
                )?,
                consensus_update_2: convert_proto_to_consensus_update(
                    value
                        .consensus_update_2
                        .ok_or(Error::proto_missing("consensus_update_2"))?,
                )?,
            }),
        })
    }
}

impl<const SYNC_COMMITTEE_SIZE: usize> TryFrom<RawNextSyncCommitteeMisbehaviour>
    for Misbehaviour<SYNC_COMMITTEE_SIZE>
{
    type Error = Error;
    fn try_from(value: RawNextSyncCommitteeMisbehaviour) -> Result<Self, Self::Error> {
        let trusted_sync_committee = value
            .trusted_sync_committee
            .ok_or(Error::MissingTrustedSyncCommittee)?;
        Ok(Self {
            client_id: ClientId::from_str(&value.client_id).map_err(Error::UnexpectedClientId)?,
            trusted_height: value
                .trusted_height
                .ok_or(Error::MissingTrustedHeight)?
                .into(),
            trusted_sync_committee: TrustedSyncCommittee {
                sync_committee: convert_proto_to_sync_committee(
                    trusted_sync_committee.sync_committee,
                )?,
                is_next: trusted_sync_committee.is_next,
            },
            data: MisbehaviourData::NextSyncCommittee(NextSyncCommitteeMisbehaviour {
                consensus_update_1: convert_proto_to_consensus_update(
                    value
                        .consensus_update_1
                        .ok_or(Error::proto_missing("consensus_update_1"))?,
                )?,
                consensus_update_2: convert_proto_to_consensus_update(
                    value
                        .consensus_update_2
                        .ok_or(Error::proto_missing("consensus_update_2"))?,
                )?,
            }),
        })
    }
}

impl<const SYNC_COMMITTEE_SIZE: usize> TryFrom<IBCAny> for Misbehaviour<SYNC_COMMITTEE_SIZE> {
    type Error = Error;

    fn try_from(raw: IBCAny) -> Result<Self, Self::Error> {
        use core::ops::Deref;

        match raw.type_url.as_str() {
            ETHEREUM_FINALIZED_HEADER_MISBEHAVIOUR_TYPE_URL => {
                RawFinalizedHeaderMisbehaviour::decode(raw.value.deref())
                    .map_err(Error::ProtoDecodeError)?
                    .try_into()
            }
            ETHEREUM_NEXT_SYNC_COMMITTEE_MISBEHAVIOUR_TYPE_URL => {
                RawNextSyncCommitteeMisbehaviour::decode(raw.value.deref())
                    .map_err(Error::ProtoDecodeError)?
                    .try_into()
            }
            _ => Err(Error::UnknownMisbehaviourType(raw.type_url)),
        }
    }
}

impl<const SYNC_COMMITTEE_SIZE: usize> Misbehaviour<SYNC_COMMITTEE_SIZE> {
    fn validate(&self) -> Result<(), Error> {
        self.trusted_sync_committee.validate()?;
        Ok(())
    }

    pub fn verify(
        &self,
        now: u64,
        l1_config: &L1Config,
        consensus_state: &L1Consensus,
    ) -> Result<(), Error> {
        let ctx = l1_config.build_context(now);

        self.validate()?;

        let l1_sync_committee = L1SyncCommittee::new(
            consensus_state,
            self.trusted_sync_committee.sync_committee.clone(),
            self.trusted_sync_committee.is_next,
        )?;

        let verifier = L1Verifier::default();
        verifier.verify_misbehaviour(&ctx, &l1_sync_committee, self.data.clone())
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
        let raw_l1_config = hex!("0a20d61ea484febacfae5298d52a2b581f3e305a51f3112a9241b968dccf019f7b11100118e59fd0c106226f0a0410000038120e0a04200000381a0608691036183712140a04300000381a0c08691036183720192812301612140a04400000381a0c08691036183720192812301612140a04500000381a0c08691036183720192822302612150a04600000381a0d08a901105618572019282230262806300838084204080210034a040880a305520410c0843d").to_vec();
        let raw_l1_config = RawL1Config::decode(&*raw_l1_config).unwrap();
        L1Config::try_from(raw_l1_config).unwrap()
    }

    pub fn get_raw_l1_header() -> RawL1Header {
        // created by optimism-ibc-relay-prover#prover_test.go#TestSetupHeadersForUpdateShort
        let raw_l1_header = hex!("0af50c0af20c0a30a35c6004f387430c3797ab0157af7b824c8fe106241c7cdeb897d900c0f9e4bb945ff2a6b88cbd10e35ec48aaa554ecb0a30896a51e0b0de0f29029af38b796db1f1e6d0f9f9085ade40a313a60cb723fa3d58f6587175570086c4fbf0fe5331f1c80a30b24391aa97bfff29adc935d06a2b6d583433caf82f92de1980e0192d3b270323bdbf24b86dc61520a40c419dde3df4b30a30abd12678c73463ecea5867a80caf256d5c5e6ba53ff188b143a4d5be83365ad257edf39eaa1ba8753c4cdf4c632ff99e0a30b570dde8ee80512e3d031caf22e775c60f7f5a6cbdeb3e52e24cf8c867d38569a53dd19cdc36a03a1bbb3a8d94b036700a30958c2692b86b4d20eaea3bb45e9447ebbc5b93ccaf8d21ef659d0cefedf5c4371b31b460ae40e8243682bde505abac1e0a30a1584dfe1573df8ec88c7b74d76726b4821bfe84bf886dd3c0e3f74c2ea18aa62ca44c871fb1c63971fccf6937e6501f0a309918433b8f0bc5e126da3fdef8d7b71456492dae6d2d07f2e10c7a7f852046f84ed0ce6d3bfec42200670db27dcf30370a30b570dde8ee80512e3d031caf22e775c60f7f5a6cbdeb3e52e24cf8c867d38569a53dd19cdc36a03a1bbb3a8d94b036700a309918433b8f0bc5e126da3fdef8d7b71456492dae6d2d07f2e10c7a7f852046f84ed0ce6d3bfec42200670db27dcf30370a30aaddb0cb69ca18f14aed7054e98a24df0ff606aeff919d489f7884fd1bd183bcb46ea54bc363146e1a88db36dc20a7a40a30a54fe5c26059ed60b4f0b66ef7b0bf167580504525f83c169507dc812816df41b1da6128341c23977300dffd32a32f410a30ae5302796cfeca685eaf37ffd5baeb32121f2f07415bee26cc0051ee513ff3932d2c365e3d9f87b0949a5980445cb64c0a30ab40dc1cfe273ad0da700c64f8fc94f91db253ca3acf20e336d9bd09de67eec5c7d3506285d83c7bb6a08d64b77e5f2d0a30a4ee6d37dc259cbb5237e4265429a9fd8ab5643af81628cc101e0d8b4a333ef2618a37df89ea3f92b5ea4333d8cda3930a30a62c0205fb22df8535c0b70076486e69dfa908feddae79e4a94a9d47b97ed190d228e1c6217e84a59882bb992dacae300a308aec5129a518010912215e1887191da94be419b4e75904c2ea745e2d253d707c088fa5b2c46dade1d162affe9f7ab17b0a3084dc37ca3cd621d3da0fbdd11ca84021e0cd81a73d772dd6fcf19775b72eb64af4e573213378ccee0915dde92ac83ba60a30958c2692b86b4d20eaea3bb45e9447ebbc5b93ccaf8d21ef659d0cefedf5c4371b31b460ae40e8243682bde505abac1e0a30afa10af166a0dbf3a25ff86cd6f8e44cccc818c5e70cd70e4e98e226b158f3563450b3fb184d2649adbb11e53080d1ca0a30ab64f900c770e2b99de6b86b4390bbd1579bd48dccec55800adbcf52e006f22128e9971bbf3a92cc0105b0974849935a0a30af61f263addfb41c46d66e60ecfb598a5942f648f58718b6b4e4c92019fdb12328efbff98703134bcf28e9c1fab4bb600a30a4ee6d37dc259cbb5237e4265429a9fd8ab5643af81628cc101e0d8b4a333ef2618a37df89ea3f92b5ea4333d8cda3930a30a0485d71f1f5e177f7d5bc9d98c5248a6a2d0de4554c2eaf02abae48f5a3e273b2ee7765784cf2a4cb7df84f617177c90a30a4ee6d37dc259cbb5237e4265429a9fd8ab5643af81628cc101e0d8b4a333ef2618a37df89ea3f92b5ea4333d8cda3930a3096947de9e6068c22a7716656a2755a9551b0b66c2d1a741bf84a088fe1e840e992dc39861bf8ba3e8d5b6d21e8f57e640a30996323af7e545fb6363ace53f1538c7ddc3eb0d985b2479da3ee4ace10cbc393b518bf02d1a2ddb2f5bdf09b473933ea0a309918433b8f0bc5e126da3fdef8d7b71456492dae6d2d07f2e10c7a7f852046f84ed0ce6d3bfec42200670db27dcf30370a3099d83a0ba33161d8c6bbe80929fd9046d4dfdac43477ff85fea5bae925e6c179ad28eb338375ee2417acbd6576ee670a0a30a4ee6d37dc259cbb5237e4265429a9fd8ab5643af81628cc101e0d8b4a333ef2618a37df89ea3f92b5ea4333d8cda3930a30a03c2a82374e04b2e0594c4ce14fb3f225b46f13188f0d8002a523c7dcfb939ae4856053c2c9c695374d7c3685df1ca50a3084a687ffdf21a0ad754d0164d1e2c03035613ab76359e7f5cf51ea4a425a6ee026725ec0a0dbd336f7dab759596f0bf812308582bbad3f9eee79addd939370c7241ee96d425c6a5d6e7fb89e59ad117c38e62064e56821b77b26353be13b86d6a66c12a0140a6b089025102d1a2098cafb088ed485add1e7ebbf781f87cfd0ee1843c530fc58ea0441d7611e42bc2220731cece7df5359d49cbc5803491385d389a6ce079e8549d1755d66acca0ba49a2a203a8f399041af0bcc34fd104ad3ca95ff35bb4045694d9eba30d1ed66dbc139db12f20c0a30a03c2a82374e04b2e0594c4ce14fb3f225b46f13188f0d8002a523c7dcfb939ae4856053c2c9c695374d7c3685df1ca50a30a1584dfe1573df8ec88c7b74d76726b4821bfe84bf886dd3c0e3f74c2ea18aa62ca44c871fb1c63971fccf6937e6501f0a308fda66b8607af873f4c2c8218dd3ffc7940d411047eb199b5cd010156af4845d21dd2e65b0e44cfffb5e78271e9bb29d0a30b72cb106b7bc1ecae219e0ae1830a509ed18a042b56a2779f4033419de69ba8ae8017090caed1f5377bfa685061573600a30a4ee6d37dc259cbb5237e4265429a9fd8ab5643af81628cc101e0d8b4a333ef2618a37df89ea3f92b5ea4333d8cda3930a308aa5bbee21e98c7b9e7a4c8ea45aa99f89e22992fa4fc2d73869d77da4cc8a05b25b61931ff521986677dd7f7159e8e60a30a1584dfe1573df8ec88c7b74d76726b4821bfe84bf886dd3c0e3f74c2ea18aa62ca44c871fb1c63971fccf6937e6501f0a3084dc37ca3cd621d3da0fbdd11ca84021e0cd81a73d772dd6fcf19775b72eb64af4e573213378ccee0915dde92ac83ba60a30a4ee6d37dc259cbb5237e4265429a9fd8ab5643af81628cc101e0d8b4a333ef2618a37df89ea3f92b5ea4333d8cda3930a308d8985e5dd341c9035b37bf7391c5944c28131b47c7d5359d18fca598010ba9a63e27c55e6b421a807038c320564db170a30a35c6004f387430c3797ab0157af7b824c8fe106241c7cdeb897d900c0f9e4bb945ff2a6b88cbd10e35ec48aaa554ecb0a30ac69ae9e6c385a368df71d11ac68f45f05e005306df3c2bf98ed3577708256bd97f8c09d3f72115444077a9bb711d8d10a308aec5129a518010912215e1887191da94be419b4e75904c2ea745e2d253d707c088fa5b2c46dade1d162affe9f7ab17b0a30930743bfc7e18d3bd7351eaa74f477505268c1e4e1fd1ca3ccccdefb2595517343bbb8f5589c435c3c39323a4c0080f80a30a35c6004f387430c3797ab0157af7b824c8fe106241c7cdeb897d900c0f9e4bb945ff2a6b88cbd10e35ec48aaa554ecb0a30a0485d71f1f5e177f7d5bc9d98c5248a6a2d0de4554c2eaf02abae48f5a3e273b2ee7765784cf2a4cb7df84f617177c90a30a8fa3584a92b079c8c73ed1553e5e161a0b21325fc2fc4e24a892354a899c7fc0bfb436a97a7ed1fc71bccda438ea7150a30ab64f900c770e2b99de6b86b4390bbd1579bd48dccec55800adbcf52e006f22128e9971bbf3a92cc0105b0974849935a0a30a8fa3584a92b079c8c73ed1553e5e161a0b21325fc2fc4e24a892354a899c7fc0bfb436a97a7ed1fc71bccda438ea7150a308d8985e5dd341c9035b37bf7391c5944c28131b47c7d5359d18fca598010ba9a63e27c55e6b421a807038c320564db170a30aaf6c1251e73fb600624937760fef218aace5b253bf068ed45398aeb29d821e4d2899343ddcbbe37cb3f6cf500dff26c0a30a8fa3584a92b079c8c73ed1553e5e161a0b21325fc2fc4e24a892354a899c7fc0bfb436a97a7ed1fc71bccda438ea7150a30ae5302796cfeca685eaf37ffd5baeb32121f2f07415bee26cc0051ee513ff3932d2c365e3d9f87b0949a5980445cb64c0a309763dde1b8028136a3ffd6dafd1f450e2cafb2819c7fa901f7c6e9cde8f2897ee7e9a45da6947fde1ad0d3836188eab50a30958c2692b86b4d20eaea3bb45e9447ebbc5b93ccaf8d21ef659d0cefedf5c4371b31b460ae40e8243682bde505abac1e0a30a804e4fa8d1391a9d078aa93985a12503b84ce4f6f1f9e70ab7fca421e1cf972538666299d4c1bfc39327b469b2db7a80a30930743bfc7e18d3bd7351eaa74f477505268c1e4e1fd1ca3ccccdefb2595517343bbb8f5589c435c3c39323a4c0080f80a30a8fa3584a92b079c8c73ed1553e5e161a0b21325fc2fc4e24a892354a899c7fc0bfb436a97a7ed1fc71bccda438ea7150a30b72cb106b7bc1ecae219e0ae1830a509ed18a042b56a2779f4033419de69ba8ae8017090caed1f5377bfa685061573600a30af89ab00a0eab1131645292a9cfba583a69a1e3ac58b210e262494853e67385aeb50d4af428bdd577b9399daa96d8b200a308d8985e5dd341c9035b37bf7391c5944c28131b47c7d5359d18fca598010ba9a63e27c55e6b421a807038c320564db170a308fda66b8607af873f4c2c8218dd3ffc7940d411047eb199b5cd010156af4845d21dd2e65b0e44cfffb5e78271e9bb29d12309325339b023fc50bc744ef7fdd824b7b5bc9315244bb0b39914dec4b902c906f064b9c913de3c16a4a505ca75f5bff2f1a206513aeb2fadbe569185826caaaa8a6e2d22b5b7ae97ce5fc795de6f7206c66a31a20243d8d8f3307b4dd1be276403dd776a691e9ccd8cfa088b76d8e5cf5959bb5071a20149c1dd2231306fafe93aae46fc748b26d2dc3822e2e896f32f9073c3984a8f91a201a9bd5ad63f4a2da9efcd077e67323dd41debd2f638650163251008af69d2d501a203eadd0b161343dc74bc3b8a8a3ca19af58505837886485ed68f9a77cb63406921a20953024c6ded67e542650258c58347cef640ac2bb254c6df6bc3af9bf3c1a1f7a226b08802510261a204051ec04f0298604a1b74cce78b26018dff72b0b91af1446ee2443a7248287372220497784693cc27dd2e704bd7d155997d49c029dd07a319c0886035cd5ce739c372a20beb4c83a76673ae70915c72a5a0737b21c070984e0d0094b30270c6d55dc34522a2050020000000000000000000000000000000000000000000000000000000000002a205f6f02af29218292d21a69b64a794a7c0873b3e0f54611972863706e8cbdf3712a20c363e8e3531e960f39ecd40de1a29985e7f1473281f67553f1d42643ab61d7672a20149c1dd2231306fafe93aae46fc748b26d2dc3822e2e896f32f9073c3984a8f92a201a9bd5ad63f4a2da9efcd077e67323dd41debd2f638650163251008af69d2d502a203eadd0b161343dc74bc3b8a8a3ca19af58505837886485ed68f9a77cb63406922a20953024c6ded67e542650258c58347cef640ac2bb254c6df6bc3af9bf3c1a1f7a32205cbed721eb34b16bb233472fcc69a60f9fa7b6ef995bef9183148012f8aa926b3a20303b72425f7fd40f18fa8199b6913bba1858356fe543432245a250e816eb22a93a203e9469a0c2885a4e8e6621b323f05c211f6aa6f13fb5cbabf94eb64d0ae8d5173a206e817161402150ae7a3c42df6d68062e41bf358f5966510d5be0b8c40188772d3a2031b38f95fa9f617a11a605bc2dcbe2b3c118fedefb271e5ba400a26cb5505c2342680a04ffffffff1260813f27f288ee634bfc215d1a8d82906e6cba0ebe0770e9ed45b6e48fd81f351a0d1e5c9be9c14b159da2fa93ad2afcf2157f1aeafabf8ecc138c31c260621deef8dc79ed74f86a3911558e33386fb52cc3bf3ba5286bbebee8c204fae8f0e2154891251ac5040a20f6627686f931982aebc4702c2490e8ef45fdf3c0bca63da533fb6da8d8cb5ab5122056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4211220b0d658ec171d83afba0347ea65e6af5bae452e53321328c39a6731fdb60cc4c812208e4b54f1db5d51d26ab71a045f150b08f4267ae9f2618b96b4c62eb65f3f8392122086768f0b1d5fc4b178f5494360a551fb930951fdda21db8ac2d42227ba0bc4591220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c1880252220005125020000000000000000000000000000000000000000000000000000000022205c47e85c55d09f8a3951d83579bf0647644629f9575140e580d733fbf9b1fcc2222035702c52f06f5df0af898572adb1ff40b9f51b7d41ac72071e39ea3d7c363a4d222086768f0b1d5fc4b178f5494360a551fb930951fdda21db8ac2d42227ba0bc4592220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c2a20898d0903232a0984edcbf6d3860c93800a137715084fc9388be9bc004d88493432207ffe241ea60187fdb0187bfa22de35d1f9bed7ab061d9401fd47e34a54fbede132207d00409ac38e3a99bc86c045f570dea66e115ba1d767d89c9e7f82901dfcfd883220a315945caef8ad30a149b2947b65d1caa2b2176fbadf4de16b04563118bf5b6e32200b54955aba5ecb0d9d4484bfb65f8f9d183577578aedc0fe06193980c72242223220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c20e5fdd1c106").to_vec();
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
            slot: 4736.into(),
            current_sync_committee: PublicKey::try_from(hex!("8582bbad3f9eee79addd939370c7241ee96d425c6a5d6e7fb89e59ad117c38e62064e56821b77b26353be13b86d6a66c").to_vec()).unwrap(),
            next_sync_committee: PublicKey::default(),
            timestamp: Time::from_unix_timestamp(1748270821, 0).unwrap(),
        }
    }

    pub fn get_time() -> u64 {
        1748317931
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

        l1_header.consensus_update.signature_slot =
            (l1_header.consensus_update.signature_slot.0 + 10000).into();

        let err = l1_header
            .verify(get_time(), &l1_config, &cons_state)
            .unwrap_err();
        match err {
            Error::L1VerifyConsensusUpdateError(e) => {
                assert!(
                    format!("{e:?}").contains("InconsistentSlotOrder"),
                    "Err {e:?}"
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
                    format!("{e:?}").contains("InvalidExecutionStateRootMerkleBranch"),
                    "Err {e:?}"
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
        let raw_l1_config = hex!("0a20d61ea484febacfae5298d52a2b581f3e305a51f3112a9241b968dccf019f7b11100118e59fd0c106226f0a0410000038120e0a04200000381a0608691036183712140a04300000381a0c08691036183720192812301612140a04400000381a0c08691036183720192812301612140a04500000381a0c08691036183720192822302612150a04600000381a0d08a901105618572019282230262806300838084204080210034a040880a305520410c0843d").to_vec();
        let raw_l1_config = RawL1Config::decode(&*raw_l1_config).unwrap();
        let l1_config = L1Config::try_from(raw_l1_config).unwrap();

        let cases = vec![TestCase {
            raw_l1_header: hex!("0af50c0af20c0a308dfa86c051edd28c3554a30e40531c898e5936ad3002711616ddd1b27054bc39caedd505a200c3d23a1c3f6b26c50ae90a308aa5bbee21e98c7b9e7a4c8ea45aa99f89e22992fa4fc2d73869d77da4cc8a05b25b61931ff521986677dd7f7159e8e60a309918433b8f0bc5e126da3fdef8d7b71456492dae6d2d07f2e10c7a7f852046f84ed0ce6d3bfec42200670db27dcf30370a30a1d9840eda3036fbf63eeea40146e4548553e6e1b2a653ab349b376f31b367c40d71fb59ff8e94b91daa99c262ec8b520a30b2225575d5e70da1257db7a0d1222c5041b52aac61cf161e8fc8126a3fdf5eb4f0867d98dfe272199c36cf8f02661b3d0a30958c2692b86b4d20eaea3bb45e9447ebbc5b93ccaf8d21ef659d0cefedf5c4371b31b460ae40e8243682bde505abac1e0a30a0485d71f1f5e177f7d5bc9d98c5248a6a2d0de4554c2eaf02abae48f5a3e273b2ee7765784cf2a4cb7df84f617177c90a30aaddb0cb69ca18f14aed7054e98a24df0ff606aeff919d489f7884fd1bd183bcb46ea54bc363146e1a88db36dc20a7a40a30a1d9840eda3036fbf63eeea40146e4548553e6e1b2a653ab349b376f31b367c40d71fb59ff8e94b91daa99c262ec8b520a30a03c2a82374e04b2e0594c4ce14fb3f225b46f13188f0d8002a523c7dcfb939ae4856053c2c9c695374d7c3685df1ca50a308725b32751419f22a54485790f8187d1ba52d84a31ad45738a93777fcd1ccbec1652229923f82f37793ce0fc2763fb4c0a30ab72cbc6575c3179680a58c0ecd5de46d2678ccbafc016746348ee5688edcb21b4e15bd37c70c508e3ea73103c2d566b0a30a62c0205fb22df8535c0b70076486e69dfa908feddae79e4a94a9d47b97ed190d228e1c6217e84a59882bb992dacae300a30896a51e0b0de0f29029af38b796db1f1e6d0f9f9085ade40a313a60cb723fa3d58f6587175570086c4fbf0fe5331f1c80a30a759f6bcca8f35fcaadc406cc4b828c016c0ed23882987a79f52f2933b5cedefe24e31df6fd0d38e8a802dbafd750d010a30a75ca9447dca3a3745ada36731187ddd1f6a152cf15d7446b785eab381e5c8562c1202a6e7a24080bc6b619a161113db0a3081ea9f74ef7d935b807474e38954ae3934856219a23e074954b2e860c5a3c400f9aedb42cd27cb4ceb697ca36d1e58cb0a30a759f6bcca8f35fcaadc406cc4b828c016c0ed23882987a79f52f2933b5cedefe24e31df6fd0d38e8a802dbafd750d010a30a4ee6d37dc259cbb5237e4265429a9fd8ab5643af81628cc101e0d8b4a333ef2618a37df89ea3f92b5ea4333d8cda3930a3081ea9f74ef7d935b807474e38954ae3934856219a23e074954b2e860c5a3c400f9aedb42cd27cb4ceb697ca36d1e58cb0a3087231421a08ed28e7d357e2b37a26a458155c8d822d829344bd1029e5d175b5edfaa78f16f784f724a2caef124944c4f0a30a759f6bcca8f35fcaadc406cc4b828c016c0ed23882987a79f52f2933b5cedefe24e31df6fd0d38e8a802dbafd750d010a308a8bb292bcc481070d3afdbbc8789e2ab4b29c9603936e6d85f5ff71e23fc5b6d61009f0fa636b5d5b2dc309d39e3d750a308aa5bbee21e98c7b9e7a4c8ea45aa99f89e22992fa4fc2d73869d77da4cc8a05b25b61931ff521986677dd7f7159e8e60a3084a687ffdf21a0ad754d0164d1e2c03035613ab76359e7f5cf51ea4a425a6ee026725ec0a0dbd336f7dab759596f0bf80a30ab64f900c770e2b99de6b86b4390bbd1579bd48dccec55800adbcf52e006f22128e9971bbf3a92cc0105b0974849935a0a30ab40dc1cfe273ad0da700c64f8fc94f91db253ca3acf20e336d9bd09de67eec5c7d3506285d83c7bb6a08d64b77e5f2d0a30a0485d71f1f5e177f7d5bc9d98c5248a6a2d0de4554c2eaf02abae48f5a3e273b2ee7765784cf2a4cb7df84f617177c90a308de5a6200cebb09b2198e69fed84bcd512ec5cf317c5f1ee99aad03d2a9a8564bf3807c08da2664222268d59c34a06e40a30b5e898a1fc06d51c695712928f44646d15451340d1b3e480a40f03250160bc07d3b6691ec94361dd524d59d9df7f76d30a308aec5129a518010912215e1887191da94be419b4e75904c2ea745e2d253d707c088fa5b2c46dade1d162affe9f7ab17b0a308725b32751419f22a54485790f8187d1ba52d84a31ad45738a93777fcd1ccbec1652229923f82f37793ce0fc2763fb4c123092dc97a87ee2ab99deca4440a66d489b5d85984d807cd29147267873cb2d8925de6755c03c52fa941f90a65bb15d735112a0140a6b08d02310261a203d474f72b49f5715933271070983daade9555a6b96aa7a22cb6cd40bf8bd75df222052ddb2674f731dbfa193598e9317823ec6d112e34f72c55ce836ef3dd124fe4c2a2076786cf308194a81a8ae5bb9a850efd509fc20c78bc4410e91654058bae257a012f20c0a30b5e898a1fc06d51c695712928f44646d15451340d1b3e480a40f03250160bc07d3b6691ec94361dd524d59d9df7f76d30a308aec5129a518010912215e1887191da94be419b4e75904c2ea745e2d253d707c088fa5b2c46dade1d162affe9f7ab17b0a3084d08d58c31bcd3cddf93e13d6f50203897384afa34644bff1135efe8e01c81c6a91ca6c234bb1e51ca32e41b828aaf90a30b72cb106b7bc1ecae219e0ae1830a509ed18a042b56a2779f4033419de69ba8ae8017090caed1f5377bfa685061573600a30aaf6c1251e73fb600624937760fef218aace5b253bf068ed45398aeb29d821e4d2899343ddcbbe37cb3f6cf500dff26c0a30a35c6004f387430c3797ab0157af7b824c8fe106241c7cdeb897d900c0f9e4bb945ff2a6b88cbd10e35ec48aaa554ecb0a30a75ca9447dca3a3745ada36731187ddd1f6a152cf15d7446b785eab381e5c8562c1202a6e7a24080bc6b619a161113db0a308dfa86c051edd28c3554a30e40531c898e5936ad3002711616ddd1b27054bc39caedd505a200c3d23a1c3f6b26c50ae90a308de5a6200cebb09b2198e69fed84bcd512ec5cf317c5f1ee99aad03d2a9a8564bf3807c08da2664222268d59c34a06e40a30b09cb155daf2022afd18114a352e506a84065c80573cb0c7c310cbe92e2706cdcf91f74bbd9e464f74e3d831386d50330a309763dde1b8028136a3ffd6dafd1f450e2cafb2819c7fa901f7c6e9cde8f2897ee7e9a45da6947fde1ad0d3836188eab50a30b27ad13afc8ff30e087797b344c8382bb0a84447549f1b0274059ddd652276e7b148ba8808a10cc45746762957d4efbe0a30ac69ae9e6c385a368df71d11ac68f45f05e005306df3c2bf98ed3577708256bd97f8c09d3f72115444077a9bb711d8d10a3081fa222737fe818b43f55f209f42adaee135b2801d02709617fc88c2871852358260ace97cf323e761b5cc18bc7325b30a308d46e9aa0c1986056e407efc7013b7f271027d3c98ce96667faa98074ab0588a61681faf78644c11819a459a95689dab0a30a759f6bcca8f35fcaadc406cc4b828c016c0ed23882987a79f52f2933b5cedefe24e31df6fd0d38e8a802dbafd750d010a30b5e898a1fc06d51c695712928f44646d15451340d1b3e480a40f03250160bc07d3b6691ec94361dd524d59d9df7f76d30a30ad9222dec71ff8ee6bc0426ffe7b5e66f96738225db281dd20027a1556d089fdebd040abfbc2041d6c1a0d8fdcfce1830a30aaddb0cb69ca18f14aed7054e98a24df0ff606aeff919d489f7884fd1bd183bcb46ea54bc363146e1a88db36dc20a7a40a30b2225575d5e70da1257db7a0d1222c5041b52aac61cf161e8fc8126a3fdf5eb4f0867d98dfe272199c36cf8f02661b3d0a308aa5bbee21e98c7b9e7a4c8ea45aa99f89e22992fa4fc2d73869d77da4cc8a05b25b61931ff521986677dd7f7159e8e60a30a804e4fa8d1391a9d078aa93985a12503b84ce4f6f1f9e70ab7fca421e1cf972538666299d4c1bfc39327b469b2db7a80a30ac69ae9e6c385a368df71d11ac68f45f05e005306df3c2bf98ed3577708256bd97f8c09d3f72115444077a9bb711d8d10a30af89ab00a0eab1131645292a9cfba583a69a1e3ac58b210e262494853e67385aeb50d4af428bdd577b9399daa96d8b200a3081ea9f74ef7d935b807474e38954ae3934856219a23e074954b2e860c5a3c400f9aedb42cd27cb4ceb697ca36d1e58cb0a30ab40dc1cfe273ad0da700c64f8fc94f91db253ca3acf20e336d9bd09de67eec5c7d3506285d83c7bb6a08d64b77e5f2d0a308d46e9aa0c1986056e407efc7013b7f271027d3c98ce96667faa98074ab0588a61681faf78644c11819a459a95689dab0a3091709ee06497b9ac049325853d64947290189a8c2322e3a500d91e23ea02dc158b6db63ae558b3b7670357a151cd60710a308c0d15baa72bfcd317e9b9402ca9bb6e7ae1db35ffce7faccae0bd19b3c8e5de7d5524aef0377770b3a90626627a93040a30a1d9840eda3036fbf63eeea40146e4548553e6e1b2a653ab349b376f31b367c40d71fb59ff8e94b91daa99c262ec8b520a309918433b8f0bc5e126da3fdef8d7b71456492dae6d2d07f2e10c7a7f852046f84ed0ce6d3bfec42200670db27dcf30370a30a0485d71f1f5e177f7d5bc9d98c5248a6a2d0de4554c2eaf02abae48f5a3e273b2ee7765784cf2a4cb7df84f617177c9123094fd008fbba3010a90f59c2217980c1fc8728f0fce547413d5c2486ef6773613ff332a8b9b2c09fe19502fbaf26d5d241a2064158fcb656c936b54a2ac4855abc182d13c35e1c34302b8611cf9ceb35416bf1a20eb6eb35caa14032309663b131c4f69223712abe3c343dd2e0e4a72fdfdaca65d1a20408c472e22bb7166e83973217e0e157a244fdb37a0057c3ebf9225e186e550db1a2076c08d6f29f0f3931f0c95e4cee610ce3e136e7f376e708a43466ee1010cdee41a20d7804b82e323f5a43ba1aac1a30a3e2a870fd07bfe625e3ac557e1ea6a43f7911a20953024c6ded67e542650258c58347cef640ac2bb254c6df6bc3af9bf3c1a1f7a226b08c02310141a205eba9772c79238672acf61345c3291281b4960bf9763912a60cbc9f0e1e460e62220762b6661d83d497cdbc2872d67149cf0dccaa38098256805cae761b06be0a5ed2a20e64c7f0d9d5678db653432be9e8d4ed240ec88e144d52f7d2d4dfe4fb90c55102a2038020000000000000000000000000000000000000000000000000000000000002a205f6f02af29218292d21a69b64a794a7c0873b3e0f54611972863706e8cbdf3712a208e5982fc2025ddfb5d92fc1ee5a6fc7942716f1f439b95d937ad070a4f7de1202a20408c472e22bb7166e83973217e0e157a244fdb37a0057c3ebf9225e186e550db2a2076c08d6f29f0f3931f0c95e4cee610ce3e136e7f376e708a43466ee1010cdee42a20d7804b82e323f5a43ba1aac1a30a3e2a870fd07bfe625e3ac557e1ea6a43f7912a20953024c6ded67e542650258c58347cef640ac2bb254c6df6bc3af9bf3c1a1f7a3220beddec06e365dc512ba64a7595748ac7d971136f49d01945a0be4081acf4be403a208fab73fdc084a6b85823d45d9e291b495f2e404f3f29b0cfb9d0cdbc6c2905003a209ea6bff680e53afa31936dcc523daeff16cfa8629fe3642b5442440ae2998fc53a206e817161402150ae7a3c42df6d68062e41bf358f5966510d5be0b8c40188772d3a201e5ac12d5d32276971fa1da09a4b389f26e403f891accf7f78301738dad4f66a42680a04ffffffff126088ccd7b8902c76b3309aee645c2e06fd18f444aad96656e030d383ad00181bfabcabf8364cf2ef5e6cd849c1dc65450c119dca18cebd50432fe7bb379aa9750bf841419766ab23f5c54610cfce8f10c2f6088d26d0bcfba4318a60e3164c014348d1231ac5040a20120517da013537f3596393c5fb17bd5e2fd2deac2421d6dc3f1aba157f6d0fc51220eaa8c40899a61ae59615cf9985f5e2194f8fd2b57d273be63bde6733e89b12ab1220c24d2dc5059d6453b759070d465f417055f0d66973f140d0b8ace66b8ba8006e12202f73765c92ed8e9e07186406a7095f69a53e2fc0b717caebe2482290697ef4571220bac7869fa617fb5331032e47ae63db0e6262f813bcd6ba9fa9f48adde6233a531220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c18c0232220005125020000000000000000000000000000000000000000000000000000000022207a2556ce05a0dbfd11906527a3dc6d684c3d7af4bc4078066ca3150255af9750222008c2ed0a25a4d41630ffcb90222c24da730cdfb2aa0e02dd8d30d3be8e57eba82220bac7869fa617fb5331032e47ae63db0e6262f813bcd6ba9fa9f48adde6233a532220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c2a2055e22fd7ea2aebfb836b4529a60cea2bda1b717f2e1ba946dded6307c03d24623220091d08fa31859c47f0f272c05a272abd5ff39b5eefa1bc22f6aba88a128b58c23220a09a2b87124e2c710b9d90a696327a3a76e1bde89ca3efbc730de5c19fa0eaa9322085f8312104836fa505c2d3b7e18404da258d2293bf1905bd88ee7e5a789664b532202adb30cd41fe2e2314817a6dbe523ec813d1824d234439814a04ba0036bedee43220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c20e5f4d1c106").to_vec(),
            cons_slot: 4544,
            cons_l1_current_sync_committee: PublicKey::try_from(hex!("92dc97a87ee2ab99deca4440a66d489b5d85984d807cd29147267873cb2d8925de6755c03c52fa941f90a65bb15d7351").to_vec()).unwrap(),
            cons_l1_next_sync_committee: PublicKey::try_from(hex!("94fd008fbba3010a90f59c2217980c1fc8728f0fce547413d5c2486ef6773613ff332a8b9b2c09fe19502fbaf26d5d24").to_vec()).unwrap(),
            cons_l1_timestamp: Time::from_unix_timestamp(1748269741, 0).unwrap(),
        },TestCase {
            raw_l1_header: hex!("0af70c0af20c0a30b5e898a1fc06d51c695712928f44646d15451340d1b3e480a40f03250160bc07d3b6691ec94361dd524d59d9df7f76d30a308aec5129a518010912215e1887191da94be419b4e75904c2ea745e2d253d707c088fa5b2c46dade1d162affe9f7ab17b0a3084d08d58c31bcd3cddf93e13d6f50203897384afa34644bff1135efe8e01c81c6a91ca6c234bb1e51ca32e41b828aaf90a30b72cb106b7bc1ecae219e0ae1830a509ed18a042b56a2779f4033419de69ba8ae8017090caed1f5377bfa685061573600a30aaf6c1251e73fb600624937760fef218aace5b253bf068ed45398aeb29d821e4d2899343ddcbbe37cb3f6cf500dff26c0a30a35c6004f387430c3797ab0157af7b824c8fe106241c7cdeb897d900c0f9e4bb945ff2a6b88cbd10e35ec48aaa554ecb0a30a75ca9447dca3a3745ada36731187ddd1f6a152cf15d7446b785eab381e5c8562c1202a6e7a24080bc6b619a161113db0a308dfa86c051edd28c3554a30e40531c898e5936ad3002711616ddd1b27054bc39caedd505a200c3d23a1c3f6b26c50ae90a308de5a6200cebb09b2198e69fed84bcd512ec5cf317c5f1ee99aad03d2a9a8564bf3807c08da2664222268d59c34a06e40a30b09cb155daf2022afd18114a352e506a84065c80573cb0c7c310cbe92e2706cdcf91f74bbd9e464f74e3d831386d50330a309763dde1b8028136a3ffd6dafd1f450e2cafb2819c7fa901f7c6e9cde8f2897ee7e9a45da6947fde1ad0d3836188eab50a30b27ad13afc8ff30e087797b344c8382bb0a84447549f1b0274059ddd652276e7b148ba8808a10cc45746762957d4efbe0a30ac69ae9e6c385a368df71d11ac68f45f05e005306df3c2bf98ed3577708256bd97f8c09d3f72115444077a9bb711d8d10a3081fa222737fe818b43f55f209f42adaee135b2801d02709617fc88c2871852358260ace97cf323e761b5cc18bc7325b30a308d46e9aa0c1986056e407efc7013b7f271027d3c98ce96667faa98074ab0588a61681faf78644c11819a459a95689dab0a30a759f6bcca8f35fcaadc406cc4b828c016c0ed23882987a79f52f2933b5cedefe24e31df6fd0d38e8a802dbafd750d010a30b5e898a1fc06d51c695712928f44646d15451340d1b3e480a40f03250160bc07d3b6691ec94361dd524d59d9df7f76d30a30ad9222dec71ff8ee6bc0426ffe7b5e66f96738225db281dd20027a1556d089fdebd040abfbc2041d6c1a0d8fdcfce1830a30aaddb0cb69ca18f14aed7054e98a24df0ff606aeff919d489f7884fd1bd183bcb46ea54bc363146e1a88db36dc20a7a40a30b2225575d5e70da1257db7a0d1222c5041b52aac61cf161e8fc8126a3fdf5eb4f0867d98dfe272199c36cf8f02661b3d0a308aa5bbee21e98c7b9e7a4c8ea45aa99f89e22992fa4fc2d73869d77da4cc8a05b25b61931ff521986677dd7f7159e8e60a30a804e4fa8d1391a9d078aa93985a12503b84ce4f6f1f9e70ab7fca421e1cf972538666299d4c1bfc39327b469b2db7a80a30ac69ae9e6c385a368df71d11ac68f45f05e005306df3c2bf98ed3577708256bd97f8c09d3f72115444077a9bb711d8d10a30af89ab00a0eab1131645292a9cfba583a69a1e3ac58b210e262494853e67385aeb50d4af428bdd577b9399daa96d8b200a3081ea9f74ef7d935b807474e38954ae3934856219a23e074954b2e860c5a3c400f9aedb42cd27cb4ceb697ca36d1e58cb0a30ab40dc1cfe273ad0da700c64f8fc94f91db253ca3acf20e336d9bd09de67eec5c7d3506285d83c7bb6a08d64b77e5f2d0a308d46e9aa0c1986056e407efc7013b7f271027d3c98ce96667faa98074ab0588a61681faf78644c11819a459a95689dab0a3091709ee06497b9ac049325853d64947290189a8c2322e3a500d91e23ea02dc158b6db63ae558b3b7670357a151cd60710a308c0d15baa72bfcd317e9b9402ca9bb6e7ae1db35ffce7faccae0bd19b3c8e5de7d5524aef0377770b3a90626627a93040a30a1d9840eda3036fbf63eeea40146e4548553e6e1b2a653ab349b376f31b367c40d71fb59ff8e94b91daa99c262ec8b520a309918433b8f0bc5e126da3fdef8d7b71456492dae6d2d07f2e10c7a7f852046f84ed0ce6d3bfec42200670db27dcf30370a30a0485d71f1f5e177f7d5bc9d98c5248a6a2d0de4554c2eaf02abae48f5a3e273b2ee7765784cf2a4cb7df84f617177c9123094fd008fbba3010a90f59c2217980c1fc8728f0fce547413d5c2486ef6773613ff332a8b9b2c09fe19502fbaf26d5d24100112a0140a6b089024103b1a20bb03a2ba5b175956ba556bd874afad656ee91588f36d02e452c8b0005fef6c1522205024ce05f66d309602b16089756d55abf651cfe00039728b730200eb49efd21f2a2052771ce40a312e84d2615a99024b2e90e871598aa1fd4a7d7ef5f311f8b9625d12f20c0a30ac69ae9e6c385a368df71d11ac68f45f05e005306df3c2bf98ed3577708256bd97f8c09d3f72115444077a9bb711d8d10a30a35c6004f387430c3797ab0157af7b824c8fe106241c7cdeb897d900c0f9e4bb945ff2a6b88cbd10e35ec48aaa554ecb0a3087231421a08ed28e7d357e2b37a26a458155c8d822d829344bd1029e5d175b5edfaa78f16f784f724a2caef124944c4f0a30ab40dc1cfe273ad0da700c64f8fc94f91db253ca3acf20e336d9bd09de67eec5c7d3506285d83c7bb6a08d64b77e5f2d0a30a1584dfe1573df8ec88c7b74d76726b4821bfe84bf886dd3c0e3f74c2ea18aa62ca44c871fb1c63971fccf6937e6501f0a30996323af7e545fb6363ace53f1538c7ddc3eb0d985b2479da3ee4ace10cbc393b518bf02d1a2ddb2f5bdf09b473933ea0a3086e014747c7922ccfc2b9d4bf6c1ecf0dc800197037858d0b85ab1944b4c3c14b95e0ed325bc42a6f467bc47ec27bc7b0a308725b32751419f22a54485790f8187d1ba52d84a31ad45738a93777fcd1ccbec1652229923f82f37793ce0fc2763fb4c0a30af61f263addfb41c46d66e60ecfb598a5942f648f58718b6b4e4c92019fdb12328efbff98703134bcf28e9c1fab4bb600a30930743bfc7e18d3bd7351eaa74f477505268c1e4e1fd1ca3ccccdefb2595517343bbb8f5589c435c3c39323a4c0080f80a30ab40dc1cfe273ad0da700c64f8fc94f91db253ca3acf20e336d9bd09de67eec5c7d3506285d83c7bb6a08d64b77e5f2d0a308419cf00f2783c430dc861a710984d0429d3b3a7f6db849b4f5c05e0d87339704c5c7f5eede6adfc8776d666587b59320a308419cf00f2783c430dc861a710984d0429d3b3a7f6db849b4f5c05e0d87339704c5c7f5eede6adfc8776d666587b59320a30a2e2d8384fc87a512ee34eb43405fd82572c9d7cd96e155a382cda284e8df9eb7189c25b7473d89c63ea4e6080e10ff80a30ab72cbc6575c3179680a58c0ecd5de46d2678ccbafc016746348ee5688edcb21b4e15bd37c70c508e3ea73103c2d566b0a308d028a021c5c31a1aa1e18eda74cfaf0fba1c454c17c2e0fc730dd07a19d0c77f7a905d54017292f3e800ca06b6977cd0a30ad9222dec71ff8ee6bc0426ffe7b5e66f96738225db281dd20027a1556d089fdebd040abfbc2041d6c1a0d8fdcfce1830a308a8bb292bcc481070d3afdbbc8789e2ab4b29c9603936e6d85f5ff71e23fc5b6d61009f0fa636b5d5b2dc309d39e3d750a30af61f263addfb41c46d66e60ecfb598a5942f648f58718b6b4e4c92019fdb12328efbff98703134bcf28e9c1fab4bb600a30ae940a07850cf904b44f31cbf0e44824bae5ec36dcfdb7fad858f2a39dba38de82ca12b0ae939a34fce7a02e4b9789f80a3087231421a08ed28e7d357e2b37a26a458155c8d822d829344bd1029e5d175b5edfaa78f16f784f724a2caef124944c4f0a30abd12678c73463ecea5867a80caf256d5c5e6ba53ff188b143a4d5be83365ad257edf39eaa1ba8753c4cdf4c632ff99e0a30afa10af166a0dbf3a25ff86cd6f8e44cccc818c5e70cd70e4e98e226b158f3563450b3fb184d2649adbb11e53080d1ca0a3096947de9e6068c22a7716656a2755a9551b0b66c2d1a741bf84a088fe1e840e992dc39861bf8ba3e8d5b6d21e8f57e640a30a0485d71f1f5e177f7d5bc9d98c5248a6a2d0de4554c2eaf02abae48f5a3e273b2ee7765784cf2a4cb7df84f617177c90a30ab40dc1cfe273ad0da700c64f8fc94f91db253ca3acf20e336d9bd09de67eec5c7d3506285d83c7bb6a08d64b77e5f2d0a30aaf6c1251e73fb600624937760fef218aace5b253bf068ed45398aeb29d821e4d2899343ddcbbe37cb3f6cf500dff26c0a30a2e2d8384fc87a512ee34eb43405fd82572c9d7cd96e155a382cda284e8df9eb7189c25b7473d89c63ea4e6080e10ff80a30996d10c3026b9344532b06c70a596f972a1e779a1f6106d3da9f6ba376bbf7ec82d2f52629e5dbf3f7d03b00f6b862af0a3099d83a0ba33161d8c6bbe80929fd9046d4dfdac43477ff85fea5bae925e6c179ad28eb338375ee2417acbd6576ee670a0a3087231421a08ed28e7d357e2b37a26a458155c8d822d829344bd1029e5d175b5edfaa78f16f784f724a2caef124944c4f0a30b2225575d5e70da1257db7a0d1222c5041b52aac61cf161e8fc8126a3fdf5eb4f0867d98dfe272199c36cf8f02661b3d123090db4f4535b735792b28e650d4b5bda8d33235ffef377c5cee554cd2190dd3986bfa561666f3f457bc91b5afccc394381a20c7e909ea4b9c47265ebc664f7fafb3ca8813251144ebdfe1399419e88f39d0961a205d30e1e94c940ecf848af6265a41fe1defde72baafa4d71415dcfc246dbb867a1a20e7604424e91ab26a9148dd84a5bb9400226d9709db32d95b9316d8bec50996ff1a2080c89f4e265139bb86a1704d51dc2c4c9ef230b23db69cbb35a7998226d4c55d1a20eef8c98deecd0be5c0e78f8a95ba1bff72f269565a54abb0c8256b93f32c2bd01a20953024c6ded67e542650258c58347cef640ac2bb254c6df6bc3af9bf3c1a1f7a226b08802410021a20a5f380916193c4196aa2c8bb0fbec86baab00a3fcc9699ad537137d095c304d3222079ff1a2f89eaf10e82ad6f683594d5d8e52457270f79cd07a614f975d249df4b2a20816dde700dd0509ab1404dfc7a77684d17866a0a248cfd1644ebad54c7970b712a2040020000000000000000000000000000000000000000000000000000000000002a205f6f02af29218292d21a69b64a794a7c0873b3e0f54611972863706e8cbdf3712a2089bc05253a8124fbc5c219f1348ee02c4b6ded381d370f603344f9b4b1f0d2d92a20e7604424e91ab26a9148dd84a5bb9400226d9709db32d95b9316d8bec50996ff2a2080c89f4e265139bb86a1704d51dc2c4c9ef230b23db69cbb35a7998226d4c55d2a20eef8c98deecd0be5c0e78f8a95ba1bff72f269565a54abb0c8256b93f32c2bd02a20953024c6ded67e542650258c58347cef640ac2bb254c6df6bc3af9bf3c1a1f7a3220363c40fd826221ef0dd812b5ef66f4bcb213773c59f0c87f0f1d5f5c89a5756e3a20b59ec922c00d07125086fe9c15e0be160033015f3b861afc1f05f1240d4ed4a43a20e81f0be9d6081fecddccaad7b4738aeedc4677d0a63ecba0cb445bbf1aac43f23a206e817161402150ae7a3c42df6d68062e41bf358f5966510d5be0b8c40188772d3a209525513ada46a215e0c92faa9b64778f5e6000beababe00e667f39636ed248f842680a04ffffffff1260b4732faf98f1ec95607d45cfbfbe825dc1e2f6a23615f8ff697d99ad824f0670610ce53bed57d4768e0693f784fc294e020e6aee466e5a44973c2f7d56b64b786072d8cb855b53ca897d7e018c0bea1bf2fe5b7990e2d4662ff805b4e4c8e8504891241ac5040a2057b4a80cd052cb20f7271150923cd8e4e8347c8937fb697293a90a736b5b9e911220eaa8c40899a61ae59615cf9985f5e2194f8fd2b57d273be63bde6733e89b12ab12201358cdca94d4f9e8351c98b0ce0b9efe17ab113de25d27907281affe838ea46912208190ba26aeddee0d91576d4b1e9692e6afb21e64686061baae5cc43f643a0a0112201deca5806b85d197f4e572c23f7839910c925995238404e3fed45a064e91971c1220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c18802422200051250200000000000000000000000000000000000000000000000000000000222005f2985710cf2183e55638cc673380e0d44417828d5a71423a0a0f83a86d19e122205612bed643b7f37d9bf750d19195946302899f8a0fc2e51b43aef6e4a674ffe422201deca5806b85d197f4e572c23f7839910c925995238404e3fed45a064e91971c2220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c2a20fbfa3ea8e30e6182ff2475c45654322363a26cd07998304e34cd1b50c6daea3b3220186b741d5bb9912b8c01b43410c3d686020d597b637969f861ccd53d2b70beea3220a09a2b87124e2c710b9d90a696327a3a76e1bde89ca3efbc730de5c19fa0eaa93220e58be1b6893cb3f2a8b489d19c4be2f9205754646d6e634f6a20ad65410240f932209f4d2958a671cec2b062e9c35550a5eb5223d95f3ace1c2e3b69a61da876fe743220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c20e5f7d1c106").to_vec(),
            cons_slot: 4544,
            cons_l1_current_sync_committee: PublicKey::try_from(hex!("94fd008fbba3010a90f59c2217980c1fc8728f0fce547413d5c2486ef6773613ff332a8b9b2c09fe19502fbaf26d5d24").to_vec()).unwrap(),
            cons_l1_next_sync_committee: PublicKey::try_from(hex!("94fd008fbba3010a90f59c2217980c1fc8728f0fce547413d5c2486ef6773613ff332a8b9b2c09fe19502fbaf26d5d24").to_vec()).unwrap(),
            cons_l1_timestamp: Time::from_unix_timestamp(1748269669, 0).unwrap(),
        }, TestCase {
            raw_l1_header: hex!("0af70c0af20c0a30ac69ae9e6c385a368df71d11ac68f45f05e005306df3c2bf98ed3577708256bd97f8c09d3f72115444077a9bb711d8d10a30a35c6004f387430c3797ab0157af7b824c8fe106241c7cdeb897d900c0f9e4bb945ff2a6b88cbd10e35ec48aaa554ecb0a3087231421a08ed28e7d357e2b37a26a458155c8d822d829344bd1029e5d175b5edfaa78f16f784f724a2caef124944c4f0a30ab40dc1cfe273ad0da700c64f8fc94f91db253ca3acf20e336d9bd09de67eec5c7d3506285d83c7bb6a08d64b77e5f2d0a30a1584dfe1573df8ec88c7b74d76726b4821bfe84bf886dd3c0e3f74c2ea18aa62ca44c871fb1c63971fccf6937e6501f0a30996323af7e545fb6363ace53f1538c7ddc3eb0d985b2479da3ee4ace10cbc393b518bf02d1a2ddb2f5bdf09b473933ea0a3086e014747c7922ccfc2b9d4bf6c1ecf0dc800197037858d0b85ab1944b4c3c14b95e0ed325bc42a6f467bc47ec27bc7b0a308725b32751419f22a54485790f8187d1ba52d84a31ad45738a93777fcd1ccbec1652229923f82f37793ce0fc2763fb4c0a30af61f263addfb41c46d66e60ecfb598a5942f648f58718b6b4e4c92019fdb12328efbff98703134bcf28e9c1fab4bb600a30930743bfc7e18d3bd7351eaa74f477505268c1e4e1fd1ca3ccccdefb2595517343bbb8f5589c435c3c39323a4c0080f80a30ab40dc1cfe273ad0da700c64f8fc94f91db253ca3acf20e336d9bd09de67eec5c7d3506285d83c7bb6a08d64b77e5f2d0a308419cf00f2783c430dc861a710984d0429d3b3a7f6db849b4f5c05e0d87339704c5c7f5eede6adfc8776d666587b59320a308419cf00f2783c430dc861a710984d0429d3b3a7f6db849b4f5c05e0d87339704c5c7f5eede6adfc8776d666587b59320a30a2e2d8384fc87a512ee34eb43405fd82572c9d7cd96e155a382cda284e8df9eb7189c25b7473d89c63ea4e6080e10ff80a30ab72cbc6575c3179680a58c0ecd5de46d2678ccbafc016746348ee5688edcb21b4e15bd37c70c508e3ea73103c2d566b0a308d028a021c5c31a1aa1e18eda74cfaf0fba1c454c17c2e0fc730dd07a19d0c77f7a905d54017292f3e800ca06b6977cd0a30ad9222dec71ff8ee6bc0426ffe7b5e66f96738225db281dd20027a1556d089fdebd040abfbc2041d6c1a0d8fdcfce1830a308a8bb292bcc481070d3afdbbc8789e2ab4b29c9603936e6d85f5ff71e23fc5b6d61009f0fa636b5d5b2dc309d39e3d750a30af61f263addfb41c46d66e60ecfb598a5942f648f58718b6b4e4c92019fdb12328efbff98703134bcf28e9c1fab4bb600a30ae940a07850cf904b44f31cbf0e44824bae5ec36dcfdb7fad858f2a39dba38de82ca12b0ae939a34fce7a02e4b9789f80a3087231421a08ed28e7d357e2b37a26a458155c8d822d829344bd1029e5d175b5edfaa78f16f784f724a2caef124944c4f0a30abd12678c73463ecea5867a80caf256d5c5e6ba53ff188b143a4d5be83365ad257edf39eaa1ba8753c4cdf4c632ff99e0a30afa10af166a0dbf3a25ff86cd6f8e44cccc818c5e70cd70e4e98e226b158f3563450b3fb184d2649adbb11e53080d1ca0a3096947de9e6068c22a7716656a2755a9551b0b66c2d1a741bf84a088fe1e840e992dc39861bf8ba3e8d5b6d21e8f57e640a30a0485d71f1f5e177f7d5bc9d98c5248a6a2d0de4554c2eaf02abae48f5a3e273b2ee7765784cf2a4cb7df84f617177c90a30ab40dc1cfe273ad0da700c64f8fc94f91db253ca3acf20e336d9bd09de67eec5c7d3506285d83c7bb6a08d64b77e5f2d0a30aaf6c1251e73fb600624937760fef218aace5b253bf068ed45398aeb29d821e4d2899343ddcbbe37cb3f6cf500dff26c0a30a2e2d8384fc87a512ee34eb43405fd82572c9d7cd96e155a382cda284e8df9eb7189c25b7473d89c63ea4e6080e10ff80a30996d10c3026b9344532b06c70a596f972a1e779a1f6106d3da9f6ba376bbf7ec82d2f52629e5dbf3f7d03b00f6b862af0a3099d83a0ba33161d8c6bbe80929fd9046d4dfdac43477ff85fea5bae925e6c179ad28eb338375ee2417acbd6576ee670a0a3087231421a08ed28e7d357e2b37a26a458155c8d822d829344bd1029e5d175b5edfaa78f16f784f724a2caef124944c4f0a30b2225575d5e70da1257db7a0d1222c5041b52aac61cf161e8fc8126a3fdf5eb4f0867d98dfe272199c36cf8f02661b3d123090db4f4535b735792b28e650d4b5bda8d33235ffef377c5cee554cd2190dd3986bfa561666f3f457bc91b5afccc39438100112a0140a6b08d02410331a2052403f0dae194eb066a7b6c8f636440382b2adb3757d6d06f21f0af56e49106d22200388a8bc0c7cfb9208632b6e5c3e6cf02fe42be8892be6001e6dcda355eb59642a204af12457b8a69b908e1181ecb7f1c504c9dbfcc47c4443c12996eb860b4f6bb412f20c0a30a35c6004f387430c3797ab0157af7b824c8fe106241c7cdeb897d900c0f9e4bb945ff2a6b88cbd10e35ec48aaa554ecb0a30896a51e0b0de0f29029af38b796db1f1e6d0f9f9085ade40a313a60cb723fa3d58f6587175570086c4fbf0fe5331f1c80a30b24391aa97bfff29adc935d06a2b6d583433caf82f92de1980e0192d3b270323bdbf24b86dc61520a40c419dde3df4b30a30abd12678c73463ecea5867a80caf256d5c5e6ba53ff188b143a4d5be83365ad257edf39eaa1ba8753c4cdf4c632ff99e0a30b570dde8ee80512e3d031caf22e775c60f7f5a6cbdeb3e52e24cf8c867d38569a53dd19cdc36a03a1bbb3a8d94b036700a30958c2692b86b4d20eaea3bb45e9447ebbc5b93ccaf8d21ef659d0cefedf5c4371b31b460ae40e8243682bde505abac1e0a30a1584dfe1573df8ec88c7b74d76726b4821bfe84bf886dd3c0e3f74c2ea18aa62ca44c871fb1c63971fccf6937e6501f0a309918433b8f0bc5e126da3fdef8d7b71456492dae6d2d07f2e10c7a7f852046f84ed0ce6d3bfec42200670db27dcf30370a30b570dde8ee80512e3d031caf22e775c60f7f5a6cbdeb3e52e24cf8c867d38569a53dd19cdc36a03a1bbb3a8d94b036700a309918433b8f0bc5e126da3fdef8d7b71456492dae6d2d07f2e10c7a7f852046f84ed0ce6d3bfec42200670db27dcf30370a30aaddb0cb69ca18f14aed7054e98a24df0ff606aeff919d489f7884fd1bd183bcb46ea54bc363146e1a88db36dc20a7a40a30a54fe5c26059ed60b4f0b66ef7b0bf167580504525f83c169507dc812816df41b1da6128341c23977300dffd32a32f410a30ae5302796cfeca685eaf37ffd5baeb32121f2f07415bee26cc0051ee513ff3932d2c365e3d9f87b0949a5980445cb64c0a30ab40dc1cfe273ad0da700c64f8fc94f91db253ca3acf20e336d9bd09de67eec5c7d3506285d83c7bb6a08d64b77e5f2d0a30a4ee6d37dc259cbb5237e4265429a9fd8ab5643af81628cc101e0d8b4a333ef2618a37df89ea3f92b5ea4333d8cda3930a30a62c0205fb22df8535c0b70076486e69dfa908feddae79e4a94a9d47b97ed190d228e1c6217e84a59882bb992dacae300a308aec5129a518010912215e1887191da94be419b4e75904c2ea745e2d253d707c088fa5b2c46dade1d162affe9f7ab17b0a3084dc37ca3cd621d3da0fbdd11ca84021e0cd81a73d772dd6fcf19775b72eb64af4e573213378ccee0915dde92ac83ba60a30958c2692b86b4d20eaea3bb45e9447ebbc5b93ccaf8d21ef659d0cefedf5c4371b31b460ae40e8243682bde505abac1e0a30afa10af166a0dbf3a25ff86cd6f8e44cccc818c5e70cd70e4e98e226b158f3563450b3fb184d2649adbb11e53080d1ca0a30ab64f900c770e2b99de6b86b4390bbd1579bd48dccec55800adbcf52e006f22128e9971bbf3a92cc0105b0974849935a0a30af61f263addfb41c46d66e60ecfb598a5942f648f58718b6b4e4c92019fdb12328efbff98703134bcf28e9c1fab4bb600a30a4ee6d37dc259cbb5237e4265429a9fd8ab5643af81628cc101e0d8b4a333ef2618a37df89ea3f92b5ea4333d8cda3930a30a0485d71f1f5e177f7d5bc9d98c5248a6a2d0de4554c2eaf02abae48f5a3e273b2ee7765784cf2a4cb7df84f617177c90a30a4ee6d37dc259cbb5237e4265429a9fd8ab5643af81628cc101e0d8b4a333ef2618a37df89ea3f92b5ea4333d8cda3930a3096947de9e6068c22a7716656a2755a9551b0b66c2d1a741bf84a088fe1e840e992dc39861bf8ba3e8d5b6d21e8f57e640a30996323af7e545fb6363ace53f1538c7ddc3eb0d985b2479da3ee4ace10cbc393b518bf02d1a2ddb2f5bdf09b473933ea0a309918433b8f0bc5e126da3fdef8d7b71456492dae6d2d07f2e10c7a7f852046f84ed0ce6d3bfec42200670db27dcf30370a3099d83a0ba33161d8c6bbe80929fd9046d4dfdac43477ff85fea5bae925e6c179ad28eb338375ee2417acbd6576ee670a0a30a4ee6d37dc259cbb5237e4265429a9fd8ab5643af81628cc101e0d8b4a333ef2618a37df89ea3f92b5ea4333d8cda3930a30a03c2a82374e04b2e0594c4ce14fb3f225b46f13188f0d8002a523c7dcfb939ae4856053c2c9c695374d7c3685df1ca50a3084a687ffdf21a0ad754d0164d1e2c03035613ab76359e7f5cf51ea4a425a6ee026725ec0a0dbd336f7dab759596f0bf812308582bbad3f9eee79addd939370c7241ee96d425c6a5d6e7fb89e59ad117c38e62064e56821b77b26353be13b86d6a66c1a203e2514e078324c8b3504b5f813a92fde5f5405c64130ce63125b858e6c1de4b61a201de254acef8180715f8179ca441e5e86cd5465b7bc4a5cab927dd2f2abbbadbd1a206c779eb7a5fe303ec2b4206a3956a34027c9e169d827724db36c1960564a2fbb1a202c06da9648e41f2c8cfff383f0e825b36c63623b995d60a7dfb2d66c62ebb1981a20dfa5419fb91e05b33e1e832ef49fb3e95f8d9180af8a5529fdb7be6803388bd81a20953024c6ded67e542650258c58347cef640ac2bb254c6df6bc3af9bf3c1a1f7a226b08c02410161a200c8ed888f267cdc3248af65795f92e45818c7ec2c10435c85534470418d4911222203700c509a5ad17d7d9be66d3f2318173bb08003594e67431e21709386929e6dd2a2080f626671e5f11ab68c3c79d34d4d65f4afc442acdbd681513c3d0043a68354e2a2048020000000000000000000000000000000000000000000000000000000000002a205f6f02af29218292d21a69b64a794a7c0873b3e0f54611972863706e8cbdf3712a20f11cf1cdb8c2cb8de492a9a4e0914dd9ddc87c7038cde2fe8e81201aa93284952a206c779eb7a5fe303ec2b4206a3956a34027c9e169d827724db36c1960564a2fbb2a202c06da9648e41f2c8cfff383f0e825b36c63623b995d60a7dfb2d66c62ebb1982a20dfa5419fb91e05b33e1e832ef49fb3e95f8d9180af8a5529fdb7be6803388bd82a20953024c6ded67e542650258c58347cef640ac2bb254c6df6bc3af9bf3c1a1f7a3220168b1e8c2095a23da05ac66a5fd4aba64137ffd34c374bf77208e900fa6696dd3a206955741282e79b5a645c4cb3ffab40632d6f6ac76508e026733cd7a2a730d72d3a2053e7d3a01b45f8e1559189d9879dfdae8b75c46b19451f79ed77bb0198b9a2033a206e817161402150ae7a3c42df6d68062e41bf358f5966510d5be0b8c40188772d3a20105db9623f254edcda37b807de91af67d0bb6370971bf93127ab6368e58ff35942680a04ffffffff1260a64f854112e8991fd496459ace02564800477264f7041c8c6b691051fc20c176852f864dd212f98260df6e38087dba7d1351b4825f6c1218a0cbd7ef7925f5de642a906a9370f272d19c9320890e892ddacf6a611f3f2fac33a0141fc9a9284a48d1241ac5040a2015a64d60c99f4008f546ebd804ebea268bec35a0405c59c6557315486e8d27761220eaa8c40899a61ae59615cf9985f5e2194f8fd2b57d273be63bde6733e89b12ab1220fe53b80ce96c68cfb233ea0a4a867f6e9d989be63264923bbc3affb22757b4671220c916cf86fac26d5f352c43e9491e5912dd60fa72d43c2536a88a4fe7e4a6e4ea1220c29a7c18740ed315262aae05b960d2a134bc1010aed9251ea9abb6f8f8693c5f1220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c18c0242220005125020000000000000000000000000000000000000000000000000000000022203e09671e4bf86cfcce3b67e17e2887d057260e17cec36a7ab674a3918f432f28222042f454323ff3d93d865312c713144045875048e7c2d30a33ae8edb1a1b94ba5c2220c29a7c18740ed315262aae05b960d2a134bc1010aed9251ea9abb6f8f8693c5f2220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c2a202ed06239bbc25c30e86ea118937b9fcfa1f6b4c900fe5d2addb06858d0e22467322013822036d36528f2ee7f323626b128e378a75931836de84a9ce065860dacb9a83220a09a2b87124e2c710b9d90a696327a3a76e1bde89ca3efbc730de5c19fa0eaa93220159bccf6295dc27b4fa7e37189156c755466fb03b5b3ba67245d453b37cc9b3a32206afe43d5077c9d8a569d13294bc9fb51897fea911d903a54e01ae0647260c9383220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c20e5fad1c106").to_vec(),
            cons_slot: 4608,
            cons_l1_current_sync_committee: PublicKey::try_from(hex!("94fd008fbba3010a90f59c2217980c1fc8728f0fce547413d5c2486ef6773613ff332a8b9b2c09fe19502fbaf26d5d24").to_vec()).unwrap(),
            cons_l1_next_sync_committee: PublicKey::try_from(hex!("90db4f4535b735792b28e650d4b5bda8d33235ffef377c5cee554cd2190dd3986bfa561666f3f457bc91b5afccc39438").to_vec()).unwrap(),
            cons_l1_timestamp: Time::from_unix_timestamp(1748270053, 0).unwrap(),
        }, TestCase {
            raw_l1_header: hex!("0af70c0af20c0a30a35c6004f387430c3797ab0157af7b824c8fe106241c7cdeb897d900c0f9e4bb945ff2a6b88cbd10e35ec48aaa554ecb0a30896a51e0b0de0f29029af38b796db1f1e6d0f9f9085ade40a313a60cb723fa3d58f6587175570086c4fbf0fe5331f1c80a30b24391aa97bfff29adc935d06a2b6d583433caf82f92de1980e0192d3b270323bdbf24b86dc61520a40c419dde3df4b30a30abd12678c73463ecea5867a80caf256d5c5e6ba53ff188b143a4d5be83365ad257edf39eaa1ba8753c4cdf4c632ff99e0a30b570dde8ee80512e3d031caf22e775c60f7f5a6cbdeb3e52e24cf8c867d38569a53dd19cdc36a03a1bbb3a8d94b036700a30958c2692b86b4d20eaea3bb45e9447ebbc5b93ccaf8d21ef659d0cefedf5c4371b31b460ae40e8243682bde505abac1e0a30a1584dfe1573df8ec88c7b74d76726b4821bfe84bf886dd3c0e3f74c2ea18aa62ca44c871fb1c63971fccf6937e6501f0a309918433b8f0bc5e126da3fdef8d7b71456492dae6d2d07f2e10c7a7f852046f84ed0ce6d3bfec42200670db27dcf30370a30b570dde8ee80512e3d031caf22e775c60f7f5a6cbdeb3e52e24cf8c867d38569a53dd19cdc36a03a1bbb3a8d94b036700a309918433b8f0bc5e126da3fdef8d7b71456492dae6d2d07f2e10c7a7f852046f84ed0ce6d3bfec42200670db27dcf30370a30aaddb0cb69ca18f14aed7054e98a24df0ff606aeff919d489f7884fd1bd183bcb46ea54bc363146e1a88db36dc20a7a40a30a54fe5c26059ed60b4f0b66ef7b0bf167580504525f83c169507dc812816df41b1da6128341c23977300dffd32a32f410a30ae5302796cfeca685eaf37ffd5baeb32121f2f07415bee26cc0051ee513ff3932d2c365e3d9f87b0949a5980445cb64c0a30ab40dc1cfe273ad0da700c64f8fc94f91db253ca3acf20e336d9bd09de67eec5c7d3506285d83c7bb6a08d64b77e5f2d0a30a4ee6d37dc259cbb5237e4265429a9fd8ab5643af81628cc101e0d8b4a333ef2618a37df89ea3f92b5ea4333d8cda3930a30a62c0205fb22df8535c0b70076486e69dfa908feddae79e4a94a9d47b97ed190d228e1c6217e84a59882bb992dacae300a308aec5129a518010912215e1887191da94be419b4e75904c2ea745e2d253d707c088fa5b2c46dade1d162affe9f7ab17b0a3084dc37ca3cd621d3da0fbdd11ca84021e0cd81a73d772dd6fcf19775b72eb64af4e573213378ccee0915dde92ac83ba60a30958c2692b86b4d20eaea3bb45e9447ebbc5b93ccaf8d21ef659d0cefedf5c4371b31b460ae40e8243682bde505abac1e0a30afa10af166a0dbf3a25ff86cd6f8e44cccc818c5e70cd70e4e98e226b158f3563450b3fb184d2649adbb11e53080d1ca0a30ab64f900c770e2b99de6b86b4390bbd1579bd48dccec55800adbcf52e006f22128e9971bbf3a92cc0105b0974849935a0a30af61f263addfb41c46d66e60ecfb598a5942f648f58718b6b4e4c92019fdb12328efbff98703134bcf28e9c1fab4bb600a30a4ee6d37dc259cbb5237e4265429a9fd8ab5643af81628cc101e0d8b4a333ef2618a37df89ea3f92b5ea4333d8cda3930a30a0485d71f1f5e177f7d5bc9d98c5248a6a2d0de4554c2eaf02abae48f5a3e273b2ee7765784cf2a4cb7df84f617177c90a30a4ee6d37dc259cbb5237e4265429a9fd8ab5643af81628cc101e0d8b4a333ef2618a37df89ea3f92b5ea4333d8cda3930a3096947de9e6068c22a7716656a2755a9551b0b66c2d1a741bf84a088fe1e840e992dc39861bf8ba3e8d5b6d21e8f57e640a30996323af7e545fb6363ace53f1538c7ddc3eb0d985b2479da3ee4ace10cbc393b518bf02d1a2ddb2f5bdf09b473933ea0a309918433b8f0bc5e126da3fdef8d7b71456492dae6d2d07f2e10c7a7f852046f84ed0ce6d3bfec42200670db27dcf30370a3099d83a0ba33161d8c6bbe80929fd9046d4dfdac43477ff85fea5bae925e6c179ad28eb338375ee2417acbd6576ee670a0a30a4ee6d37dc259cbb5237e4265429a9fd8ab5643af81628cc101e0d8b4a333ef2618a37df89ea3f92b5ea4333d8cda3930a30a03c2a82374e04b2e0594c4ce14fb3f225b46f13188f0d8002a523c7dcfb939ae4856053c2c9c695374d7c3685df1ca50a3084a687ffdf21a0ad754d0164d1e2c03035613ab76359e7f5cf51ea4a425a6ee026725ec0a0dbd336f7dab759596f0bf812308582bbad3f9eee79addd939370c7241ee96d425c6a5d6e7fb89e59ad117c38e62064e56821b77b26353be13b86d6a66c100112a0140a6b089025102d1a2098cafb088ed485add1e7ebbf781f87cfd0ee1843c530fc58ea0441d7611e42bc2220731cece7df5359d49cbc5803491385d389a6ce079e8549d1755d66acca0ba49a2a203a8f399041af0bcc34fd104ad3ca95ff35bb4045694d9eba30d1ed66dbc139db12f20c0a30a03c2a82374e04b2e0594c4ce14fb3f225b46f13188f0d8002a523c7dcfb939ae4856053c2c9c695374d7c3685df1ca50a30a1584dfe1573df8ec88c7b74d76726b4821bfe84bf886dd3c0e3f74c2ea18aa62ca44c871fb1c63971fccf6937e6501f0a308fda66b8607af873f4c2c8218dd3ffc7940d411047eb199b5cd010156af4845d21dd2e65b0e44cfffb5e78271e9bb29d0a30b72cb106b7bc1ecae219e0ae1830a509ed18a042b56a2779f4033419de69ba8ae8017090caed1f5377bfa685061573600a30a4ee6d37dc259cbb5237e4265429a9fd8ab5643af81628cc101e0d8b4a333ef2618a37df89ea3f92b5ea4333d8cda3930a308aa5bbee21e98c7b9e7a4c8ea45aa99f89e22992fa4fc2d73869d77da4cc8a05b25b61931ff521986677dd7f7159e8e60a30a1584dfe1573df8ec88c7b74d76726b4821bfe84bf886dd3c0e3f74c2ea18aa62ca44c871fb1c63971fccf6937e6501f0a3084dc37ca3cd621d3da0fbdd11ca84021e0cd81a73d772dd6fcf19775b72eb64af4e573213378ccee0915dde92ac83ba60a30a4ee6d37dc259cbb5237e4265429a9fd8ab5643af81628cc101e0d8b4a333ef2618a37df89ea3f92b5ea4333d8cda3930a308d8985e5dd341c9035b37bf7391c5944c28131b47c7d5359d18fca598010ba9a63e27c55e6b421a807038c320564db170a30a35c6004f387430c3797ab0157af7b824c8fe106241c7cdeb897d900c0f9e4bb945ff2a6b88cbd10e35ec48aaa554ecb0a30ac69ae9e6c385a368df71d11ac68f45f05e005306df3c2bf98ed3577708256bd97f8c09d3f72115444077a9bb711d8d10a308aec5129a518010912215e1887191da94be419b4e75904c2ea745e2d253d707c088fa5b2c46dade1d162affe9f7ab17b0a30930743bfc7e18d3bd7351eaa74f477505268c1e4e1fd1ca3ccccdefb2595517343bbb8f5589c435c3c39323a4c0080f80a30a35c6004f387430c3797ab0157af7b824c8fe106241c7cdeb897d900c0f9e4bb945ff2a6b88cbd10e35ec48aaa554ecb0a30a0485d71f1f5e177f7d5bc9d98c5248a6a2d0de4554c2eaf02abae48f5a3e273b2ee7765784cf2a4cb7df84f617177c90a30a8fa3584a92b079c8c73ed1553e5e161a0b21325fc2fc4e24a892354a899c7fc0bfb436a97a7ed1fc71bccda438ea7150a30ab64f900c770e2b99de6b86b4390bbd1579bd48dccec55800adbcf52e006f22128e9971bbf3a92cc0105b0974849935a0a30a8fa3584a92b079c8c73ed1553e5e161a0b21325fc2fc4e24a892354a899c7fc0bfb436a97a7ed1fc71bccda438ea7150a308d8985e5dd341c9035b37bf7391c5944c28131b47c7d5359d18fca598010ba9a63e27c55e6b421a807038c320564db170a30aaf6c1251e73fb600624937760fef218aace5b253bf068ed45398aeb29d821e4d2899343ddcbbe37cb3f6cf500dff26c0a30a8fa3584a92b079c8c73ed1553e5e161a0b21325fc2fc4e24a892354a899c7fc0bfb436a97a7ed1fc71bccda438ea7150a30ae5302796cfeca685eaf37ffd5baeb32121f2f07415bee26cc0051ee513ff3932d2c365e3d9f87b0949a5980445cb64c0a309763dde1b8028136a3ffd6dafd1f450e2cafb2819c7fa901f7c6e9cde8f2897ee7e9a45da6947fde1ad0d3836188eab50a30958c2692b86b4d20eaea3bb45e9447ebbc5b93ccaf8d21ef659d0cefedf5c4371b31b460ae40e8243682bde505abac1e0a30a804e4fa8d1391a9d078aa93985a12503b84ce4f6f1f9e70ab7fca421e1cf972538666299d4c1bfc39327b469b2db7a80a30930743bfc7e18d3bd7351eaa74f477505268c1e4e1fd1ca3ccccdefb2595517343bbb8f5589c435c3c39323a4c0080f80a30a8fa3584a92b079c8c73ed1553e5e161a0b21325fc2fc4e24a892354a899c7fc0bfb436a97a7ed1fc71bccda438ea7150a30b72cb106b7bc1ecae219e0ae1830a509ed18a042b56a2779f4033419de69ba8ae8017090caed1f5377bfa685061573600a30af89ab00a0eab1131645292a9cfba583a69a1e3ac58b210e262494853e67385aeb50d4af428bdd577b9399daa96d8b200a308d8985e5dd341c9035b37bf7391c5944c28131b47c7d5359d18fca598010ba9a63e27c55e6b421a807038c320564db170a308fda66b8607af873f4c2c8218dd3ffc7940d411047eb199b5cd010156af4845d21dd2e65b0e44cfffb5e78271e9bb29d12309325339b023fc50bc744ef7fdd824b7b5bc9315244bb0b39914dec4b902c906f064b9c913de3c16a4a505ca75f5bff2f1a206513aeb2fadbe569185826caaaa8a6e2d22b5b7ae97ce5fc795de6f7206c66a31a20243d8d8f3307b4dd1be276403dd776a691e9ccd8cfa088b76d8e5cf5959bb5071a20149c1dd2231306fafe93aae46fc748b26d2dc3822e2e896f32f9073c3984a8f91a201a9bd5ad63f4a2da9efcd077e67323dd41debd2f638650163251008af69d2d501a203eadd0b161343dc74bc3b8a8a3ca19af58505837886485ed68f9a77cb63406921a20953024c6ded67e542650258c58347cef640ac2bb254c6df6bc3af9bf3c1a1f7a226b08802510261a204051ec04f0298604a1b74cce78b26018dff72b0b91af1446ee2443a7248287372220497784693cc27dd2e704bd7d155997d49c029dd07a319c0886035cd5ce739c372a20beb4c83a76673ae70915c72a5a0737b21c070984e0d0094b30270c6d55dc34522a2050020000000000000000000000000000000000000000000000000000000000002a205f6f02af29218292d21a69b64a794a7c0873b3e0f54611972863706e8cbdf3712a20c363e8e3531e960f39ecd40de1a29985e7f1473281f67553f1d42643ab61d7672a20149c1dd2231306fafe93aae46fc748b26d2dc3822e2e896f32f9073c3984a8f92a201a9bd5ad63f4a2da9efcd077e67323dd41debd2f638650163251008af69d2d502a203eadd0b161343dc74bc3b8a8a3ca19af58505837886485ed68f9a77cb63406922a20953024c6ded67e542650258c58347cef640ac2bb254c6df6bc3af9bf3c1a1f7a32205cbed721eb34b16bb233472fcc69a60f9fa7b6ef995bef9183148012f8aa926b3a20303b72425f7fd40f18fa8199b6913bba1858356fe543432245a250e816eb22a93a203e9469a0c2885a4e8e6621b323f05c211f6aa6f13fb5cbabf94eb64d0ae8d5173a206e817161402150ae7a3c42df6d68062e41bf358f5966510d5be0b8c40188772d3a2031b38f95fa9f617a11a605bc2dcbe2b3c118fedefb271e5ba400a26cb5505c2342680a04ffffffff1260813f27f288ee634bfc215d1a8d82906e6cba0ebe0770e9ed45b6e48fd81f351a0d1e5c9be9c14b159da2fa93ad2afcf2157f1aeafabf8ecc138c31c260621deef8dc79ed74f86a3911558e33386fb52cc3bf3ba5286bbebee8c204fae8f0e2154891251ac5040a20f6627686f931982aebc4702c2490e8ef45fdf3c0bca63da533fb6da8d8cb5ab5122056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4211220b0d658ec171d83afba0347ea65e6af5bae452e53321328c39a6731fdb60cc4c812208e4b54f1db5d51d26ab71a045f150b08f4267ae9f2618b96b4c62eb65f3f8392122086768f0b1d5fc4b178f5494360a551fb930951fdda21db8ac2d42227ba0bc4591220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c1880252220005125020000000000000000000000000000000000000000000000000000000022205c47e85c55d09f8a3951d83579bf0647644629f9575140e580d733fbf9b1fcc2222035702c52f06f5df0af898572adb1ff40b9f51b7d41ac72071e39ea3d7c363a4d222086768f0b1d5fc4b178f5494360a551fb930951fdda21db8ac2d42227ba0bc4592220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c2a20898d0903232a0984edcbf6d3860c93800a137715084fc9388be9bc004d88493432207ffe241ea60187fdb0187bfa22de35d1f9bed7ab061d9401fd47e34a54fbede132207d00409ac38e3a99bc86c045f570dea66e115ba1d767d89c9e7f82901dfcfd883220a315945caef8ad30a149b2947b65d1caa2b2176fbadf4de16b04563118bf5b6e32200b54955aba5ecb0d9d4484bfb65f8f9d183577578aedc0fe06193980c72242223220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c20e5fdd1c106").to_vec(),
            cons_slot: 4672,
            cons_l1_current_sync_committee: PublicKey::try_from(hex!("90db4f4535b735792b28e650d4b5bda8d33235ffef377c5cee554cd2190dd3986bfa561666f3f457bc91b5afccc39438").to_vec()).unwrap(),
            cons_l1_next_sync_committee: PublicKey::try_from(hex!("8582bbad3f9eee79addd939370c7241ee96d425c6a5d6e7fb89e59ad117c38e62064e56821b77b26353be13b86d6a66c").to_vec()).unwrap(),
            cons_l1_timestamp: Time::from_unix_timestamp(1748270437, 0).unwrap(),
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
                .verify(1748319096, &l1_config, &cons_state)
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
