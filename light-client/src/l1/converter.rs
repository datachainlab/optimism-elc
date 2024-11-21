/// Same as ethereum-elc

use alloc::vec::Vec;
use ethereum_ibc::consensus::beacon::BeaconBlockHeader;
use ethereum_ibc::consensus::bls::{PublicKey, Signature};
use ethereum_ibc::consensus::sync_protocol::{SyncAggregate, SyncCommittee, EXECUTION_PAYLOAD_DEPTH};
use ethereum_ibc::consensus::types::H256;
use ethereum_ibc::update::{ConsensusUpdateInfo, ExecutionUpdateInfo, LightClientUpdate};
use crate::errors::Error;
use optimism_ibc_proto::ibc::lightclients::ethereum::v1::{
    BeaconBlockHeader as ProtoBeaconBlockHeader,
    LightClientUpdate as ProtoLightClientUpdate,
    ExecutionUpdate as ProtoExecutionUpdate,
    SyncAggregate as ProtoSyncAggregate,
};
use ssz_rs::{Bitvector, Deserialize, Vector};

pub(crate) fn convert_proto_to_header(
    header: &ProtoBeaconBlockHeader,
) -> Result<BeaconBlockHeader, ethereum_ibc::errors::Error> {
    Ok(BeaconBlockHeader {
        slot: header.slot.into(),
        proposer_index: header.proposer_index.into(),
        parent_root: H256::from_slice(&header.parent_root),
        state_root: H256::from_slice(&header.state_root),
        body_root: H256::from_slice(&header.body_root),
    })
}

pub(crate) fn convert_proto_to_execution_update(
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
    }
}

pub(crate) fn convert_proto_sync_aggregate<const SYNC_COMMITTEE_SIZE: usize>(
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
        sync_committee_signature: Signature::try_from(sync_aggregate.sync_committee_signature)?,
    })
}

pub(crate) fn convert_proto_to_consensus_update<const SYNC_COMMITTEE_SIZE: usize>(
    consensus_update: ProtoLightClientUpdate,
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

    let light_client_update = LightClientUpdate {
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
                SyncCommittee {
                    pubkeys: Vector::<PublicKey, SYNC_COMMITTEE_SIZE>::from_iter(
                        consensus_update
                            .next_sync_committee
                            .clone()
                            .ok_or(Error::proto_missing("next_sync_committee"))?
                            .pubkeys
                            .into_iter()
                            .map(|pk| pk.try_into())
                            .collect::<Result<Vec<PublicKey>, _>>()?,
                    ),
                    aggregate_pubkey: PublicKey::try_from(
                        consensus_update
                            .next_sync_committee
                            .ok_or(Error::proto_missing("next_sync_committee"))?
                            .aggregate_pubkey,
                    )?,
                },
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
    };

    Ok(new_consensus_update(
        light_client_update,
        H256::from_slice(&consensus_update.finalized_execution_root),
        consensus_update
            .finalized_execution_branch
            .into_iter()
            .map(|n| H256::from_slice(&n))
            .collect(),
    ))
}

pub(crate) fn decode_branch<const N: usize>(bz: Vec<Vec<u8>>) -> [H256; N]
where
    [H256; N]: Default,
{
    let mut array: [H256; N] = Default::default();
    let v: Vec<H256> = bz.into_iter().map(|b| H256::from_slice(&b)).collect();
    array.clone_from_slice(v.as_slice());
    array
}

fn new_consensus_update<const SYNC_COMMITTEE_SIZE: usize>(
    light_client_update: LightClientUpdate<SYNC_COMMITTEE_SIZE>,
    finalized_execution_root: H256,
    finalized_execution_branch: Vec<H256>,
) -> ConsensusUpdateInfo<SYNC_COMMITTEE_SIZE> {
    let mut branch: [H256; EXECUTION_PAYLOAD_DEPTH] = Default::default();
    branch.clone_from_slice(&finalized_execution_branch);
    ConsensusUpdateInfo {
        light_client_update,
        finalized_execution_root,
        finalized_execution_branch: branch,
    }
}