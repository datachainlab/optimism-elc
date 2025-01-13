use alloc::string::ToString;
use crate::consensus_state::ConsensusState;
use crate::errors::Error;
use ethereum_ibc::consensus::beacon::{Epoch, Root, Slot};
use ethereum_ibc::consensus::bls::PublicKey;
use ethereum_ibc::consensus::compute::compute_sync_committee_period_at_slot;
use ethereum_ibc::consensus::context::ChainContext;
use ethereum_ibc::consensus::fork::ForkParameters;
use ethereum_ibc::consensus::sync_protocol::{SyncCommittee, SyncCommitteePeriod};
use ethereum_ibc::consensus::types::U64;
use ethereum_ibc::light_client_verifier::consensus::SyncProtocolVerifier;
use ethereum_ibc::light_client_verifier::context::{
    ChainConsensusVerificationContext, Fraction, LightClientContext,
};
use ethereum_ibc::light_client_verifier::errors::Error::IrrelevantConsensusUpdates;
use ethereum_ibc::light_client_verifier::state::LightClientStoreReader;
use ethereum_ibc::light_client_verifier::updates::ConsensusUpdate;
use ethereum_ibc::types::{
    convert_proto_to_consensus_update, convert_proto_to_execution_update, ConsensusUpdateInfo,
    ExecutionUpdateInfo, TrustedSyncCommittee,
};
use optimism_ibc_proto::ibc::lightclients::optimism::v1::L1Header as RawL1Header;
use serde::{Deserialize, Serialize};

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
        trusted_consensus_state: &ConsensusState,
    ) -> Result<(Slot, PublicKey, PublicKey), Error> {
        let ctx = l1_config.build_context(now);

        let l1_sync_committee = L1SyncCommittee::new(
            trusted_consensus_state,
            self.trusted_sync_committee.sync_committee.clone(),
            self.trusted_sync_committee.is_next,
        )?;
        L1Verifier::default().verify(
            &ctx,
            &l1_sync_committee,
            &self.consensus_update,
            &self.execution_update,
        )?;

        apply_updates(&ctx, trusted_consensus_state, &self.consensus_update)
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
        let consensus_update =
            convert_proto_to_consensus_update(consensus_update).map_err(Error::L1IBCError)?;
        let execution_update = convert_proto_to_execution_update(execution_update);
        let trusted_sync_committee = value
            .trusted_sync_committee
            .ok_or(Error::MissingTrustedSyncCommittee)?
            .try_into()
            .map_err(Error::L1IBCError)?;

        Ok(Self {
            trusted_sync_committee,
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
        consensus_state: &ConsensusState,
        sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
        is_next: bool,
    ) -> Result<Self, Error> {
        sync_committee.validate().map_err(Error::L1ConsensusError)?;
        if !is_next {
            return if sync_committee.aggregate_pubkey == consensus_state.l1_current_sync_committee {
                Ok(Self {
                    slot: consensus_state.l1_slot,
                    current_sync_committee: Some(sync_committee),
                    next_sync_committee: None,
                    ..Default::default()
                })
            } else {
                Err(Error::UnexpectedCurrentSyncCommitteeKeys(
                    sync_committee.aggregate_pubkey,
                    consensus_state.l1_current_sync_committee.clone(),
                ))
            };
        }

        if sync_committee.aggregate_pubkey == consensus_state.l1_next_sync_committee {
            Ok(Self {
                slot: consensus_state.l1_slot,
                current_sync_committee: None,
                next_sync_committee: Some(sync_committee),
                ..Default::default()
            })
        } else {
            Err(Error::UnexpectedNextSyncCommitteeKeys(
                sync_committee.aggregate_pubkey,
                consensus_state.l1_next_sync_committee.clone(),
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
        self.consensus_verifier
            .validate_updates(ctx, l1_sync_committee, consensus_update, execution_update)
            .map_err(Error::L1VerifyError)
    }
}

fn apply_updates<const SYNC_COMMITTEE_SIZE: usize, CC: ChainConsensusVerificationContext>(
    ctx: &CC,
    consensus_state: &ConsensusState,
    consensus_update: &ConsensusUpdateInfo<SYNC_COMMITTEE_SIZE>,
) -> Result<(Slot, PublicKey, PublicKey), Error> {
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
            update_finalized_slot,
            consensus_state.l1_current_sync_committee.clone(),
            consensus_state.l1_next_sync_committee.clone(),
        ))
    } else if store_period + 1 == update_finalized_period {
        // store_period + 1 == finalized_period == attested_period == signature_period
        // Why `finalized_period == attested_period == signature_period` here?
        // Because our store only have the current or next sync committee info, so the verified update's signature period must match the `store_period + 1` here.
        if let Some((update_next_sync_committee, _)) = &consensus_update.next_sync_committee {
            Ok((
                update_finalized_slot,
                consensus_state.l1_next_sync_committee.clone(),
                update_next_sync_committee.aggregate_pubkey.clone(),
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
    ) -> Result<(), ethereum_ibc::light_client_verifier::errors::Error> {
        if self.slot >= update.finalized_beacon_header().slot {
            Err(
                IrrelevantConsensusUpdates(
                    "finalized header slot is not greater than current slot".to_string(),
                ),
            )
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{hex, B256};
    use ethereum_ibc::consensus::beacon::{Root};
    use ethereum_ibc::consensus::bls::PublicKey;
    use crate::l1::{L1Config, L1Header};
    use optimism_ibc_proto::ibc::lightclients::optimism::v1::L1Header as RawL1Header;
    use optimism_ibc_proto::ibc::lightclients::optimism::v1::L1Config as RawL1Config;
    use light_client::types::Time;
    use prost::Message;
    use crate::consensus_state::ConsensusState;

    #[test]
    pub fn test_l1_header_verify_success() {
        // created by optimism-ibc-relay-prover
        let raw_l1_config = hex!("0a20acac7566fdf384a1ada45c01dcf9030d7eb0e1e5f5302659101d0b2a5bb59092100118dba594bc0622580a0400000001120e0a04010000011a0608691036183712140a04020000011a0c08691036183720192812301612140a04030000011a0c08691036183720192812301612140a04040000011a0c086910361837201928223026280630083808420408021003").to_vec();
        let raw_l1_config= RawL1Config::decode(&*raw_l1_config).unwrap();
        let l1_config = L1Config::try_from(raw_l1_config).unwrap();

        let raw_l1_header = hex!("0af90c0a02100112f20c0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e123082c0c49d5142e3f5a7340864440c61787b6741271e4ce2a21114f137a693fc4484582aee2ebbb9c6d9f9ebdae7ff73f712bd050a6b08e00210031a205be16d9c18f95729da3cdc7901bdf10375f948f2223a86e43ee553929c2358c3222044674b15a63d0cdc582bcecf64d2f5ec19af5384acc760fa118921c34cbe2bb32a20ccd2a4737648811b777d1df1780fdabc02633cb0d2a681c3383fff60c7485c5f226b08d00210021a201938cf83d1aadeb6b972f5ab2fdeec168e7809e6c6bdc4e2ddbeac0c700f2b0c222053ea25f333f9ea6cffaad264e9470cb36f23cf3bd22ec79618edf3b85d75e4432a20ad86688eef19d5784a46536540fe8225d92de9fd85d1be2544ca60e43ec6861a2a202a000000000000000000000000000000000000000000000000000000000000002a2086220a2d72000ffb901cf75bf2918181ffea3c6567a573566d8c826e9e5674932a208c8fa1c1fec22f21cb869eda077eb82a2fb543b28781ffe878a62b78019d8c882a20e03614d354746aae27b9a2a6c3e9f85395c071ee4c1c2884793bac88f8ee24392a2083dcb0e464567dcb5bda288d5d8e38259d3b4e0c2d7844e3f947cc114ab2cce22a2066ab132cd57b2d0fc9fb4094acf4d8ab7b4f7bc08ee0da249fa9ba2ddc30c6813220116ec6f817a13d896693a65024c9533f78321f4d1e49e12e178a0f55730ffb2a3a20184d0e8d1c1cf5182937c63d447fb54059bc8c0e929cf9554e24ce6f76117f033a206c6dd63656639d153a2e86a9cab291e7a26e957ad635fec872d2836e92340c233a20db56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d713a209be50e7dc941f1481f5d0f46caaf6c2e1bbb9ea0837aa5243dfbc2bc4d2eb16c42680a04ffffffff1260811204b06dcf53cba20298e3c54afddcbc611a7f8e44c1c068d471f97913f097bf04b439fd740d3c9ae8084c2333a68401b4f474fad8864de6d8afe0d418030d7d85c7289ab56472945fddad559bd492d9f9739d07b0ce30867f351db1eaa44548e1021af9020a2058fd4c8a5ddb802fc96d150aa2ae07d0b7cad4cdba820c240ef38f8923da59a9122056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4211220042663a54f7944371912e6f9df320277200199f40940282072f178b25c2142ff1220c0dfa52f328ef771efde38d1f52bd1e3c63cec9d5c3ae89ce6abfdbe83b5eb351220fd85633d5dcca5a40d19a890f0e71ad5e22efa738861b07c70adae1f9a10c6cf1220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c18d0022220e01a6f03000000000000000000000000000000000000000000000000000000002220c4d8d5de4956f4352e51959f912752775b017968a698acc57d925e09b5911e152220ac1bb5686e221a7339e74b3f1c37b17aefa319b136ba3ca5742aee4e611c82562220fd85633d5dcca5a40d19a890f0e71ad5e22efa738861b07c70adae1f9a10c6cf2220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c").to_vec();
        let raw_l1_header = RawL1Header::decode(&*raw_l1_header).unwrap();
        let l1_header = L1Header::<{ethereum_ibc::consensus::preset::minimal::PRESET.SYNC_COMMITTEE_SIZE}>::try_from(raw_l1_header.clone()).unwrap();
        let cons_state = ConsensusState {
            storage_root: Root::default(),
            timestamp: Time::unix_epoch(),
            output_root: B256::default(),
            hash: B256::default(),
            l1_slot: 335.into(),
            l1_current_sync_committee: PublicKey::try_from(hex!("82c0c49d5142e3f5a7340864440c61787b6741271e4ce2a21114f137a693fc4484582aee2ebbb9c6d9f9ebdae7ff73f7").to_vec()).unwrap(),
            l1_next_sync_committee: PublicKey::default()
        };
        l1_header.verify(1736776514, &l1_config, &cons_state).unwrap();
    }

}