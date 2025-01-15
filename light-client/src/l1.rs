use crate::consensus_state::ConsensusState;
use crate::errors::Error;
use alloc::string::ToString;
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

#[cfg(test)]
mod tests {
    use crate::consensus_state::ConsensusState;
    use crate::l1::{L1Config, L1Header};
    use alloc::vec;
    use alloc::vec::Vec;
    use alloy_primitives::{hex, B256};
    use ethereum_ibc::consensus::beacon::Root;
    use ethereum_ibc::consensus::bls::PublicKey;
    use ethereum_ibc::consensus::compute::hash_tree_root;
    use ethereum_ibc::consensus::merkle::is_valid_normalized_merkle_branch;
    use ethereum_ibc::consensus::types::H256;
    use light_client::types::Time;
    use optimism_ibc_proto::ibc::lightclients::optimism::v1::L1Config as RawL1Config;
    use optimism_ibc_proto::ibc::lightclients::optimism::v1::L1Header as RawL1Header;
    use prost::Message;

    #[test]
    pub fn test_l1_header_verify_success_same_period() {
        // created by optimism-ibc-relay-prover
        let raw_l1_config = hex!("0a20acac7566fdf384a1ada45c01dcf9030d7eb0e1e5f5302659101d0b2a5bb59092100118dba594bc0622580a0400000001120e0a04010000011a0608691036183712140a04020000011a0c08691036183720192812301612140a04030000011a0c08691036183720192812301612140a04040000011a0c086910361837201928223026280630083808420408021003").to_vec();
        let raw_l1_config = RawL1Config::decode(&*raw_l1_config).unwrap();
        let l1_config = L1Config::try_from(raw_l1_config).unwrap();

        let raw_l1_header = hex!("0af90c0a02100112f20c0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b123082c0c49d5142e3f5a7340864440c61787b6741271e4ce2a21114f137a693fc4484582aee2ebbb9c6d9f9ebdae7ff73f712bb050a6b08a00a10021a20f4dd3e62f948770a05280af892d4dc16da9b3dca76cc725b0561b5de9836efbb22207126c1f8a003ac623b0a6e8fd923140853e82d1b4948a5ae229cd7a812dfb21f2a20ad732cedceb10421ee46680407861d117981568188a91253092b6de20ebd3476226908900a1a2093b59162c0dc0cbf71c2ae6bb31bf6f366d0b9d56a449e7f42df4514f7cf19b22220f7b08a7e75097ab2a0d615720d84894096726b71d1253ad2312e797e532e94642a20a23ecf5342d3cfa4722100778d466942e3825e920b3d184991d400135838b5292a20a2000000000000000000000000000000000000000000000000000000000000002a2086220a2d72000ffb901cf75bf2918181ffea3c6567a573566d8c826e9e5674932a2038411fa552e13868331e2f3419317213de0cb8acab5dea2e4e41f73667d24f792a203b0b390f17f9b1c9dc3512ba2e5840c3e0ffc94af0da3ccbeef5c5bd0a7384be2a20434306737334c65e8ec2051c6dcb20cfb570927322c5d81a51f0577bf84ad35e2a20fbaa3f1a4ea39ad95174320443a4103385d85f9c533aa41a330abcfb05e01c2c3220d86025956a37fa77a90db8d1495c3bf85673b6668c2af0ecca9147bd41ae6cd13a200c16951c16ee5128dd9fcc8ab79d3c847d63458c319492a22a3815d1d39debd23a206c6dd63656639d153a2e86a9cab291e7a26e957ad635fec872d2836e92340c233a20db56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d713a20fca76b89e862c06949196f7f06fe54554d44301e756aad371863a616e99625f842680a04ffffffff1260b6ef9dde767dc446c4faf4d9c52adcf3052ddfff06687d9c78d3b372447d1279d3f56cd9c5f13e72239fe95f8fdb0fb11078dc93f719318d942ce0c6b89839960154e497ebbbeaa61f2c69d21e00026e93f9687e7d39aff9068d72d8c85b4ba748a10a1af9020a2058fd4c8a5ddb802fc96d150aa2ae07d0b7cad4cdba820c240ef38f8923da59a9122056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4211220a60420223ca8129366350c3d4cdaccfaa314c8dd0cf55572258ce28d5ceb5d0f12202780143178c43a9733c07d9e6d8c4340a6613fda9418c216cef31fc1fa4496be122067401a1b3a359db899824f9723ae1cf56c5348dc96f76ceaa65029444c37a13f1220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c18900a222080c3c901000000000000000000000000000000000000000000000000000000002220f913bb7829c14b3c9028b1cf2121157e318db60572bb3dbcde8a62d7086712fc2220ae57fc10842a14fad3254378873d41231f7609bbaa707886a25060529104968f222067401a1b3a359db899824f9723ae1cf56c5348dc96f76ceaa65029444c37a13f2220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c").to_vec();
        let raw_l1_header = RawL1Header::decode(&*raw_l1_header).unwrap();
        let l1_header = L1Header::<
            { ethereum_ibc::consensus::preset::minimal::PRESET.SYNC_COMMITTEE_SIZE },
        >::try_from(raw_l1_header.clone())
        .unwrap();
        let cons_state = ConsensusState {
            storage_root: Root::default(),
            timestamp: Time::unix_epoch(),
            output_root: B256::default(),
            hash: B256::default(),
            l1_slot: 1295.into(),
            l1_current_sync_committee: PublicKey::try_from(hex!("82c0c49d5142e3f5a7340864440c61787b6741271e4ce2a21114f137a693fc4484582aee2ebbb9c6d9f9ebdae7ff73f7").to_vec()).unwrap(),
            l1_next_sync_committee: PublicKey::default()
        };
        let (slot, l1_current_sync_committee, l1_next_sync_committee) = l1_header
            .verify(1736948358, &l1_config, &cons_state)
            .unwrap();
        // same period : cons_state period == finalized_period
        assert_eq!(slot, l1_header.consensus_update.finalized_header.0.slot);
        assert_eq!(
            l1_current_sync_committee,
            cons_state.l1_current_sync_committee
        );
        assert_eq!(l1_next_sync_committee, cons_state.l1_next_sync_committee);

        // TODO should be verified in ethereum-ibc
        is_valid_normalized_merkle_branch(
            hash_tree_root(H256::from(hex!("dab7e7fafbe915878971f8dc8a098cba0b83d1eb02fdaafe2e6188ec82aa0604"))).unwrap(),
            &vec![
                H256::from(hex!("7ffe241ea60187fdb0187bfa22de35d1f9bed7ab061d9401fd47e34a54fbede1")),
                H256::from(hex!("7d00409ac38e3a99bc86c045f570dea66e115ba1d767d89c9e7f82901dfcfd88")),
                H256::from(hex!("fb347fd2bad912dfd45cea481ab8f18b68105ed6a652845d5ae3c8aeeb5850fa")),
                H256::from(hex!("63bb8fe39e2c76c6be51edfc2d3a0a0979903ce76878abeac9c2b009c9db905f")),
                H256::from(hex!("536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c")),
            ],
            44, //deneb fork
            l1_header.consensus_update.finalized_execution_root,
        ).unwrap()
    }

    struct TestCase {
        raw_l1_header: Vec<u8>,
        cons_slot: u64,
        cons_l1_current_sync_committee: PublicKey,
        cons_l1_next_sync_committee: PublicKey,
    }
    #[test]
    pub fn test_l1_header_verify_success_multi_period() {
        // created by optimism-ibc-relay-prover
        let raw_l1_config = hex!("0a20acac7566fdf384a1ada45c01dcf9030d7eb0e1e5f5302659101d0b2a5bb59092100118dba594bc0622580a0400000001120e0a04010000011a0608691036183712140a04020000011a0c08691036183720192812301612140a04030000011a0c08691036183720192812301612140a04040000011a0c086910361837201928223026280630083808420408021003").to_vec();
        let raw_l1_config = RawL1Config::decode(&*raw_l1_config).unwrap();
        let l1_config = L1Config::try_from(raw_l1_config).unwrap();

        let cases = vec![TestCase {
            raw_l1_header: hex!("0afb0c0a02100112f20c0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e123082c0c49d5142e3f5a7340864440c61787b6741271e4ce2a21114f137a693fc4484582aee2ebbb9c6d9f9ebdae7ff73f7180112dc130a6b08d00210021a2005a5424149abe61b6fdd4d6df7647a1881c25f7b36dd0b61cc21c8d1c08ed42522207bab4a9b88a93ac147a0b0c3ba22e37124060b4e00cf919c2c9afc7a6576caa72a20ea26b20bd4902798c555754f3f1a187b4d710a34c899c8c0862cc6a636a3974712f20c0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b123082c0c49d5142e3f5a7340864440c61787b6741271e4ce2a21114f137a693fc4484582aee2ebbb9c6d9f9ebdae7ff73f71a2070d228fb4a5adbd18ac57591ce5bc052bdb243d704a771209c0d745a91a04f6b1a203133567479b3b2854cb5098436de7cdc008ee117f0792d7e9b7495b6164120e41a20aa58e143f099df2208149c0e4f8363ecf2932578a269480e618f6d5bd22ddbe01a20d8a10e73b80a3c2e2ee24581967bc1e1b2711dab898ce91732c3b6576800f0df1a2082d18e362daab9e8de31dfedae3adff7314fea2fcabcda17d69529bad1689ef7226b08c00210021a2072288c739459386c86a8c53b36ad6c50a43633b623e2ffe3289e224f78da85392220fdaf4bc544d1d9846b8a349bf9096b1cc583eb44266152ee4c742af06664c3612a2087e89b6433141dcdd75b8b7209eae24118a27a43a4e1e35dc559ee35abebdc392a2028000000000000000000000000000000000000000000000000000000000000002a2086220a2d72000ffb901cf75bf2918181ffea3c6567a573566d8c826e9e5674932a208c8fa1c1fec22f21cb869eda077eb82a2fb543b28781ffe878a62b78019d8c882a20aa58e143f099df2208149c0e4f8363ecf2932578a269480e618f6d5bd22ddbe02a20d8a10e73b80a3c2e2ee24581967bc1e1b2711dab898ce91732c3b6576800f0df2a2082d18e362daab9e8de31dfedae3adff7314fea2fcabcda17d69529bad1689ef732201d8e176a7308db13ed13028bc6a9f9507e519ca2f7e46338f1333ad94033d9413a20c063436e050f8191dad5d2c7821a329d09fe6fe64cdb392fd883c9628ca9f7fe3a206c6dd63656639d153a2e86a9cab291e7a26e957ad635fec872d2836e92340c233a20db56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d713a20cc52dc3d2242cf71cd98332ba201ab1988f7c9914f221320bec1a50607d1b8e842680a04ffffffff126097044c20ee19b413635b53442d9bc62239fd51c2bf4113f311b6ca9a21d4cea171ca6b57bff4a9493cf4e64eaeb537ac0f71e503fe107a5a4d457947220c04b8f39af753647289419f42e7949f1213840b8cf830afbdc88566d4e4c04968130a48d1021af9020a2058fd4c8a5ddb802fc96d150aa2ae07d0b7cad4cdba820c240ef38f8923da59a9122056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4211220136e7521e06af931169509f4d17c51884d18d6b77e88ba63b12d84f7b27e5cff12208a0ac0bbd625dd44d8ade5a7694c7a2d3dc407e9e59d9a4784cf389bd45aa77112200153f44446d8b0efd5ef5fa7fcb664e09ef3003b55fb9d902664d558c48518001220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c18c002222090f47c03000000000000000000000000000000000000000000000000000000002220da3c5ff59d67af3f2053bc6f4efebe7280ae44d937a2932cc0f7b45680d9321822208780da91335d1a4d6d5251253b94a9beb344dd4cb086908db1160f8c5ac49f1c22200153f44446d8b0efd5ef5fa7fcb664e09ef3003b55fb9d902664d558c48518002220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c").to_vec(),
            cons_slot: 313,
            cons_l1_current_sync_committee: PublicKey::default(),
            cons_l1_next_sync_committee: PublicKey::try_from(hex!("82c0c49d5142e3f5a7340864440c61787b6741271e4ce2a21114f137a693fc4484582aee2ebbb9c6d9f9ebdae7ff73f7").to_vec()).unwrap(),
        },TestCase {
            raw_l1_header: hex!("0afb0c0a02100112f20c0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b123082c0c49d5142e3f5a7340864440c61787b6741271e4ce2a21114f137a693fc4484582aee2ebbb9c6d9f9ebdae7ff73f7180112dc130a6b08900310031a208122dc0d7e6d72895c941971c0d64022e7bc99693e80176b9a50c52ac28f7a03222040e1ef4b1d774dadf9cc40e7d7793edd976b8fa7f04f525b55d7e70a2357c1752a20503c6bbfc246ce6404d7c9ebd3e3ac8b52f6e8c3bc5bc1a8d72499ef7f6542dd12f20c0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b123082c0c49d5142e3f5a7340864440c61787b6741271e4ce2a21114f137a693fc4484582aee2ebbb9c6d9f9ebdae7ff73f71a20ff94b0f1d6f6309d2572b59e2e13643673962f5ac255c3c5dabc9f07e909f0d51a20b4922da389273fca09786bf4ab6e81b03d21b3c24a5eea9aa9a5889731ea845e1a20fd2010306d1b28c20922b75f70904f016f6fbfda3170748086a8417bea4395f31a20ab6a8db8a026f3348909d7ff90883a7e787616f5fcaa59b847f51fd9e766ec401a209494541e8abe146b01833ede4e4f0736f2a7b251f989fc60c32b09ff9c905f8f226b08800310021a209b86082f638d3aa217124755d4d3c0bc7ac92a9e3460595c735e69fdbea7e5be22207cd6a82883cc75e9598b7d8e0b167fa935ccfc38b213c541f336b23ffe9c4ef82a206f5d87da4efbf5b4b55c95307d498586448e035814531cc1d82613c4b02941882a2030000000000000000000000000000000000000000000000000000000000000002a2086220a2d72000ffb901cf75bf2918181ffea3c6567a573566d8c826e9e5674932a20cada9b1dac0806d6e8d891f2ab5ee3b28ab1a8765194dd9e82a7bf2347c91abd2a20fd2010306d1b28c20922b75f70904f016f6fbfda3170748086a8417bea4395f32a20ab6a8db8a026f3348909d7ff90883a7e787616f5fcaa59b847f51fd9e766ec402a209494541e8abe146b01833ede4e4f0736f2a7b251f989fc60c32b09ff9c905f8f32204fd25d58c1472d5c135b66b623c18bf11fafbd1808f59a4b6d0dbb60b8e7ef583a20ce87a658fa6c7577940ff30e2ca4d98cfc5019649ae474932caf9fd2e264eb6d3a206c6dd63656639d153a2e86a9cab291e7a26e957ad635fec872d2836e92340c233a20db56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d713a2014253a99442085cd1f1b30ff2b65b562c28820a395be0d9abca9d9c2d69f468a42680a04ffffffff12608bd95f92b2e805b51e73392b6f252ae81d475fcfcdef9b6cccdac83e309602eb236c9ee1f8b147bb9c50e889843526c81469fc6d1c1b1c4ae8496d6f5f3df7e180b3bc050d888e5ff9358e5eeaa9334cc49dbb6c88f28c19a1aadfd46bdb83064891031af9020a2058fd4c8a5ddb802fc96d150aa2ae07d0b7cad4cdba820c240ef38f8923da59a9122056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4211220748680f5fc66ba2ed31927a0307ac197c253e99a7283427676ba64369dad76a71220b54093b672c6a7bacd6a96ec621738968e66a20fb03b9f45950cbfcb8fc6e5a0122030414f97c05d413e21d2ed4f46f687d43aa168c1834e6f8aa9ac78959345e8c71220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c188003222067d44603000000000000000000000000000000000000000000000000000000002220da65e920b3999323f09453b7418fa59635ae45427eb9b2f1b2d3bf232e23cc722220ea302e49138fa122464758d707a74f00d5fa87b6964822adc318eefdf3917b73222030414f97c05d413e21d2ed4f46f687d43aa168c1834e6f8aa9ac78959345e8c72220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c").to_vec(),
            cons_slot: 320,
            cons_l1_current_sync_committee: PublicKey::try_from(hex!("82c0c49d5142e3f5a7340864440c61787b6741271e4ce2a21114f137a693fc4484582aee2ebbb9c6d9f9ebdae7ff73f7").to_vec()).unwrap(),
            cons_l1_next_sync_committee: PublicKey::try_from(hex!("82c0c49d5142e3f5a7340864440c61787b6741271e4ce2a21114f137a693fc4484582aee2ebbb9c6d9f9ebdae7ff73f7").to_vec()).unwrap(),
        }, TestCase {
            raw_l1_header: hex!("0afb0c0a02100112f20c0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b123082c0c49d5142e3f5a7340864440c61787b6741271e4ce2a21114f137a693fc4484582aee2ebbb9c6d9f9ebdae7ff73f7180112dc130a6b08d00310021a202677148e80f8d069981604b663c8ce5765cf79a298f73ffb8691af2f0bebd8c32220ac8fbc3ea0987ae3379cb9d15f7de45d96ad5705ee65ef1256554027d88129702a2081b7b844973f9ecc5296fc28db478143a0d85c6dd56967257c6b611eb0e7d1a112f20c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b123082c0c49d5142e3f5a7340864440c61787b6741271e4ce2a21114f137a693fc4484582aee2ebbb9c6d9f9ebdae7ff73f71a20c713c04d75b73ee182f71471d47a772cf33b0d253812768739ba366c1df7c29d1a2002dcbac2bc608bc65d0fdc87aadd3484a24cd6eaa398cd54e0d36f733f243d431a205d3787c761ce430b78fe3654c8373e74319ddbcfe9f9e79a21cbc8b08d5507201a20e8b2822cfab3078e960b1fd86a1f5ab151af1cb9df42439cabf6aa979446737f1a20228030fc33cf23bc67327050c6b7f73b07900acd11c6537afefff74cb54cb27c226b08c00310011a20006af4228d51ce04cfe02caf49fc65217df1c9d6ee2b854a463194dc3af4b6362220df92a13c634634394b732f7ca46561c76918de542e2607b654ad4ed5f4243c972a20f45fb2b6b6ffd102cb1f782ade54dddf7899108f593701168a3768b1ab3f2f202a2038000000000000000000000000000000000000000000000000000000000000002a2086220a2d72000ffb901cf75bf2918181ffea3c6567a573566d8c826e9e5674932a202f754a25129813e7ad3c40cbfde800d39cd30ce49f3a8a1bbfd2fc2575aaac6a2a205d3787c761ce430b78fe3654c8373e74319ddbcfe9f9e79a21cbc8b08d5507202a20e8b2822cfab3078e960b1fd86a1f5ab151af1cb9df42439cabf6aa979446737f2a20228030fc33cf23bc67327050c6b7f73b07900acd11c6537afefff74cb54cb27c32201feb712342763cf4f1c9e6c881024db03bcc617129c52db7a82673d093c817233a20c843eeb061d0cc0d8f67a829c3faf2765b5ee135bcce8edc46531539b31ce60a3a206c6dd63656639d153a2e86a9cab291e7a26e957ad635fec872d2836e92340c233a20db56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d713a2008617f2d662191a3e3c8f73f13ac43f1be0325dd6094008a965d2fc4d263244642680a04ffffffff126080dd84ad1b06d6b483377413a7089367da8ac262e0f3d631c11d890726a84792154cec7d0a5875c33b2778b7e594483f072d64639f624719893abfdb762729423fc81eadecbd647b22dbe382fa42f91935335a60d210d55c01e9213410b5e62548d1031af9020a2058fd4c8a5ddb802fc96d150aa2ae07d0b7cad4cdba820c240ef38f8923da59a9122056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4211220be793342786095d4d5c5cc473ab192561d475fe9920310098e9f63bf6c61686e12204726964a4e86c01e61ddc4297ae0cb95e7bef7e5f2482d74453691e8e1df221c122006af791496f244dfbfa21e4c6bc23bb919ccc2fd43b0e4c163e4fcd5788c74a51220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c18c003222024fc1303000000000000000000000000000000000000000000000000000000002220f2fccfd9f03664174179dc0ca8a5ebb3ec7ce5601a06050e56bf9aa61341ea2122200ff9a6793471630044620f3186686a137f4f3a4f49e301bf9038b5b96b7eba88222006af791496f244dfbfa21e4c6bc23bb919ccc2fd43b0e4c163e4fcd5788c74a52220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c").to_vec(),
            cons_slot: 384,
            cons_l1_current_sync_committee: PublicKey::try_from(hex!("82c0c49d5142e3f5a7340864440c61787b6741271e4ce2a21114f137a693fc4484582aee2ebbb9c6d9f9ebdae7ff73f7").to_vec()).unwrap(),
            cons_l1_next_sync_committee: PublicKey::try_from(hex!("82c0c49d5142e3f5a7340864440c61787b6741271e4ce2a21114f137a693fc4484582aee2ebbb9c6d9f9ebdae7ff73f7").to_vec()).unwrap(),
        },TestCase {
            raw_l1_header: hex!("0af90c0a02100112f20c0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b0a30a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c0a30a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b0a3088c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e0a30b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b123082c0c49d5142e3f5a7340864440c61787b6741271e4ce2a21114f137a693fc4484582aee2ebbb9c6d9f9ebdae7ff73f712bd050a6b08f80310031a202a99699c244e2198a1fc91cba7f2ea770836ae3d73c5e7691169d11fdd326c6f2220e8acbce5b7005d4936e690a20ba49236c34ee7af77afb7cc00b53c10c3bb22c22a2001c42f580908a9b3ae6fb5ee83e18659e002ab9d8e25b5eb01438fe2ffe2e012226b08e80310021a20697c64959b4bf419283225d3f5b9f940cc0875864e1f32509fa57b90e12672ea2220097411c6d00789332ba143c5824361a2c0e377ea90e6956cd29e96c2fea1b2392a20f70854737cdd92e30bfca8870c24641b435ca6bc091c95eeb40abf4880b509ec2a203d000000000000000000000000000000000000000000000000000000000000002a2086220a2d72000ffb901cf75bf2918181ffea3c6567a573566d8c826e9e5674932a202f754a25129813e7ad3c40cbfde800d39cd30ce49f3a8a1bbfd2fc2575aaac6a2a20ae9db59878f86b3e75b0224f27f7e39530ec1e7a02e22356b20465a6011fe1012a20c917891ea44f97380cbc94177f626795d42f6e408481beaa395e8d6f2e44e93d2a2095132058d8cc4afb36502a797263a0ab1aab3c230123580a61c000bd5d65c93d3220b5f74fd99ef412aa1f42018a1dfe884d8429b5c58d96831c2ad1cbb64c3d55aa3a20c9cb2391a09d7927b631dc1fa7836ec4ed6eab5d819c5f5b9d142883848478163a206c6dd63656639d153a2e86a9cab291e7a26e957ad635fec872d2836e92340c233a20db56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d713a20b9175232e50a3ffbd686cd181d0b3a9489d10f038937dab06ee8700f07fba18942680a04ffffffff1260b16fa82552cb12f1567b410c3bb8abcf604397dd4249a487fab99b054f3ee7162bd03ef797bc76606bb924848202e83e15576cf17b9dd0d1b49f89e3b3602796915174d0f7466db9fe9e3dcfa8fde35494081006187db5f1563d108e9fd120fd48f9031af9020a2058fd4c8a5ddb802fc96d150aa2ae07d0b7cad4cdba820c240ef38f8923da59a9122056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421122020858bc174b3d30a9d783077832a1927c12f83fa92496bf041ccfb9f5a2feeaa1220d720a0a53035f39ed05cf054d2b8010a853893a67b136fa3aacf599d467bf2481220d993f5b945cec7ca2cb0f9a2e03250dc4b347aa0fd456e5c13030c37c53e03461220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c18e8032220bac8f502000000000000000000000000000000000000000000000000000000002220ff72aded29317e91dd7ae8de427f9a7d7a1dd46593e9929592da94c771e43ed92220428a062b0403f15d0d3a439a6d8e5c46bcbbdd4607ba679582f714ee4d3feff72220d993f5b945cec7ca2cb0f9a2e03250dc4b347aa0fd456e5c13030c37c53e03462220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c").to_vec(),
            cons_slot: 448,
            cons_l1_current_sync_committee: PublicKey::try_from(hex!("82c0c49d5142e3f5a7340864440c61787b6741271e4ce2a21114f137a693fc4484582aee2ebbb9c6d9f9ebdae7ff73f7").to_vec()).unwrap(),
            cons_l1_next_sync_committee: PublicKey::try_from(hex!("82c0c49d5142e3f5a7340864440c61787b6741271e4ce2a21114f137a693fc4484582aee2ebbb9c6d9f9ebdae7ff73f7").to_vec()).unwrap(),
        }];

        for (i, case) in cases.iter().enumerate() {
            let raw_l1_header = RawL1Header::decode(&*case.raw_l1_header.to_vec()).unwrap();
            let l1_header = L1Header::<
                { ethereum_ibc::consensus::preset::minimal::PRESET.SYNC_COMMITTEE_SIZE },
            >::try_from(raw_l1_header.clone())
            .unwrap();
            let mut cons_state = ConsensusState {
                storage_root: Root::default(),
                timestamp: Time::unix_epoch(),
                output_root: B256::default(),
                hash: B256::default(),
                l1_slot: case.cons_slot.into(),
                l1_current_sync_committee: case.cons_l1_current_sync_committee.clone(),
                l1_next_sync_committee: case.cons_l1_next_sync_committee.clone(),
            };
            let (slot, l1_current_sync_committee, l1_next_sync_committee) = l1_header
                .verify(1736839576, &l1_config, &cons_state)
                .unwrap();
            assert_eq!(slot, l1_header.consensus_update.finalized_header.0.slot);
            if i == cases.len() - 1 {
                // last is same period( cons_state period == finalized_period )
                assert_eq!(
                    l1_current_sync_committee, cons_state.l1_current_sync_committee,
                    "result {i}"
                );
                assert_eq!(
                    l1_next_sync_committee, cons_state.l1_next_sync_committee,
                    "result {i}"
                );

                // Verify exactly same slot
                cons_state.l1_slot = slot;
                cons_state.l1_current_sync_committee = l1_current_sync_committee;
                cons_state.l1_next_sync_committee = l1_next_sync_committee;
                let result = l1_header
                    .verify(1736839576, &l1_config, &cons_state)
                    .unwrap();
                assert_eq!(
                    result,
                    (
                        cons_state.l1_slot,
                        cons_state.l1_current_sync_committee,
                        cons_state.l1_next_sync_committee
                    )
                );
            } else {
                assert_eq!(
                    l1_current_sync_committee, cons_state.l1_next_sync_committee,
                    "result {i}"
                );
                assert_eq!(
                    l1_next_sync_committee,
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
