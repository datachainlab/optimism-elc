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
    use alloc::vec;
    use core::ops::Add;
    use alloy_primitives::{hex, B256};
    use ethereum_ibc::consensus::beacon::{Epoch, Root, Slot};
    use ethereum_ibc::consensus::bls::PublicKey;
    use crate::l1::{L1Config, L1Header};
    use optimism_ibc_proto::ibc::lightclients::optimism::v1::L1Header as RawL1Header;
    use optimism_ibc_proto::ibc::lightclients::optimism::v1::L1Config as RawL1Config;
    use ethereum_ibc_proto::ibc::lightclients::ethereum::v1::{
        SyncCommittee,
        TrustedSyncCommittee as RawTrustedSyncCommittee};
    use ethereum_ibc_proto::ibc::lightclients::ethereum::v1::ConsensusUpdate as RawConsensusUpdate;
    use ethereum_ibc_proto::ibc::lightclients::ethereum::v1::ExecutionUpdate as RawExecutionUpdate;
    use light_client::types::Time;
    use prost::Message;
    use crate::consensus_state::ConsensusState;

    #[test]
    pub fn test_l1_header_verify_success() {
        // created by optimism-ibc-relay-prover
        let raw_l1_header = hex!("0af90c0a02100112f20c0a30aff9f2432d328bba781aa2a6bac512a225d2a528cbe83eeb542c3e51defa5e6c4681955f2a5300f23b98e86aa64fb7350a308ca1bccbe513b4503f8496b8468c42718972718feff4e3d5eec970f3c56ac0e2a8d4d59ad331db9cbea643ea775314bb0a308bf7c9c9972045c582b7363af44e93da26aef3c8fce81a0469d0c5f48199312f73953ce3c3547b91f543b5586a307c380a3099729eb9833e428853a7444653824aac579864675d6c69c1fc79423f4aba0d51153a40f31c1082816ddb0cdce31bc6b20a30a4662c910f9eda828898a0cddd61332aca5808be1efedb7aedae7978a0bc7f9d2a35baf97f913ca920c957c4e2b7a18c0a30b505fbc0beb4fef613b0720292aa7d74b59ee7ae38055f5b0358f26c52df26bfb1a0ac8d486f581e420cac39eaf18dda0a308df81a9e3c61ff1cba9f13c792f1c933131b6d155e8b552d673df44fad4530b68c4e86e9cd2e5cc93a3b806c6b00f4a60a309401d4c66e72e596e0072c27de5bcf3c99900011d36f01219b9e0dc54c852393378b4a0bd12084032c6f02de2dcf12960a30a1ae1d14d16cf61a6ae0c9589a19a8f38e161f02dbd98c9f5400fc63689af3af2c146bcfb46f0d94469502947d19d6df0a30a39882700ed7f72fcdbac07081b7c0c912cb8647ed8494926e6c9c2fc1a7415c7c60e3afcc3d3278fe25b50b851c3ad50a30b154fd14f7e9c617a1845078cc17f838621b4cfc1279eb11bd11afa4d913f0230cf81feda1f2b0f7bd7eb7a26d51cd280a30ae23fb1b0c76e4fd9800c18945094932655fa3a6aea990392c08c16e9816b3637b3818f609bf774e7277aa9901f1140a0a3089929f3a811cf44f70d60ccaa4571dff9371c73f60b70b7a50f2cf816861daeb14499b112890a200963d82d324c2ee8f0a30a125a3659c269801fb2e00c8f38d6b6fbe91a85dc99691db008cf325ef4ca7443c6fbc8a9131acf885d6169f859b8b1c0a30ae809a58eb62ac77b1a9c4b0ba4a3e3dc5024027de9f568cc91b66f1b7426feb4dfc61a5b8117c51c6a0c92f007a29ca0a3089931c9f649137fe9a6d59a455bcc695af861fa080fef0d598cc2ae66ed193939d12e72cf0a6f081ada36b4090f864cc0a30b4a484c89a1f85c32773f80e915a1441d7e83db65e06382f5eb7660eee9ebff358fc1aa72a1d5b0df058247cd1ba3c000a3087fa175dd34496aee3b88a482accaa19e271be98265981949c42769cd45b3d67afcc060167b2effc748ff15076b11b270a3085242431f0f8a0e939f2e469d6d35473e72a9577bf81a5ae16b345cddf1c50eecc5c7520b9580d9717c166a9835664fd0a3085bc68a8c76d4f706648059fa2d3b387c86ee65082e5fc16713794c6c0f8277d37c72783abe1c47ad3de97bd33ef66a30a308b49344506042460fc40f4a60d64079e86a29e87cffe29ebd8908fd1803ca21f53c0665145291ea5e34b30a01dca7cb50a30958979725c3497149c8f1ed2e3f073a56207ff17218ba3fef7fbcc6e07bbd7b8fc528ff646a49e9c1a145ed27017ef4d0a3091838562f203c048b60308d5dae4e845977b8bd946806886f91f23038df2759e9306efcb56f15d57498a68ee789bf5ce0a30b88c17f529454d0305f27188d32f1aea28a82881d32a1e30e7b01c9aa53b9a9ea01a3706852b4c97c9eaa42e670e93820a308efdefbccd6479b9953a5ec6416e6d48201865968567379b213040dbf0be7efa00d66343c21a7e801d6bfd7403cfcfa70a30847cddf22fe1483b2808f08bb98586deba65165fab87d7c60f8081af495c3d9ba234ce61150840ac28d8833f721b08d40a3088091d52b099523e2717d3a526f8a41a7ff20ca4e4b4d153ebafe6f9265e58f8aa45f1e415d598c758e684bcb376577b0a30980f54178ab1e2d21822e9cd7327acb170269e6215cc8151f5f9c74d3e9ed4fd8e2d5b03c0d5b187edf0b56b6d2fc2fc0a30a8b7eaa52875524b0b4716b56d2f377cb878ceb51b925c0a7fa4629f16b2a8161e28aed5c6446ff1889ab7473c86b6f30a30a77a318dd834183c3e3b3921c94b1dbb8d1bb2c619e0c492a592c2de5a91e73b5c054bba52619355ed34012386a7aa1d0a3099804a3e664ba9d8b0a91fdb6127f2753932e41c6f62d1c26edd5f81a12f0eb7bdc9df0d58121436cabd07261f2bcdbd0a3095419a10ad9771dc7545637bc14e4eb7938e0bcc57a42000ddbb117750570fb5ce290679d326a0783e6c780be23df6d8123093f8ab5c5e459920b9e1d7d0f7ed0ccec0abf4663c4f165cbbe9474286f730e8fa21a30b9e9e6c828472ae2db7d8ef9512c0050a6c08b4cc0310371a201661c8506131a1deb7a9a8ea621d7eeca9e31fbd27a0cad8e5227be97e84530422200295fe81f1d58008f7c7d63828d51f7649d9d23bc31f8c2dbe0c488c75e20c522a20902fcec3ad6f0a8c0de3850d41154303365df577e1c7a23abcb1ff4b1a1e48fc226c08a0cc0310331a20e3adfeb1bf6859fcb66f70060cac395e23bbb4c16d8ad7bd191538ff36f1bc8e22201a39f3c69febbb47ff516e754cc99b47215fd59c64a41b049902948faf367a102a20eb87f230aea7fc0fc2478d421610e5e378b56e4f28d26efd22fc6e9078906e962a20c41c0000000000000000000000000000000000000000000000000000000000002a20c26f8f6ca0086d685f241b1bcf453ff75db64cd1e567b1f9175b78afc5ebdf0a2a2093d011e58ac588ba211be7fe3c99900d5414410f08b0c6935d26e2514d1333052a207e354ea0e5a3f5670501a3c0ef8724012b1af8dc4d059aaed9344428efb6a2f32a20d099ec853a8436b15f75ec93d814798db830a3b7e34ca54f57c5b17774de66982a20a46fd821d4a0047f79e71acbbf921042fb59f9d2eb507e2ff94d0e2228123e1b3220da23258269bb416592080f1138ba65f647367c57ead9de6c898efa501f5b5cff3a20522d387c6919f52b485169d7c265f30c5a14f8ca3ac00d341df6eb4ecc898c153a2023c0509c484e6f765a62df758c65ff8c66719f229b5e518bdb130e382711bd8a3a20db56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d713a20662330803d5140383c6e0c517593d1f214a0238de7f0ee6121fc20e707940f7a42680a04ffffffff1260b36877765dda847b1d3df265ed0758884a773813a27da1729ee9711fac4d3ed1fdd618677bf2461f57bd5f3d8a4ee58a15df95441fb06adaf852f0e7fcf2ba871522081ce1daae6f6361c10dd6628592cec353879c7131459ceeaedc2c32a72148b5cc031afa020a20f8c3474b4b528f2bb6adbe2f8b463ad2131b146de9e59235f1f29a306dc7ef6712201b0f6708b9f6290dc5cb0068bf69c7886270511d88e85f06ee2bfcaa0619754912203eb39ed1bfbcffc7130eedef03e30a585435edc5eaa41cfe838693b60b73d00f1220b757f38a31272d40de8bbbba84f699a94cf39435580db2b2bc3c00ff0276236212201880ea722f7cc4c5cb3067691714227cc757fffff2a91e92aa7995cb6c4ba1971220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c18c7cf02222080c3c901000000000000000000000000000000000000000000000000000000002220fafd03e3f0f83f1500211c79d6f7ecde32fff6570b56d4f6be0a0e041e3928a1222014b6446caf81c673d101491fc0c79d886618e2480a9c8c4aa7f64b02e666e81a22201880ea722f7cc4c5cb3067691714227cc757fffff2a91e92aa7995cb6c4ba1972220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c").to_vec();
        let raw_l1_header = RawL1Header::decode(&*raw_l1_header).unwrap();
        let l1_header = L1Header::<{ethereum_ibc::consensus::preset::minimal::PRESET.SYNC_COMMITTEE_SIZE}>::try_from(raw_l1_header).unwrap();
        let raw_l1_config = hex!("0a2075da2cb5dbf4d891796935c9dedd02e1aae3a02c9416f97c008c499d87879136100118dae4f3bb0622580a0400000001120e0a04010000011a0608691036183712140a04020000011a0c08691036183720192812301612140a04030000011a0c08691036183720192812301612140a04040000011a0c086910361837201928223026280630083808420408021003").to_vec();
        let raw_l1_config= RawL1Config::decode(&*raw_l1_config).unwrap();
        let l1_config = L1Config::try_from(raw_l1_config).unwrap();

        let cons_state = ConsensusState {
            storage_root: Root::default(),
            timestamp: Time::unix_epoch(),
            output_root: B256::default(),
            hash: B256::default(),
            l1_slot: 58880.into(),
            l1_current_sync_committee: PublicKey::try_from(hex!("93f8ab5c5e459920b9e1d7d0f7ed0ccec0abf4663c4f165cbbe9474286f730e8fa21a30b9e9e6c828472ae2db7d8ef95").to_vec()).unwrap(),
            l1_next_sync_committee: PublicKey::try_from(hex!("a941be81b0a493b9ccff685d07f633d77fc7810d99d473a28eb21112889375a089a8cb88788d9c41d191001253ee2b46").to_vec()).unwrap(),
        };
        l1_header.verify(l1_config.genesis_time.add(86400_000).0, &l1_config, &cons_state).unwrap();
    }

}