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
        _update: &C,
    ) -> Result<(), ethereum_ibc::light_client_verifier::errors::Error> {
        unreachable!("ensure_relevant_update is not implemented for L1SyncCommittee");
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloy_primitives::hex;
    use ethereum_ibc::consensus::beacon::{Epoch, Root, Slot};
    use crate::l1::{L1Config, L1Header};
    use optimism_ibc_proto::ibc::lightclients::optimism::v1::L1Header as RawL1Header;
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
        let raw_l1 = hex!("0af90c0a02100112f20c0a30b35142bcfe0b34acd33d38a42af340f3d4c033a5ded38b7cb186ca368c011d39cf82f782d810c6941e541b8df90419400a30a1ae1d14d16cf61a6ae0c9589a19a8f38e161f02dbd98c9f5400fc63689af3af2c146bcfb46f0d94469502947d19d6df0a30a4662c910f9eda828898a0cddd61332aca5808be1efedb7aedae7978a0bc7f9d2a35baf97f913ca920c957c4e2b7a18c0a3085242431f0f8a0e939f2e469d6d35473e72a9577bf81a5ae16b345cddf1c50eecc5c7520b9580d9717c166a9835664fd0a30b178bccfd693edfb8d163a2050dfb251b2a4d5b4e4a7b3787354964159d9f4d0890a263601eeeff5c8a0663486b3fca80a3088091d52b099523e2717d3a526f8a41a7ff20ca4e4b4d153ebafe6f9265e58f8aa45f1e415d598c758e684bcb376577b0a3099729eb9833e428853a7444653824aac579864675d6c69c1fc79423f4aba0d51153a40f31c1082816ddb0cdce31bc6b20a30b0591fe44b7eba93e4f088344d0b924bbe3c7ed9bfb42bf0193ea020f2c7eb8a53c8ebcb0d0f929201c399230005f3e70a308f1e06e20ac5dd13518bd6c5e19c0a00a9dac968a13167087d9f8199bcb2e93fcb53199f2400ab2f398958761d7c33e60a30b5889b85291f380a80e2cdf02fc62edf4041ef1fb0810b01ebbaacf917c0d54f4bc1454c6772b91baf695652cc9c3f850a30b22df594adad3ae08c339d6e2079ec7b4c69cab5e8f5fb55680221ba40ffcd384844639a8775af10f3d02d10a5b18dab0a30b7f682183f898daaf1b98f9e946c1ad58818fcf19d1922e867b8d54549d5551d39de3bba0b7d919e82b97f8dedbad03e0a30a459e9ad0870b24aeb95d53b437014dc5dd97bbe38d78b51797da732e26e70e47ae97eb6d16ace2b7b21961fe9c279040a30a960c5230b2348f3121d891aeabb2d3598893f7d32c675b6a4ef40a1331fe4b9010150dffd379e3216b3dcf0edb232590a30ab0b0a68c9ab8ef73338f8ee1bce7bdfb4fdd1020b4163bec31b952651141db4c8db7fc4b0c97cb8645ad2a58344c1c80a30961d5cb5deed3612dfbbbffccada34d5a940bcb9b8002452be08d3d69e69274a98854b140744d2640da797cbe910b1cd0a3099804a3e664ba9d8b0a91fdb6127f2753932e41c6f62d1c26edd5f81a12f0eb7bdc9df0d58121436cabd07261f2bcdbd0a30aff9f2432d328bba781aa2a6bac512a225d2a528cbe83eeb542c3e51defa5e6c4681955f2a5300f23b98e86aa64fb7350a308bf7c9c9972045c582b7363af44e93da26aef3c8fce81a0469d0c5f48199312f73953ce3c3547b91f543b5586a307c380a30858b74656127a05134b7614d5fba180e97739c99cf60a42498f1e9c7eda0a88a5fce2d8bc8df5010a5260f96db1b132b0a30b88c17f529454d0305f27188d32f1aea28a82881d32a1e30e7b01c9aa53b9a9ea01a3706852b4c97c9eaa42e670e93820a30a86404df6d392d2ba08e01a3a967bfd58f081f45bec4e68bf91302f1918870f80719e78a33fa95c520e929e0d58bf38c0a308cf690a81a1eab3d0554acfc7087e0b9ad3dcd50b9612893f56bd1536b6865092f60e7cef0c81e2acf97f287f4d28d1d0a30ae23fb1b0c76e4fd9800c18945094932655fa3a6aea990392c08c16e9816b3637b3818f609bf774e7277aa9901f1140a0a30935b301be1f67fc6a896b57309e546bfc1ae731a19b73777ca848fb81f4d8d7b9a5c1cf8ad54d5e1eda09f2095d848cb0a308ca1bccbe513b4503f8496b8468c42718972718feff4e3d5eec970f3c56ac0e2a8d4d59ad331db9cbea643ea775314bb0a30a77a318dd834183c3e3b3921c94b1dbb8d1bb2c619e0c492a592c2de5a91e73b5c054bba52619355ed34012386a7aa1d0a3089931c9f649137fe9a6d59a455bcc695af861fa080fef0d598cc2ae66ed193939d12e72cf0a6f081ada36b4090f864cc0a30a8a4c939ec0ee6ff6c58ace82cb82a603fd246defc10fdb37f6d66b5d1f2a1f9fa962547f87ec3aa611402f00bcec0a80a308c3d37929876321cfb221b3dca80feb1c38159ee83e01d1ad60fd16d9d2c78993a41643ec1e7af2d6a0ff8dfb05467ea0a3085bc68a8c76d4f706648059fa2d3b387c86ee65082e5fc16713794c6c0f8277d37c72783abe1c47ad3de97bd33ef66a30a3095419a10ad9771dc7545637bc14e4eb7938e0bcc57a42000ddbb117750570fb5ce290679d326a0783e6c780be23df6d81230818d704739c58be76d451e8ee7dc0219ee05a70d5ae8883ce50cb38452d2f6ae98aa8f58a2b6d91b13704215ca9e8ac812c0050a6c08d2bc03101f1a20cc4b81681aecde381a22ff3fd783637b453f17e115e8464b9a6be7b0b7eec54222206280f2051eed7cceeb6e2ca0df842e7407801e38d7055e934859c96abbe2cccc2a20ac685229b5bf43e11b944cfbf4092e9f208f6842085d695ebf82cb8a10865d36226c08c0bc0310261a204ec487b55dc9d763a428f40e4f4a6de27c292141d4a566f8a20b1869ec07f1442220c560190013eb3736fcd205de886ab24ba726fbabd1aad1547173550ea3fb48862a20910021ff13faefaadacccce284a32774fd6549b277c8c83ab24a471c1926619d2a20c81b0000000000000000000000000000000000000000000000000000000000002a201b551484c08b8e7f67dfebb84d962521462e97b25cf598949669e7f1cc09b30f2a2093d011e58ac588ba211be7fe3c99900d5414410f08b0c6935d26e2514d1333052a207cfb7fc8b098cb16f2c152b6c3f601280f7eb6ddad5a76d589d43107ee5008362a2050c127731137604d232497a7628660758895388e464053c8e091ba0ce0a7bbeb2a20117e2d766286c293b657b087db5de81e3d919d0d003608db2321e51b4aec379732201a21643cf3dba961d3520f11b33b2714e1b4afabf9a0f51b48ce7f4827f2b7e43a2034ec782719fdf157244a03e0f86889060a0bcf98c9ad2b177e76e06a9f3d35b73a208307c3e06a2258b3d3f6ae868c4f5214b63830b1fcefe19a2eaa149771321e723a20db56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d713a202ccd02aa05035d20bbfb35348ec98820ad9d1bbd52ab6a520dcdeee51ba5cea042680a04ffffffff12608593289076e15192d182557bc08561ef5e2e7a5474d792ef72eb5999a88d4bfe223e094b865aaa3a423cb171b58758c4044b4161ecfebcd0bb990991133e18e573d216ccff4573f0fecf83270844f923b9a116bb7f98dbf10df2caaf5b58a16248d3bc031afa020a209fd009b5c2d016c67245019d1bd4be1aa316fcbb5f4084f3bb7d4621c75a5337122011e171407dd93f6030a8898b1e32af6586e7890fa040a84222d6b8e6d71f7442122078df58ed6b8262e03d47067005c49ac65ed81f06e43bc93b6884fccaef442ece1220e539627c92f7e4d8682d977b0da441ba2c78ef8c3d7e07b6ebac1f5af5f8342d122019ff790ec253a41a67b63047cc265551da556fea1b38380234b7313be7300a4c1220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c189ac402222080c3c9010000000000000000000000000000000000000000000000000000000022206f00bde44faef650a62d20c0832f1b97adfcec69370ad4121c5d652ec7855ec722208c66366877cfe6f70787fec8245b6298cb8dae8809759adad22a5833c28baa0c222019ff790ec253a41a67b63047cc265551da556fea1b38380234b7313be7300a4c2220536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c").to_vec();
        let raw_l1_header = RawL1Header::decode(&*raw_l1).unwrap();
        let l1 = L1Header::<{ethereum_ibc::consensus::preset::minimal::PRESET.SYNC_COMMITTEE_SIZE}>::try_from(raw_l1_header).unwrap();
        /* TODO
        let l1_config = L1Config {
            genesis_validators_root: Root::default(),
            min_sync_committee_participants: 0.into(),
            genesis_time: 0.into(),
            fork_parameters: Default::default(),
            seconds_per_slot: 0.into(),
            slots_per_epoch: Slot::default(),
            epochs_per_sync_committee_period: Epoch::default(),
            trust_level: Default::default(),
        };
        let cons_state = ConsensusState {
            storage_root: Default::default(),
            timestamp: Time::unix_epoch(),
            output_root: Default::default(),
            hash: Default::default(),
            l1_slot: Default::default(),
            l1_current_sync_committee: Default::default(),
            l1_next_sync_committee: Default::default(),
        };
        l1.verify(0, &l1_config, &cons_state).unwrap();
         */
    }

}