use crate::errors::Error;
use core::str::FromStr;
use core::time::Duration;
use ethereum_consensus::beacon::{Epoch, Root, Slot};
use ethereum_consensus::bls::PublicKey;
use ethereum_consensus::compute::compute_sync_committee_period_at_slot;
use ethereum_consensus::context::ChainContext;
use ethereum_consensus::fork::ForkParameters;
use ethereum_consensus::sync_protocol::SyncCommitteePeriod;
use ethereum_consensus::types::U64;
use ethereum_light_client_types::consensus::{
    convert_proto_to_consensus_update, convert_proto_to_execution_update, ConsensusUpdateInfo,
    ExecutionUpdateInfo, TrustedSyncCommittee,
};
use ethereum_light_client_types::time::{new_timestamp, validate_header_timestamp};
use ethereum_light_client_types::update::{
    compute_sync_committees, TrustedConsensusState, TrustedSyncCommitteeInfo,
};
use ethereum_light_client_types::validate::validate_execution_update;
use ethereum_light_client_verifier::consensus::SyncProtocolVerifier;
use ethereum_light_client_verifier::context::{
    ChainConsensusVerificationContext, Fraction, LightClientContext,
};
use ethereum_light_client_verifier::misbehaviour::{
    FinalizedHeaderMisbehaviour, Misbehaviour as MisbehaviourData, NextSyncCommitteeMisbehaviour,
};
use ethereum_light_client_verifier::updates::ConsensusUpdate;
use light_client::types::{ClientId, Time};
use optimism_ibc_proto::google::protobuf::Any as IBCAny;
use optimism_ibc_proto::ibc::lightclients::optimism::v1::{
    FinalizedHeaderMisbehaviour as RawFinalizedHeaderMisbehaviour, L1Header as RawL1Header,
    NextSyncCommitteeMisbehaviour as RawNextSyncCommitteeMisbehaviour,
};
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
pub struct L1ConsensusState {
    pub slot: Slot,
    pub current_sync_committee: PublicKey,
    pub next_sync_committee: PublicKey,
    pub timestamp: Time,
}

impl Default for L1ConsensusState {
    fn default() -> Self {
        Self {
            slot: Slot::default(),
            current_sync_committee: PublicKey::default(),
            next_sync_committee: PublicKey::default(),
            timestamp: Time::from_unix_timestamp_nanos(0).unwrap(),
        }
    }
}

impl TrustedSyncCommitteeInfo for L1ConsensusState {
    fn current_period<C: ChainContext>(&self, ctx: &C) -> SyncCommitteePeriod {
        compute_sync_committee_period_at_slot(ctx, self.slot)
    }

    fn current_sync_committee(&self) -> PublicKey {
        self.current_sync_committee.clone()
    }

    fn next_sync_committee(&self) -> PublicKey {
        self.next_sync_committee.clone()
    }

    fn is_relevant_update(&self, update_finalized_slot: U64) -> bool {
        update_finalized_slot > U64(self.slot.into())
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
        validate_header_timestamp(
            ctx,
            self.consensus_update.finalized_beacon_header().slot,
            self.timestamp,
        )?;
        Ok(())
    }
}

impl<const SYNC_COMMITTEE_SIZE: usize> L1Header<SYNC_COMMITTEE_SIZE> {
    pub fn verify(
        &self,
        now: u64,
        l1_config: &L1Config,
        consensus_state: &L1ConsensusState,
    ) -> Result<(bool, L1ConsensusState), Error> {
        let ctx = l1_config.build_context(now);

        self.validate(&ctx)?;

        let trusted_sync_committee = L1TrustedConsensusState::new(
            consensus_state.clone(),
            self.trusted_sync_committee.sync_committee.clone(),
            self.trusted_sync_committee.is_next,
        )?;
        L1Verifier::default().verify(
            &ctx,
            &trusted_sync_committee,
            &self.consensus_update,
            &self.execution_update,
        )?;
        apply_updates(
            &ctx,
            consensus_state,
            self.consensus_update.clone(),
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
            trusted_sync_committee: trusted_sync_committee.try_into()?,
            consensus_update,
            execution_update,
            timestamp: new_timestamp(value.timestamp)?,
        })
    }
}

pub type L1TrustedConsensusState<const SYNC_COMMITTEE_SIZE: usize> =
    TrustedConsensusState<SYNC_COMMITTEE_SIZE, L1ConsensusState>;

#[derive(Default)]
pub struct L1Verifier<const SYNC_COMMITTEE_SIZE: usize> {
    consensus_verifier:
        SyncProtocolVerifier<SYNC_COMMITTEE_SIZE, L1TrustedConsensusState<SYNC_COMMITTEE_SIZE>>,
}

impl<const SYNC_COMMITTEE_SIZE: usize> L1Verifier<SYNC_COMMITTEE_SIZE> {
    pub fn verify<CC: ChainConsensusVerificationContext>(
        &self,
        ctx: &CC,
        trusted_l1_cons_state: &L1TrustedConsensusState<SYNC_COMMITTEE_SIZE>,
        consensus_update: &ConsensusUpdateInfo<SYNC_COMMITTEE_SIZE>,
        execution_update: &ExecutionUpdateInfo,
    ) -> Result<(), Error> {
        // Same L1 validation as ethereum-light-client-rs
        self.consensus_verifier
            .validate_updates(
                ctx,
                trusted_l1_cons_state,
                consensus_update,
                execution_update,
            )
            .map_err(Error::L1VerifyConsensusUpdateError)?;

        // Ensure valid l1 block hash (only required for pre-Gloas)
        validate_execution_update::<SYNC_COMMITTEE_SIZE, _, _>(
            ctx,
            consensus_update,
            execution_update,
        )?;
        Ok(())
    }

    pub fn verify_misbehaviour<CC: ChainConsensusVerificationContext>(
        &self,
        ctx: &CC,
        trusted_l1_cons_state: &L1TrustedConsensusState<SYNC_COMMITTEE_SIZE>,
        data: MisbehaviourData<SYNC_COMMITTEE_SIZE, ConsensusUpdateInfo<SYNC_COMMITTEE_SIZE>>,
    ) -> Result<(), Error> {
        self.consensus_verifier
            .validate_misbehaviour(ctx, trusted_l1_cons_state, data)
            .map_err(Error::L1VerifyMisbehaviourError)
    }
}

fn apply_updates<const SYNC_COMMITTEE_SIZE: usize, CC: ChainConsensusVerificationContext>(
    ctx: &CC,
    consensus_state: &L1ConsensusState,
    consensus_update: ConsensusUpdateInfo<SYNC_COMMITTEE_SIZE>,
    header_timestamp: Time,
) -> Result<(bool, L1ConsensusState), Error> {
    let store_period = consensus_state.current_period(ctx);
    let update_finalized_slot = consensus_update.finalized_header.0.slot;
    let update_finalized_period = compute_sync_committee_period_at_slot(ctx, update_finalized_slot);
    let period_changed = store_period + 1 == update_finalized_period;

    let sync_committee_info = compute_sync_committees(ctx, consensus_state, consensus_update)?;

    Ok((
        period_changed,
        L1ConsensusState {
            slot: update_finalized_slot,
            timestamp: header_timestamp,
            current_sync_committee: sync_committee_info.current_sync_committee,
            next_sync_committee: sync_committee_info.next_sync_committee,
        },
    ))
}

const ETHEREUM_FINALIZED_HEADER_MISBEHAVIOUR_TYPE_URL: &str =
    "/ibc.lightclients.ethereum.v1.FinalizedHeaderMisbehaviour";
const ETHEREUM_NEXT_SYNC_COMMITTEE_MISBEHAVIOUR_TYPE_URL: &str =
    "/ibc.lightclients.ethereum.v1.NextSyncCommitteeMisbehaviour";

#[derive(Clone, Debug)]
pub struct Misbehaviour<const SYNC_COMMITTEE_SIZE: usize> {
    pub client_id: ClientId,
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
        Ok(Self {
            client_id: ClientId::from_str(&value.client_id).map_err(Error::UnexpectedClientId)?,
            trusted_sync_committee: value
                .trusted_sync_committee
                .ok_or(Error::proto_missing("trusted_sync_committee"))?
                .try_into()?,
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
        Ok(Self {
            client_id: ClientId::from_str(&value.client_id).map_err(Error::UnexpectedClientId)?,
            trusted_sync_committee: value
                .trusted_sync_committee
                .ok_or(Error::proto_missing("trusted_sync_committee"))?
                .try_into()?,
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
        consensus_state: &L1ConsensusState,
    ) -> Result<(), Error> {
        let ctx = l1_config.build_context(now);

        self.validate()?;

        let trusted_l1_cons_state = L1TrustedConsensusState::new(
            consensus_state.clone(),
            self.trusted_sync_committee.sync_committee.clone(),
            self.trusted_sync_committee.is_next,
        )?;

        let verifier = L1Verifier::default();
        verifier.verify_misbehaviour(&ctx, &trusted_l1_cons_state, self.data.clone())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::errors::Error;
    use crate::l1::{apply_updates, L1Config, L1ConsensusState, L1Header};
    use ethereum_consensus::bls::PublicKey;
    use ethereum_consensus::types::H256;
    use optimism_ibc_proto::ibc::lightclients::optimism::v1::L1Header as RawL1Header;

    std::thread_local! {
        // Shared per-test fixture so all get_* helpers reference the same
        // (randomly-generated) sync committees within a test.
        static L1_FIXTURE: crate::test_utils::L1Fixture = crate::test_utils::L1Fixture::new();
    }

    pub fn get_l1_config() -> L1Config {
        L1_FIXTURE.with(|f| f.l1_config())
    }

    pub fn get_raw_l1_header() -> RawL1Header {
        L1_FIXTURE.with(|f| f.raw_l1_header())
    }

    pub fn get_l1_header(
    ) -> L1Header<{ ethereum_consensus::preset::minimal::PRESET.SYNC_COMMITTEE_SIZE }> {
        L1_FIXTURE.with(|f| f.l1_header())
    }

    pub fn get_l1_consensus() -> L1ConsensusState {
        L1_FIXTURE.with(|f| f.l1_consensus_state())
    }

    pub fn get_time() -> u64 {
        L1_FIXTURE.with(|f| f.now())
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
            Error::EthLightClientTypesError(
                ethereum_light_client_types::errors::Error::InvalidCurrentSyncCommitteeKeys {
                    ..
                },
            ) => {}
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
            Error::EthLightClientTypesError(
                ethereum_light_client_types::errors::Error::InvalidNextSyncCommitteeKeys { .. },
            ) => {}
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
            Error::L1VerifyConsensusUpdateError(_) => {}
            _ => panic!("Unexpected error: {:?}", err),
        }
    }

    #[test]
    pub fn test_l1_header_verify_error_execution_update() {
        let l1_config = get_l1_config();
        let mut l1_header = get_l1_header();
        let cons_state = get_l1_consensus();

        // Execution payload state_root no longer matches its merkle branch.
        l1_header.execution_update.state_root = H256([9; 32]);

        let err = l1_header
            .verify(get_time(), &l1_config, &cons_state)
            .unwrap_err();
        match err {
            Error::L1VerifyConsensusUpdateError(_) => {}
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
            Error::EthLightClientTypesError(
                ethereum_light_client_types::errors::Error::InvalidBlockHashMerkleBranch { .. },
            ) => {}
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
            l1_header.consensus_update.clone(),
            l1_header.timestamp,
        )
        .unwrap_err();
        match err {
            Error::EthLightClientTypesError(
                ethereum_light_client_types::errors::Error::StoreNotSupportedFinalizedPeriod {
                    ..
                },
            ) => {}
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
            l1_header.consensus_update.clone(),
            l1_header.timestamp,
        )
        .unwrap_err();
        match err {
            Error::EthLightClientTypesError(
                ethereum_light_client_types::errors::Error::NoNextSyncCommitteeInConsensusUpdate {
                    ..
                },
            ) => {}
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

    #[test]
    pub fn test_l1_header_verify_success_multi_period() {
        let l1_config = get_l1_config();
        // trusted state in period 1 (current=committee1, next=committee2)
        let cons_state = get_l1_consensus();
        // update finalized in period 2 (store_period + 1), signed by committee2
        let l1_header = L1_FIXTURE.with(|f| f.l1_header_next_period());

        let (_, l1_consensus) = l1_header
            .verify(get_time(), &l1_config, &cons_state)
            .unwrap();

        assert_eq!(
            l1_consensus.slot,
            l1_header.consensus_update.finalized_header.0.slot
        );
        // is_next == true: new current == trusted next committee
        assert!(l1_header.trusted_sync_committee.is_next);
        assert_eq!(
            l1_consensus.current_sync_committee,
            cons_state.next_sync_committee
        );
        assert_eq!(
            l1_consensus.next_sync_committee,
            l1_header
                .consensus_update
                .next_sync_committee
                .clone()
                .unwrap()
                .0
                .aggregate_pubkey
        );
    }
}
