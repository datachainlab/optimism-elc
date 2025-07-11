use crate::consensus_state::ConsensusState;
use crate::errors::Error;
use crate::header::Header;
use crate::l1::{L1Config, L1Consensus};
use crate::misbehaviour::{FaultDisputeGameConfig, Misbehaviour, Verifier};
use crate::misc::{
    new_timestamp, validate_header_timestamp_not_future,
    validate_state_timestamp_within_trusting_period,
};
use alloc::borrow::ToOwned;
use alloc::vec::Vec;
use alloy_primitives::B256;
use ethereum_consensus::beacon::Version;
use ethereum_consensus::fork::{ForkParameter, ForkParameters, ForkSpec};
use ethereum_consensus::types::{Address, H256, U64};
use ethereum_light_client_verifier::context::Fraction;
use ethereum_light_client_verifier::execution::ExecutionVerifier;
use kona_genesis::RollupConfig;
use light_client::types::{Any, ClientId, Height, Time};
use optimism_ibc_proto::google::protobuf::Any as IBCAny;
use optimism_ibc_proto::ibc::lightclients::ethereum::v1::{
    Fork as ProtoFork, ForkParameters as ProtoForkParameters, ForkSpec as ProtoForkSpec,
    Fraction as ProtoFraction,
};
use optimism_ibc_proto::ibc::lightclients::optimism::v1::ClientState as RawClientState;
use optimism_ibc_proto::ibc::lightclients::optimism::v1::L1Config as RawL1Config;
use prost::Message;

pub const OPTIMISM_CLIENT_STATE_TYPE_URL: &str = "/ibc.lightclients.optimism.v1.ClientState";

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ClientState {
    pub chain_id: u64,

    /// IBC Solidity parameters
    pub ibc_store_address: Address,
    pub ibc_commitments_slot: H256,

    /// State
    pub latest_height: Height,
    pub frozen: bool,

    /// L2 RollupConfig
    pub rollup_config: RollupConfig,

    /// L1 Config
    pub l1_config: L1Config,

    /// Fault Dispute Game Config
    pub fault_dispute_game_config: FaultDisputeGameConfig,
}

impl ClientState {
    /// canonicalize canonicalizes some fields of specified client state
    /// target fields: latest_height, frozen
    pub fn canonicalize(mut self) -> Self {
        self.latest_height = Height::new(0, 0);
        self.frozen = false;
        self
    }

    pub fn freeze(mut self) -> Self {
        self.frozen = true;
        self
    }

    pub fn check_header_and_update_state<const L1_SYNC_COMMITTEE_SIZE: usize>(
        &self,
        now: Time,
        trusted_consensus_state: &ConsensusState,
        header: Header<L1_SYNC_COMMITTEE_SIZE>,
    ) -> Result<(ClientState, ConsensusState, Height), Error> {
        // Since the L1 block hash is used for L2 derivation, the validity of L1 must be verified.
        let l1_consensus = header.verify_l1(
            &self.l1_config,
            now.as_unix_timestamp_secs(),
            trusted_consensus_state,
        )?;

        // Ensure L2 header is valid
        let (l2_header, l1_origin, l2_output_root) = header.verify_l2(
            self.chain_id,
            trusted_consensus_state.output_root,
            &self.rollup_config,
        )?;

        // Ensure account storage is valid
        header.account_update.verify_account_storage(
            &self.ibc_store_address,
            H256::from_slice(l2_header.state_root.0.as_slice()),
        )?;

        // check if the current timestamp is within the trusting period
        // check not L2 but L1 because the L2 is derived from L1 consensus
        validate_state_timestamp_within_trusting_period(
            now,
            self.l1_config.trusting_period,
            trusted_consensus_state.l1_timestamp,
        )?;
        // check if the header timestamp does not indicate a future time
        validate_header_timestamp_not_future(
            now,
            self.l1_config.max_clock_drift,
            l1_consensus.timestamp,
        )?;

        let mut new_client_state = self.clone();
        let header_height = Height::new(header.trusted_height.revision_number(), l2_header.number);
        if new_client_state.latest_height < header_height {
            new_client_state.latest_height = header_height;
        }
        let new_consensus_state = ConsensusState {
            storage_root: header.account_update.account_storage_root,
            timestamp: new_timestamp(l2_header.timestamp)?,
            output_root: l2_output_root,
            l1_slot: l1_consensus.slot,
            l1_current_sync_committee: l1_consensus.current_sync_committee,
            l1_next_sync_committee: l1_consensus.next_sync_committee,
            l1_timestamp: l1_consensus.timestamp,
            l1_origin,
        };

        Ok((new_client_state, new_consensus_state, header_height))
    }
    pub fn check_misbehaviour_and_update_state<const L1_SYNC_COMMITTEE_SIZE: usize>(
        &self,
        now: Time,
        client_id: &ClientId,
        trusted_consensus_state: &ConsensusState,
        misbehaviour: Misbehaviour<L1_SYNC_COMMITTEE_SIZE>,
    ) -> Result<ClientState, Error> {
        if self.frozen {
            return Err(Error::ClientFrozen(client_id.clone()));
        }

        let misbehaviour_client_id = misbehaviour.client_id();
        if misbehaviour_client_id != client_id {
            return Err(Error::UnexpectedClientIdInMisbehaviour(
                client_id.clone(),
                misbehaviour_client_id.clone(),
            ));
        }

        let l1_cons_state = L1Consensus {
            slot: trusted_consensus_state.l1_slot,
            current_sync_committee: trusted_consensus_state.l1_current_sync_committee.clone(),
            next_sync_committee: trusted_consensus_state.l1_next_sync_committee.clone(),
            timestamp: trusted_consensus_state.l1_timestamp,
        };

        validate_state_timestamp_within_trusting_period(
            now,
            self.l1_config.trusting_period,
            trusted_consensus_state.l1_timestamp,
        )?;

        match &misbehaviour {
            Misbehaviour::L1(l1) => l1.verify(
                now.as_unix_timestamp_secs(),
                &self.l1_config,
                &l1_cons_state,
            ),
            Misbehaviour::L2(l2) => match l2.verifier() {
                Verifier::Future(v) => v.verify(
                    now.as_unix_timestamp_secs(),
                    &self.l1_config,
                    &self.fault_dispute_game_config,
                    &l1_cons_state,
                    misbehaviour.trusted_height().revision_height(),
                    trusted_consensus_state.l1_origin,
                ),
                Verifier::Past(v) => v.verify(
                    now.as_unix_timestamp_secs(),
                    &self.l1_config,
                    &self.fault_dispute_game_config,
                    &l1_cons_state,
                    trusted_consensus_state.output_root,
                ),
            },
        }?;

        Ok(Self {
            frozen: true,
            ..self.clone()
        })
    }

    pub fn verify_membership(
        &self,
        root: H256,
        key: H256,
        value: &[u8],
        proof: Vec<Vec<u8>>,
    ) -> Result<(), Error> {
        let execution_verifier = ExecutionVerifier;
        execution_verifier
            .verify_membership(
                root,
                key.as_bytes(),
                rlp::encode(&trim_left_zero(value)).as_ref(),
                proof,
            )
            .map_err(Error::VerifyMembershipError)
    }

    pub fn verify_non_membership(
        &self,
        root: H256,
        key: H256,
        proof: Vec<Vec<u8>>,
    ) -> Result<(), Error> {
        let execution_verifier = ExecutionVerifier;
        execution_verifier
            .verify_non_membership(root, key.as_bytes(), proof)
            .map_err(Error::VerifyMembershipError)
    }
}

impl From<L1Config> for RawL1Config {
    fn from(value: L1Config) -> Self {
        fn make_fork(version: &Version, epoch: U64, spec: ForkSpec) -> ProtoFork {
            ProtoFork {
                version: version_to_bytes(version),
                epoch: epoch.into(),
                spec: Some(ProtoForkSpec {
                    finalized_root_gindex: spec.finalized_root_gindex,
                    current_sync_committee_gindex: spec.current_sync_committee_gindex,
                    next_sync_committee_gindex: spec.next_sync_committee_gindex,
                    execution_payload_gindex: spec.execution_payload_gindex,
                    execution_payload_state_root_gindex: spec.execution_payload_state_root_gindex,
                    execution_payload_block_number_gindex: spec
                        .execution_payload_block_number_gindex,
                }),
            }
        }
        fn version_to_bytes(version: &Version) -> Vec<u8> {
            version.0.to_vec()
        }

        Self {
            genesis_validators_root: value.genesis_validators_root.as_bytes().to_vec(),
            min_sync_committee_participants: value.min_sync_committee_participants.into(),
            genesis_time: value.genesis_time.into(),
            fork_parameters: Some(ProtoForkParameters {
                genesis_fork_version: version_to_bytes(value.fork_parameters.genesis_version()),
                forks: value
                    .fork_parameters
                    .forks()
                    .iter()
                    .map(|f| make_fork(&f.version, f.epoch, f.spec.clone()))
                    .collect(),
            }),
            seconds_per_slot: value.seconds_per_slot.into(),
            slots_per_epoch: value.slots_per_epoch.into(),
            epochs_per_sync_committee_period: value.epochs_per_sync_committee_period.into(),
            trust_level: Some(ProtoFraction {
                numerator: value.trust_level.numerator(),
                denominator: value.trust_level.denominator(),
            }),
            trusting_period: Some(value.trusting_period.into()),
            max_clock_drift: Some(value.max_clock_drift.into()),
        }
    }
}

impl TryFrom<RawL1Config> for L1Config {
    type Error = Error;

    fn try_from(value: RawL1Config) -> Result<Self, Self::Error> {
        fn bytes_to_version(bz: Vec<u8>) -> Version {
            assert_eq!(bz.len(), 4);
            let mut version = Version::default();
            version.0.copy_from_slice(&bz);
            version
        }
        fn convert_fork_spec(spec: Option<ProtoForkSpec>) -> Result<ForkSpec, Error> {
            let spec = spec.ok_or(Error::MissingForkSpec)?;
            Ok(ForkSpec {
                finalized_root_gindex: spec.finalized_root_gindex,
                current_sync_committee_gindex: spec.current_sync_committee_gindex,
                next_sync_committee_gindex: spec.next_sync_committee_gindex,
                execution_payload_gindex: spec.execution_payload_gindex,
                execution_payload_state_root_gindex: spec.execution_payload_state_root_gindex,
                execution_payload_block_number_gindex: spec.execution_payload_block_number_gindex,
            })
        }
        let raw_fork_parameters = value.fork_parameters.ok_or(Error::MissingForkParameters)?;
        let fork_parameters: ForkParameters = ForkParameters::new(
            bytes_to_version(raw_fork_parameters.genesis_fork_version),
            raw_fork_parameters
                .forks
                .into_iter()
                .map(|f| -> Result<_, Error> {
                    Ok(ForkParameter::new(
                        bytes_to_version(f.version),
                        f.epoch.into(),
                        convert_fork_spec(f.spec)?,
                    ))
                })
                .collect::<Result<Vec<_>, _>>()?,
        )
        .map_err(Error::L1ConsensusError)?;
        let trust_level = value.trust_level.ok_or(Error::MissingTrustLevel)?;

        let trusting_period = value
            .trusting_period
            .ok_or(Error::MissingTrustingPeriod)?
            .try_into()
            .map_err(|_| Error::MissingTrustingPeriod)?;

        let max_clock_drift = value
            .max_clock_drift
            .ok_or(Error::NegativeMaxClockDrift)?
            .try_into()
            .map_err(|_| Error::NegativeMaxClockDrift)?;

        Ok(Self {
            genesis_validators_root: H256::from_slice(&value.genesis_validators_root),
            min_sync_committee_participants: value.min_sync_committee_participants.into(),
            genesis_time: value.genesis_time.into(),
            fork_parameters,
            seconds_per_slot: value.seconds_per_slot.into(),
            slots_per_epoch: value.slots_per_epoch.into(),
            epochs_per_sync_committee_period: value.epochs_per_sync_committee_period.into(),
            trust_level: Fraction::new(trust_level.numerator, trust_level.denominator).unwrap(),
            trusting_period,
            max_clock_drift,
        })
    }
}

impl TryFrom<RawClientState> for ClientState {
    type Error = Error;

    fn try_from(value: RawClientState) -> Result<Self, Self::Error> {
        let raw_latest_height = value
            .latest_height
            .as_ref()
            .ok_or(Error::MissingLatestHeight)?;

        let latest_height = Height::new(
            raw_latest_height.revision_number,
            raw_latest_height.revision_height,
        );

        let raw_ibc_store_address = value.ibc_store_address.clone();
        let ibc_store_address = Address::try_from(raw_ibc_store_address.as_slice())
            .map_err(Error::UnexpectedStoreAddress)?;

        let raw_ibc_commitments_slot = value.ibc_commitments_slot.clone();
        let ibc_commitments_slot = B256::try_from(raw_ibc_commitments_slot.as_slice())
            .map_err(Error::UnexpectedCommitmentSlot)?;
        let ibc_commitments_slot = H256::from(ibc_commitments_slot.0);

        let rollup_config: RollupConfig = serde_json::from_slice(&value.rollup_config_json)
            .map_err(Error::UnexpectedRollupConfig)?;

        let frozen = value.frozen;

        let l1_config = value.l1_config.ok_or(Error::MissingL1Config)?;
        let l1_config = L1Config::try_from(l1_config)?;
        let fault_dispute_game_config = value
            .fault_dispute_game_config
            .ok_or(Error::MissingFaultDisputeGameConfig)?;

        Ok(Self {
            chain_id: value.chain_id,
            ibc_store_address,
            ibc_commitments_slot,
            latest_height,
            frozen,
            rollup_config,
            l1_config,
            fault_dispute_game_config: fault_dispute_game_config.try_into()?,
        })
    }
}

impl TryFrom<ClientState> for RawClientState {
    type Error = Error;

    fn try_from(value: ClientState) -> Result<Self, Self::Error> {
        Ok(Self {
            chain_id: value.chain_id,
            ibc_store_address: value.ibc_store_address.0.to_vec(),
            ibc_commitments_slot: value.ibc_commitments_slot.0.to_vec(),
            latest_height: Some(optimism_ibc_proto::ibc::core::client::v1::Height {
                revision_number: value.latest_height.revision_number(),
                revision_height: value.latest_height.revision_height(),
            }),
            frozen: value.frozen.to_owned(),
            rollup_config_json: serde_json::to_vec(&value.rollup_config)
                .map_err(Error::UnexpectedRollupConfig)?,
            l1_config: Some(value.l1_config.into()),
            fault_dispute_game_config: Some(value.fault_dispute_game_config.into()),
        })
    }
}

impl TryFrom<IBCAny> for ClientState {
    type Error = Error;

    fn try_from(any: IBCAny) -> Result<Self, Self::Error> {
        if any.type_url != OPTIMISM_CLIENT_STATE_TYPE_URL {
            return Err(Error::UnknownClientStateType(any.type_url));
        }
        RawClientState::decode(any.value.as_slice())
            .map_err(Error::ProtoDecodeError)?
            .try_into()
    }
}

impl TryFrom<ClientState> for IBCAny {
    type Error = Error;

    fn try_from(value: ClientState) -> Result<Self, Self::Error> {
        let value: RawClientState = value.try_into()?;
        let mut v = Vec::new();
        value.encode(&mut v).map_err(Error::ProtoEncodeError)?;
        Ok(Self {
            type_url: OPTIMISM_CLIENT_STATE_TYPE_URL.to_owned(),
            value: v,
        })
    }
}

impl TryFrom<ClientState> for Any {
    type Error = Error;
    fn try_from(value: ClientState) -> Result<Self, Error> {
        Ok(IBCAny::try_from(value)?.into())
    }
}

impl TryFrom<Any> for ClientState {
    type Error = Error;

    fn try_from(any: Any) -> Result<Self, Self::Error> {
        IBCAny::from(any).try_into()
    }
}

fn trim_left_zero(value: &[u8]) -> &[u8] {
    let mut pos = 0;
    for v in value {
        if *v != 0 {
            break;
        }
        pos += 1;
    }
    &value[pos..]
}

#[cfg(test)]
mod test {
    use crate::client_state::trim_left_zero;

    #[test]
    fn test_trim_left_zero() {
        assert_eq!(trim_left_zero(&[1, 2, 3, 4]), [1, 2, 3, 4]);
        assert_eq!(trim_left_zero(&[1, 2, 3, 0]), [1, 2, 3, 0]);
        assert_eq!(trim_left_zero(&[0, 2, 3, 0]), [2, 3, 0]);
        assert_eq!(trim_left_zero(&[0, 0, 3, 0]), [3, 0]);
        assert_eq!(trim_left_zero(&[0, 0, 0, 4]), [4]);
        assert!(trim_left_zero(&[0, 0, 0, 0]).is_empty());
        assert!(trim_left_zero(&[]).is_empty());
    }
}
