use crate::consensus_state::ConsensusState;
use crate::errors::Error;
use crate::header::{Header, VerifyResult};
use crate::l1::L1Config;
use crate::misc::{
    new_timestamp, validate_header_timestamp_not_future,
    validate_state_timestamp_within_trusting_period,
};
use alloc::borrow::ToOwned;
use alloc::vec::Vec;
use alloy_primitives::B256;
use core::time::Duration;
use ethereum_ibc::client_state::{trim_left_zero, verify_account_storage};
use ethereum_ibc::consensus::beacon::Version;
use ethereum_ibc::consensus::fork::{ForkParameter, ForkParameters, ForkSpec};
use ethereum_ibc::consensus::types::{Address, H256, U64};
use ethereum_ibc::light_client_verifier::context::Fraction;
use ethereum_ibc::light_client_verifier::execution::ExecutionVerifier;
use ethereum_ibc_proto::ibc::lightclients::ethereum::v1::{
    Fork as ProtoFork, ForkParameters as ProtoForkParameters, ForkSpec as ProtoForkSpec,
    Fraction as ProtoFraction,
};
use light_client::types::{Any, Height, Time};
use op_alloy_genesis::RollupConfig;
use optimism_ibc_proto::google::protobuf::Any as IBCAny;
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

    ///Light Client parameters
    pub trusting_period: Duration,
    pub max_clock_drift: Duration,

    /// State
    pub latest_height: Height,
    pub frozen: bool,

    /// RollupConfig
    pub rollup_config: RollupConfig,

    /// L1 Config
    pub l1_config: L1Config,
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
    ) -> Result<(ClientState, ConsensusState, Height, Time), Error> {
        // Ensure l1 finalized
        let (l1_slot, l1_current_sync_committee, l1_next_sync_committee) =
            header.l1_header().verify(
                now.as_unix_timestamp_secs(),
                &self.l1_config,
                &trusted_consensus_state,
            )?;

        // Update only L1 sync committee
        if header.is_empty_derivation() {
            let mut new_consensus_state = trusted_consensus_state.clone();
            new_consensus_state.l1_slot = l1_slot;
            new_consensus_state.l1_current_sync_committee = l1_current_sync_committee;
            new_consensus_state.l1_next_sync_committee = l1_next_sync_committee;
            return Ok((
                self.clone(),
                new_consensus_state,
                header.trusted_height(),
                trusted_consensus_state.timestamp,
            ));
        }

        // Ensure header is valid
        let VerifyResult {
            l2_header,
            l2_output_root,
        } = header.verify(
            self.chain_id,
            trusted_consensus_state.hash,
            &self.rollup_config,
        )?;

        // Ensure world state is valid
        let account_update = header.account_update_ref();
        verify_account_storage(
            &self.ibc_store_address,
            &ExecutionVerifier::default(),
            H256::from_slice(l2_header.state_root.0.as_slice()),
            account_update,
        )
        .map_err(Error::L1IBCError)?;

        // check if the current timestamp is within the trusting period
        validate_state_timestamp_within_trusting_period(
            now,
            self.trusting_period,
            trusted_consensus_state.timestamp,
        )?;
        // check if the header timestamp does not indicate a future time
        let timestamp = new_timestamp(l2_header.timestamp)?;
        validate_header_timestamp_not_future(now, self.max_clock_drift, timestamp)?;

        let mut new_client_state = self.clone();
        let header_height = Height::new(
            header.trusted_height().revision_number(),
            l2_header.number as u64,
        );
        if new_client_state.latest_height < header_height {
            new_client_state.latest_height = header_height;
        }
        let new_consensus_state = ConsensusState {
            storage_root: account_update.account_storage_root,
            timestamp: new_timestamp(l2_header.timestamp)?,
            output_root: l2_output_root,
            hash: l2_header.hash_slow(),
            l1_slot,
            l1_current_sync_committee,
            l1_next_sync_committee,
        };

        Ok((
            new_client_state,
            new_consensus_state,
            header_height,
            timestamp,
        ))
    }

    pub fn verify_membership(
        &self,
        root: H256,
        key: H256,
        value: &[u8],
        proof: Vec<Vec<u8>>,
    ) -> Result<(), Error> {
        let execution_verifier = ExecutionVerifier::default();
        execution_verifier
            .verify_membership(
                root,
                key.as_bytes(),
                rlp::encode(&trim_left_zero(value)).as_ref(),
                proof,
            )
            .map_err(Error::L1VerifyError)
    }

    pub fn verify_non_membership(
        &self,
        root: H256,
        key: H256,
        proof: Vec<Vec<u8>>,
    ) -> Result<(), Error> {
        let execution_verifier = ExecutionVerifier::default();
        execution_verifier
            .verify_non_membership(root, key.as_bytes(), proof)
            .map_err(Error::L1VerifyError)
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
                numerator: value.trust_level.numerator,
                denominator: value.trust_level.denominator,
            }),
        }
    }
}

impl TryFrom<RawL1Config> for L1Config {
    type Error = Error;

    fn try_from(value: RawL1Config) -> Result<Self, Self::Error> {
        //TODO ethereum-ibc-rs refactor
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
                .enumerate()
                .map(|(_i, f)| -> Result<_, Error> {
                    Ok(ForkParameter::new(
                        bytes_to_version(f.version),
                        f.epoch.into(),
                        convert_fork_spec(f.spec)?,
                    ))
                })
                .collect::<Result<Vec<_>, _>>()?,
        )
        .map_err(|e| Error::L1IBCError(ethereum_ibc::errors::Error::EthereumConsensusError(e)))?;
        let trust_level = value.trust_level.ok_or(Error::MissingTrustLevel)?;

        Ok(Self {
            genesis_validators_root: H256::from_slice(&value.genesis_validators_root),
            min_sync_committee_participants: value.min_sync_committee_participants.into(),
            genesis_time: value.genesis_time.into(),
            fork_parameters,
            seconds_per_slot: value.seconds_per_slot.into(),
            slots_per_epoch: value.slots_per_epoch.into(),
            epochs_per_sync_committee_period: value.epochs_per_sync_committee_period.into(),
            trust_level: Fraction::new(trust_level.numerator, trust_level.denominator),
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

        let rollup_config: RollupConfig = serde_json::from_slice(&value.rollup_config_json)
            .map_err(Error::UnexpectedRollupConfig)?;

        let frozen = value.frozen;

        let l1_config = value.l1_config.ok_or(Error::MissingL1Config)?;
        let l1_config = L1Config::try_from(l1_config)?;

        Ok(Self {
            chain_id: value.chain_id,
            ibc_store_address,
            ibc_commitments_slot,
            latest_height,
            trusting_period,
            max_clock_drift,
            frozen,
            rollup_config,
            l1_config,
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
            trusting_period: Some(value.trusting_period.into()),
            max_clock_drift: Some(value.max_clock_drift.into()),
            frozen: value.frozen.to_owned(),
            rollup_config_json: serde_json::to_vec(&value.rollup_config)
                .map_err(Error::UnexpectedRollupConfig)?,
            l1_config: Some(value.l1_config.into()),
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
