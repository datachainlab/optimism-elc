use crate::errors::Error;
use crate::types::ChainId;
use alloc::borrow::ToOwned;
use alloc::vec::Vec;
use alloy_primitives::ruint::aliases::B160;
use alloy_primitives::B256;
use core::time::Duration;
use light_client::types::{Any, Height, Time};
use op_alloy_genesis::RollupConfig;
use optimism_ibc_proto::google::protobuf::Any as IBCAny;
use optimism_ibc_proto::ibc::lightclients::optimism::v1::ClientState as RawClientState;
use prost::Message;
pub const OPTIMISM_CLIENT_STATE_TYPE_URL: &str = "/ibc.lightclients.optimism.v1.ClientState";

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ClientState {
    /// Chain parameters
    pub chain_id: ChainId,

    /// IBC Solidity parameters
    pub ibc_store_address: B160,
    pub ibc_commitments_slot: B256,

    ///Light Client parameters
    pub trusting_period: Duration,
    pub max_clock_drift: Duration,

    /// State
    pub latest_height: Height,
    pub frozen: bool,

    /// RollupConfig
    pub rollup_config: RollupConfig,
}

impl ClientState {
    /// canonicalize canonicalizes some fields of specified client state
    /// target fields: latest_height, frozen
    pub fn canonicalize(mut self) -> Self {
        self.latest_height = Height::new(self.chain_id.version(), 0);
        self.frozen = false;
        self
    }

    pub fn freeze(mut self) -> Self {
        self.frozen = true;
        self
    }
}

impl TryFrom<RawClientState> for ClientState {
    type Error = Error;

    fn try_from(value: RawClientState) -> Result<Self, Self::Error> {
        let raw_latest_height = value
            .latest_height
            .as_ref()
            .ok_or(Error::MissingLatestHeight)?;

        let chain_id = ChainId::new(value.chain_id);

        let latest_height = Height::new(
            raw_latest_height.revision_number,
            raw_latest_height.revision_height,
        );

        let raw_ibc_store_address = value.ibc_store_address.clone();
        let ibc_store_address = raw_ibc_store_address
            .try_into()
            .map_err(|_| Error::UnexpectedStoreAddress(value.ibc_store_address))?;

        let raw_ibc_commitments_slot = value.ibc_commitments_slot.clone();
        let ibc_commitments_slot = raw_ibc_commitments_slot
            .try_into()
            .map_err(|_| Error::UnexpectedCommitmentSlot(value.ibc_commitments_slot))?;

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

        Ok(Self {
            chain_id,
            ibc_store_address,
            ibc_commitments_slot,
            latest_height,
            trusting_period,
            max_clock_drift,
            frozen,
            rollup_config,
        })
    }
}

impl TryFrom<ClientState> for RawClientState {
    type Error = Error;

    fn try_from(value: ClientState) -> Result<Self, Self::Error> {
        Ok(Self {
            chain_id: value.chain_id.id(),
            ibc_store_address: value.ibc_store_address.to_be_bytes_vec(),
            ibc_commitments_slot: value.ibc_commitments_slot.to_vec(),
            latest_height: Some(optimism_ibc_proto::ibc::core::client::v1::Height {
                revision_number: value.latest_height.revision_number(),
                revision_height: value.latest_height.revision_height(),
            }),
            trusting_period: Some(value.trusting_period.into()),
            max_clock_drift: Some(value.max_clock_drift.into()),
            frozen: value.frozen.to_owned(),
            rollup_config_json: serde_json::to_vec(&value.rollup_config)
                .map_err(Error::UnexpectedRollupConfig)?,
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
        let value: RawClientState = value.into();
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
        IBCAny::try_from(any).try_into()
    }
}
