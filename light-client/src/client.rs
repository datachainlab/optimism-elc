use crate::client_state::ClientState;
use crate::consensus_state::ConsensusState;
use crate::errors::Error;
use crate::header::Header;
use crate::message::ClientMessage;
use crate::misc::calculate_ibc_commitment_storage_location;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use alloy_primitives::keccak256;
use ethereum_ibc::commitment::decode_eip1184_rlp_proof;
use ethereum_ibc::consensus::types::H256;
use light_client::commitments::{
    gen_state_id_from_any, CommitmentPrefix, EmittedState, StateID, TrustingPeriodContext,
    UpdateStateProxyMessage, ValidationContext, VerifyMembershipProxyMessage,
};
use light_client::types::{Any, ClientId, Height};
use light_client::{
    CreateClientResult, Error as LightClientError, HostClientReader, LightClient,
    UpdateClientResult, UpdateStateData, VerifyMembershipResult, VerifyNonMembershipResult,
};

pub struct OptimismLightClient<const L1_SYNC_COMMITTEE_SIZE: usize>;

pub(crate) const OPTIMISM_CLIENT_TYPE: &str = "optimism";

impl<const L1_SYNC_COMMITTEE_SIZE: usize> LightClient
    for OptimismLightClient<L1_SYNC_COMMITTEE_SIZE>
{
    fn client_type(&self) -> String {
        OPTIMISM_CLIENT_TYPE.into()
    }

    fn latest_height(
        &self,
        ctx: &dyn HostClientReader,
        client_id: &ClientId,
    ) -> Result<Height, LightClientError> {
        let any_client_state = ctx.client_state(client_id)?;
        let client_state = ClientState::try_from(any_client_state)?;
        Ok(client_state.latest_height)
    }

    fn create_client(
        &self,
        _: &dyn HostClientReader,
        any_client_state: Any,
        any_consensus_state: Any,
    ) -> Result<CreateClientResult, light_client::Error> {
        let client_state = ClientState::try_from(any_client_state.clone())?;
        let consensus_state = ConsensusState::try_from(any_consensus_state)?;

        let post_state_id = gen_state_id(client_state.clone(), consensus_state.clone())?;

        let height = client_state.latest_height;
        let timestamp = consensus_state.timestamp;

        Ok(CreateClientResult {
            height,
            message: UpdateStateProxyMessage {
                prev_state_id: None,
                post_state_id,
                emitted_states: vec![EmittedState(height, any_client_state)],
                prev_height: None,
                post_height: height,
                timestamp,
                context: ValidationContext::Empty,
            }
            .into(),
            prove: false,
        })
    }

    fn update_client(
        &self,
        ctx: &dyn HostClientReader,
        client_id: ClientId,
        client_message: Any,
    ) -> Result<UpdateClientResult, light_client::Error> {
        match ClientMessage::<L1_SYNC_COMMITTEE_SIZE>::try_from(client_message.clone())? {
            ClientMessage::Header(header) => Ok(self.update_state(ctx, client_id, header)?.into()),
            //TODO misbehavior
            ClientMessage::Misbehaviour => todo!("misbehaviour"),
        }
    }

    fn verify_membership(
        &self,
        ctx: &dyn HostClientReader,
        client_id: ClientId,
        prefix: CommitmentPrefix,
        path: String,
        value: Vec<u8>,
        proof_height: Height,
        proof: Vec<u8>,
    ) -> Result<VerifyMembershipResult, light_client::Error> {
        let (client_state, cons_state, proof, key, root) =
            Self::validate_membership_args(ctx, &client_id, &path, &proof_height, proof)?;

        let value = keccak256(&value).0;

        client_state.verify_membership(root, key, &value, proof)?;

        Ok(VerifyMembershipResult {
            message: VerifyMembershipProxyMessage::new(
                prefix.to_vec(),
                path,
                Some(value),
                proof_height,
                gen_state_id(client_state, cons_state)?,
            ),
        })
    }

    fn verify_non_membership(
        &self,
        ctx: &dyn HostClientReader,
        client_id: ClientId,
        prefix: CommitmentPrefix,
        path: String,
        proof_height: Height,
        proof: Vec<u8>,
    ) -> Result<VerifyNonMembershipResult, light_client::Error> {
        let (client_state, cons_state, proof, key, root) =
            Self::validate_membership_args(ctx, &client_id, &path, &proof_height, proof)?;

        client_state.verify_non_membership(root, key, proof)?;

        Ok(VerifyNonMembershipResult {
            message: VerifyMembershipProxyMessage::new(
                prefix.to_vec(),
                path.to_string(),
                None,
                proof_height,
                gen_state_id(client_state, cons_state)?,
            ),
        })
    }
}

impl<const L1_SYNC_COMMITTEE_SIZE: usize> OptimismLightClient<L1_SYNC_COMMITTEE_SIZE> {
    fn update_state(
        &self,
        ctx: &dyn HostClientReader,
        client_id: ClientId,
        header: Header<L1_SYNC_COMMITTEE_SIZE>,
    ) -> Result<UpdateStateData, Error> {
        let trusted_height = header.trusted_height();
        let any_client_state = ctx.client_state(&client_id).map_err(Error::LCPError)?;
        let any_consensus_state = ctx
            .consensus_state(&client_id, &trusted_height)
            .map_err(Error::LCPError)?;

        //Ensure client is not frozen
        let client_state = ClientState::try_from(any_client_state)?;
        if client_state.frozen {
            return Err(Error::ClientFrozen(client_id));
        }

        // Create new state and ensure header is valid
        let trusted_consensus_state = ConsensusState::try_from(any_consensus_state)?;

        let (new_client_state, new_consensus_state, height, timestamp) = client_state
            .check_header_and_update_state(
                ctx.host_timestamp(),
                &trusted_consensus_state,
                header,
            )?;

        let trusted_state_timestamp = trusted_consensus_state.timestamp;
        let trusting_period = client_state.trusting_period;
        let max_clock_drift = client_state.max_clock_drift;
        let prev_state_id = gen_state_id(client_state, trusted_consensus_state)?;
        let post_state_id = gen_state_id(new_client_state.clone(), new_consensus_state.clone())?;

        Ok(UpdateStateData {
            new_any_client_state: new_client_state.try_into()?,
            new_any_consensus_state: new_consensus_state.try_into()?,
            height,
            message: UpdateStateProxyMessage {
                prev_state_id: Some(prev_state_id),
                post_state_id,
                emitted_states: Default::default(),
                prev_height: Some(trusted_height),
                post_height: height,
                timestamp,
                context: ValidationContext::TrustingPeriod(TrustingPeriodContext::new(
                    trusting_period,
                    max_clock_drift,
                    timestamp,
                    trusted_state_timestamp,
                )),
            },
            prove: true,
        })
    }
    fn validate_membership_args(
        ctx: &dyn HostClientReader,
        client_id: &ClientId,
        path: &str,
        proof_height: &Height,
        proof: Vec<u8>,
    ) -> Result<(ClientState, ConsensusState, Vec<Vec<u8>>, H256, H256), Error> {
        let client_state =
            ClientState::try_from(ctx.client_state(client_id).map_err(Error::LCPError)?)?;
        if client_state.frozen {
            return Err(Error::ClientFrozen(client_id.clone()));
        }
        let proof_height = *proof_height;
        if client_state.latest_height < proof_height {
            return Err(Error::UnexpectedProofHeight(
                proof_height,
                client_state.latest_height,
            ));
        }

        let consensus_state = ConsensusState::try_from(
            ctx.consensus_state(&client_id, &proof_height)
                .map_err(Error::LCPError)?,
        )?;
        let root = consensus_state.storage_root;
        let proof = decode_eip1184_rlp_proof(proof.into()).map_err(Error::L1IBCError)?;
        if root.is_zero() {
            return Err(Error::UnexpectedStorageRoot(
                proof_height,
                client_state.latest_height,
            ));
        }
        let key =
            calculate_ibc_commitment_storage_location(&client_state.ibc_commitments_slot, path);

        Ok((client_state, consensus_state, proof, key, root))
    }
}

fn gen_state_id(
    client_state: ClientState,
    consensus_state: ConsensusState,
) -> Result<StateID, Error> {
    let client_state = Any::try_from(client_state.canonicalize())?;
    let consensus_state = Any::try_from(consensus_state.canonicalize())?;
    gen_state_id_from_any(&client_state, &consensus_state)
        .map_err(LightClientError::commitment)
        .map_err(Error::LCPError)
}
