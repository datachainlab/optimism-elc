use crate::client_state::ClientState;
use crate::consensus_state::ConsensusState;
use crate::errors::{ClientError, Error};
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use alloy_primitives::keccak256;
use ethereum_ibc::commitment::{calculate_ibc_commitment_storage_key, decode_eip1184_rlp_proof};
use ethereum_ibc::consensus::types::H256;
use ethereum_ibc::eth_client_type;
use ethereum_ibc::light_client_verifier::execution::ExecutionVerifier;
use light_client::commitments::{
    gen_state_id_from_any, CommitmentPrefix, EmittedState, StateID, UpdateStateProxyMessage,
    ValidationContext, VerifyMembershipProxyMessage,
};
use light_client::types::{Any, ClientId, Height};
use light_client::{
    CreateClientResult, Error as LightClientError, HostClientReader, LightClient,
    UpdateClientResult, VerifyMembershipResult, VerifyNonMembershipResult,
};

pub struct OptimismLightClient<
    const L1_SYNC_COMMITTEE_SIZE: usize,
    const L1_EXECUTION_PAYLOAD_TREE_DEPTH: usize,
>;

pub(crate) const OPTIMISM_CLIENT_TYPE: &str = "optimism";

impl<const L1_SYNC_COMMITTEE_SIZE: usize, const L1_EXECUTION_PAYLOAD_TREE_DEPTH: usize> LightClient
    for OptimismLightClient<L1_SYNC_COMMITTEE_SIZE, L1_EXECUTION_PAYLOAD_TREE_DEPTH>
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
        let client_state =
            ClientState::try_from(any_client_state).map_err(|e| ClientError::LatestHeight {
                cause: e,
                client_id: client_id.clone(),
            })?;
        Ok(client_state.latest_height)
    }

    fn create_client(
        &self,
        ctx: &dyn HostClientReader,
        any_client_state: Any,
        any_consensus_state: Any,
    ) -> Result<CreateClientResult, Error> {
        InnerLightClient
            .create_client(ctx, any_client_state.clone(), any_consensus_state.clone())
            .map_err(|e| {
                ClientError::CreateClient {
                    cause: e,
                    client_state: any_client_state,
                    consensus_sate: any_consensus_state,
                }
                .into()
            })
    }

    fn update_client(
        &self,
        ctx: &dyn HostClientReader,
        client_id: ClientId,
        client_message: Any,
    ) -> Result<UpdateClientResult, Error> {
        InnerLightClient
            .update_client(ctx, client_id.clone(), client_message.clone())
            .map_err(|e| {
                ClientError::UpdateClient {
                    cause: e,
                    client_id,
                }
                .into()
            })
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
    ) -> Result<VerifyMembershipResult, Error> {
        InnerLightClient
            .verify_membership(
                ctx,
                client_id.clone(),
                prefix.clone(),
                path.clone(),
                value.clone(),
                proof_height,
                proof.clone(),
            )
            .map_err(|e| {
                ClientError::VerifyMembership {
                    cause: e,
                    client_id,
                    prefix,
                    path,
                    value,
                    proof_height,
                    proof,
                }
                .into()
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
    ) -> Result<VerifyNonMembershipResult, Error> {
        InnerLightClient
            .verify_non_membership(
                ctx,
                client_id.clone(),
                prefix.clone(),
                path.clone(),
                proof_height,
                proof.clone(),
            )
            .map_err(|e| {
                ClientError::VerifyNonMembership {
                    cause: e,
                    client_id,
                    prefix,
                    path,
                    proof_height,
                    proof,
                }
                .into()
            })
    }
}

struct InnerLightClient<
    const L1_SYNC_COMMITTEE_SIZE: usize,
    const L1_EXECUTION_PAYLOAD_TREE_DEPTH: usize,
>;

impl<const L1_SYNC_COMMITTEE_SIZE: usize, const L1_EXECUTION_PAYLOAD_TREE_DEPTH: usize>
    InnerLightClient<L1_SYNC_COMMITTEE_SIZE, L1_EXECUTION_PAYLOAD_TREE_DEPTH>
{
    fn create_client(
        &self,
        _: &dyn HostClientReader,
        any_client_state: Any,
        any_consensus_state: Any,
    ) -> Result<CreateClientResult, Error> {
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
    ) -> Result<UpdateClientResult, Error> {
        todo!()
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
    ) -> Result<VerifyMembershipResult, Error> {
        let (client_state, cons_state, proof, key, root) =
            Self::validate_args(ctx, &client_id, &path, &proof_height, proof)?;

        let value = keccak256(&value).0;

        let execution_verifier = ExecutionVerifier::default();
        execution_verifier
            .verify_membership(
                root,
                key.as_bytes(),
                rlp::encode(&trim_left_zero(&value)).as_ref(),
                proof,
            )
            .map_err(Error::L1Error)?;

        Ok(VerifyMembershipResult {
            message: VerifyMembershipProxyMessage::new(
                prefix.into_vec(),
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
    ) -> Result<VerifyNonMembershipResult, Error> {
        let (client_state, cons_state, proof, key, root) =
            Self::validate_args(ctx, &client_id, &path, &proof_height, proof)?;

        let execution_verifier = ExecutionVerifier::default();
        execution_verifier
            .verify_non_membership(root, key.as_bytes(), proof)
            .map_err(Error::L1Error)?;

        Ok(VerifyNonMembershipResult {
            message: VerifyMembershipProxyMessage::new(
                prefix.into_vec(),
                path.to_string(),
                None,
                proof_height,
                gen_state_id(client_state, cons_state)?,
            ),
        })
    }

    fn validate_args(
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
        let storage_root = consensus_state.state_root;
        let proof = decode_eip1184_rlp_proof(proof.into())?;
        let path = path.into();
        let root = H256::from_slice(storage_root.as_slice());
        if root.is_zero() {
            return Err(Error::UnexpectedStorageRoot(
                proof_height,
                client_state.latest_height,
            ));
        }
        let key = calculate_ibc_commitment_storage_key(
            &H256::from_slice(client_state.ibc_commitments_slot.as_slice()),
            path.clone(),
        );

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
