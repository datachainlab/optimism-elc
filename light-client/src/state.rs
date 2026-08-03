use crate::client_state::ClientState;
use crate::consensus_state::ConsensusState;
use crate::errors::Error;
use ethereum_light_client_types::client_state::ClientState as _;
use light_client::commitments::{gen_state_id_from_any, StateID};
use light_client::types::Any;
use light_client::Error as LightClientError;

pub fn gen_state_id(
    client_state: ClientState,
    consensus_state: ConsensusState,
) -> Result<StateID, Error> {
    let client_state = Any::try_from(client_state.canonicalize())?;
    let consensus_state = Any::try_from(consensus_state)?;
    gen_state_id_from_any(&client_state, &consensus_state)
        .map_err(LightClientError::commitment)
        .map_err(Error::LCPError)
}
