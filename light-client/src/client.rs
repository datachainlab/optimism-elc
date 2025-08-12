use crate::client_state::ClientState;
use crate::commitment::{calculate_ibc_commitment_storage_location, decode_rlp_proof};
use crate::consensus_state::ConsensusState;
use crate::errors::Error;
use crate::header::Header;
use crate::message::ClientMessage;
use crate::misbehaviour::Misbehaviour;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::{format, vec};
use alloy_primitives::keccak256;
use core::time::Duration;
use ethereum_consensus::types::H256;
use light_client::commitments::{
    gen_state_id_from_any, CommitmentPrefix, EmittedState, MisbehaviourProxyMessage, PrevState,
    StateID, TrustingPeriodContext, UpdateStateProxyMessage, ValidationContext,
    VerifyMembershipProxyMessage,
};
use light_client::types::{Any, ClientId, Height, Time};
use light_client::{
    CreateClientResult, Error as LightClientError, HostClientReader, LightClient, MisbehaviourData,
    UpdateClientResult, UpdateStateData, VerifyMembershipResult, VerifyNonMembershipResult,
};
use optimism_derivation::logger;

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

        if client_state.frozen {
            return Err(Error::CannotInitializeFrozenClient.into());
        }
        if client_state.latest_height.revision_height() == 0 {
            return Err(Error::UnexpectedLatestHeight(client_state.latest_height).into());
        }

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
        logger::info(&format!("update_client {}", client_id.to_string()));
        match ClientMessage::<L1_SYNC_COMMITTEE_SIZE>::try_from(client_message.clone())? {
            ClientMessage::Header(header) => Ok(self.update_state(ctx, client_id, header)?.into()),
            ClientMessage::Misbehaviour(misbehaviour) => Ok(self
                .submit_misbehaviour(ctx, client_id, client_message, misbehaviour)?
                .into()),
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
        let ValidateMembershipResult {
            client_state,
            consensus_state,
            storage_proof,
            storage_key,
            storage_root,
        } = Self::validate_membership_args(ctx, &client_id, &path, &proof_height, proof)?;

        let value = keccak256(&value).0;

        client_state.verify_membership(storage_root, storage_key, &value, storage_proof)?;

        Ok(VerifyMembershipResult {
            message: VerifyMembershipProxyMessage::new(
                prefix.to_vec(),
                path,
                Some(value),
                proof_height,
                gen_state_id(client_state, consensus_state)?,
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
        let ValidateMembershipResult {
            client_state,
            consensus_state,
            storage_proof,
            storage_key,
            storage_root,
        } = Self::validate_membership_args(ctx, &client_id, &path, &proof_height, proof)?;

        client_state.verify_non_membership(storage_root, storage_key, storage_proof)?;

        Ok(VerifyNonMembershipResult {
            message: VerifyMembershipProxyMessage::new(
                prefix.to_vec(),
                path.to_string(),
                None,
                proof_height,
                gen_state_id(client_state, consensus_state)?,
            ),
        })
    }
}

struct ValidateMembershipResult {
    client_state: ClientState,
    consensus_state: ConsensusState,
    storage_proof: Vec<Vec<u8>>,
    storage_key: H256,
    storage_root: H256,
}

impl<const L1_SYNC_COMMITTEE_SIZE: usize> OptimismLightClient<L1_SYNC_COMMITTEE_SIZE> {
    fn update_state(
        &self,
        ctx: &dyn HostClientReader,
        client_id: ClientId,
        header: Header<L1_SYNC_COMMITTEE_SIZE>,
    ) -> Result<UpdateStateData, Error> {
        logger::info(&format!(
            "update_state {} trusted_height={}",
            client_id.to_string(),
            header.trusted_height.revision_height()
        ));
        let trusted_height = header.trusted_height;
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

        let (new_client_state, new_consensus_state, height) = client_state
            .check_header_and_update_state(
                ctx.host_timestamp(),
                &trusted_consensus_state,
                header,
            )?;

        let trusted_state_l1_timestamp = trusted_consensus_state.l1_timestamp;
        let trusting_period = client_state.l1_config.trusting_period;
        let max_clock_drift = client_state.l1_config.max_clock_drift;
        let new_l1_timestamp = new_consensus_state.l1_timestamp;
        let new_l2_timestamp = new_consensus_state.timestamp;
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
                timestamp: new_l2_timestamp,
                context: ValidationContext::TrustingPeriod(TrustingPeriodContext::new(
                    trusting_period,
                    max_clock_drift,
                    new_l1_timestamp,
                    trusted_state_l1_timestamp,
                )),
            },
            prove: true,
        })
    }

    fn submit_misbehaviour(
        &self,
        ctx: &dyn HostClientReader,
        client_id: ClientId,
        any_message: Any,
        misbehaviour: Misbehaviour<L1_SYNC_COMMITTEE_SIZE>,
    ) -> Result<MisbehaviourData, Error> {
        let trusted_height = misbehaviour.trusted_height();
        let any_client_state = ctx.client_state(&client_id).map_err(Error::LCPError)?;
        let any_consensus_state = ctx
            .consensus_state(&client_id, &trusted_height)
            .map_err(Error::LCPError)?;
        let trusted_consensus_state = ConsensusState::try_from(any_consensus_state)?;
        let client_state = ClientState::try_from(any_client_state)?;
        let new_client_state = client_state.check_misbehaviour_and_update_state(
            ctx.host_timestamp(),
            &client_id,
            &trusted_consensus_state,
            misbehaviour,
        )?;

        Ok(MisbehaviourData {
            new_any_client_state: new_client_state.try_into()?,
            message: MisbehaviourProxyMessage {
                prev_states: self.make_prev_states(
                    ctx,
                    &client_id,
                    &client_state,
                    vec![trusted_height],
                )?,
                // For misbehaviour, it is acceptable if the header's timestamp points to the future.
                context: ValidationContext::TrustingPeriod(TrustingPeriodContext::new(
                    client_state.l1_config.trusting_period,
                    Duration::ZERO,
                    Time::unix_epoch(),
                    trusted_consensus_state.l1_timestamp,
                )),
                client_message: any_message,
            },
        })
    }

    fn make_prev_states(
        &self,
        ctx: &dyn HostClientReader,
        client_id: &ClientId,
        client_state: &ClientState,
        heights: Vec<Height>,
    ) -> Result<Vec<PrevState>, Error> {
        let mut prev_states = Vec::new();
        for height in heights {
            let consensus_state: ConsensusState = ctx
                .consensus_state(client_id, &height)
                .map_err(Error::LCPError)?
                .try_into()?;
            prev_states.push(PrevState {
                height,
                state_id: gen_state_id(client_state.clone(), consensus_state)?,
            });
        }
        Ok(prev_states)
    }

    fn validate_membership_args(
        ctx: &dyn HostClientReader,
        client_id: &ClientId,
        path: &str,
        proof_height: &Height,
        proof: Vec<u8>,
    ) -> Result<ValidateMembershipResult, Error> {
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
            ctx.consensus_state(client_id, &proof_height)
                .map_err(Error::LCPError)?,
        )?;
        let root = consensus_state.storage_root;
        let proof = decode_rlp_proof(proof)?;
        if root.is_zero() {
            return Err(Error::UnexpectedStorageRoot(
                proof_height,
                client_state.latest_height,
            ));
        }
        let key =
            calculate_ibc_commitment_storage_location(&client_state.ibc_commitments_slot, path);

        Ok(ValidateMembershipResult {
            client_state,
            consensus_state,
            storage_proof: proof,
            storage_key: key,
            storage_root: root,
        })
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

#[cfg(test)]
mod test {
    use crate::client::{OptimismLightClient, OPTIMISM_CLIENT_TYPE};
    use crate::client_state::ClientState;
    use crate::consensus_state::ConsensusState;
    use crate::l1::tests::get_l1_config;
    use crate::misbehaviour::FaultDisputeGameConfig;
    use alloc::collections::BTreeMap;
    use alloc::string::{String, ToString};
    use alloc::vec::Vec;
    use alloy_primitives::{hex, B256};
    use core::str::FromStr;
    use ethereum_consensus::types::{Address, H256};
    use light_client::commitments::{CommitmentPrefix, ProxyMessage, UpdateStateProxyMessage};
    use light_client::types::{Any, ClientId, Height, Time};
    use light_client::{
        ClientReader, HostClientReader, HostContext, LightClient, UpdateClientResult,
    };
    use optimism_ibc_proto::ibc::lightclients::optimism::v1::ClientState as RawClientState;
    use optimism_ibc_proto::ibc::lightclients::optimism::v1::ConsensusState as RawConsensusState;
    use prost::Message;

    extern crate std;

    #[derive(Default)]
    struct MockClientReader {
        client_state: Option<ClientState>,
        consensus_state: BTreeMap<Height, ConsensusState>,
        time: Option<Time>,
    }

    impl HostContext for MockClientReader {
        fn host_timestamp(&self) -> Time {
            self.time.unwrap_or_else(Time::now)
        }
    }

    impl HostClientReader for MockClientReader {}

    impl store::KVStore for MockClientReader {
        fn set(&mut self, _key: Vec<u8>, _value: Vec<u8>) {}

        fn get(&self, _key: &[u8]) -> Option<Vec<u8>> {
            None
        }

        fn remove(&mut self, _key: &[u8]) {}
    }

    impl ClientReader for MockClientReader {
        fn client_state(&self, client_id: &ClientId) -> Result<Any, light_client::Error> {
            let cs = self
                .client_state
                .clone()
                .ok_or_else(|| light_client::Error::client_state_not_found(client_id.clone()))?;
            Ok(Any::try_from(cs).unwrap())
        }

        fn consensus_state(
            &self,
            client_id: &ClientId,
            height: &Height,
        ) -> Result<Any, light_client::Error> {
            let state = self
                .consensus_state
                .get(height)
                .ok_or_else(|| {
                    light_client::Error::consensus_state_not_found(client_id.clone(), *height)
                })?
                .clone();
            Ok(Any::try_from(state).unwrap())
        }
    }

    impl Default for ClientState {
        fn default() -> Self {
            ClientState {
                chain_id: 0,
                ibc_store_address: Default::default(),
                ibc_commitments_slot: Default::default(),
                latest_height: Default::default(),
                frozen: false,
                rollup_config: Default::default(),
                l1_config: get_l1_config(),
                fault_dispute_game_config: Default::default(),
            }
        }
    }

    impl Default for ConsensusState {
        fn default() -> Self {
            ConsensusState {
                storage_root: Default::default(),
                timestamp: Time::now(),
                output_root: Default::default(),
                l1_slot: Default::default(),
                l1_current_sync_committee: Default::default(),
                l1_next_sync_committee: Default::default(),
                l1_timestamp: Time::now(),
                l1_origin: Default::default(),
            }
        }
    }

    fn get_initial_state() -> (ClientState, ConsensusState) {
        // All the test parameters are created by optimism-ibc-relay-prover#prover_test.go#TestSetupHeadersForUpdateShort
        let raw_cs = hex!("08e4ab8301121430346563383746363433353343344435433835331a201ee222554989dda120e26ecacf756fe1235cd8d726706b57517715dde4f0c900220310fa0632e0097b2267656e65736973223a7b226c31223a7b2268617368223a22307833323036646233326531363237623866323332383536653665653235323266343036346638333439333535666663376637333039363966313232303261613236222c226e756d626572223a31327d2c226c32223a7b2268617368223a22307839313834313637643634393239373632303463336436643361383730323566613834383934326161323663666435323632303034326635306433346366353464222c226e756d626572223a307d2c226c325f74696d65223a313735313433353737342c2273797374656d5f636f6e666967223a7b226261746368657241646472223a22307864336632633561666232643736663535373966333236623063643764613566356134313236633335222c226f76657268656164223a22307830303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030222c227363616c6172223a22307830313030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303063356663353030303030353538222c226761734c696d6974223a36303030303030302c2265697031353539506172616d73223a22307830303030303030303030303030303030222c226f70657261746f72466565506172616d73223a22307830303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030227d7d2c22626c6f636b5f74696d65223a322c226d61785f73657175656e6365725f6472696674223a3630302c227365715f77696e646f775f73697a65223a333630302c226368616e6e656c5f74696d656f7574223a3330302c226c315f636861696e5f6964223a333135313930382c226c325f636861696e5f6964223a323135313930382c227265676f6c6974685f74696d65223a302c2263616e796f6e5f74696d65223a302c2264656c74615f74696d65223a302c2265636f746f6e655f74696d65223a302c22666a6f72645f74696d65223a302c226772616e6974655f74696d65223a302c22686f6c6f63656e655f74696d65223a302c22697374686d75735f74696d65223a302c2262617463685f696e626f785f61646472657373223a22307830306134666534633661616130373239643736393963333837653766323831646436346166613261222c226465706f7369745f636f6e74726163745f61646472657373223a22307866343831373130613162653561366164393036656439656334643665386465353633326262323764222c226c315f73797374656d5f636f6e6669675f61646472657373223a22307864373736366162663339336132383132343835353335343130326134623865353561396164613035222c2270726f746f636f6c5f76657273696f6e735f61646472657373223a22307830303030303030303030303030303030303030303030303030303030303030303030303030303030222c22636861696e5f6f705f636f6e666967223a7b2265697031353539456c6173746963697479223a362c226569703135353944656e6f6d696e61746f72223a35302c226569703135353944656e6f6d696e61746f7243616e796f6e223a3235307d7d3ab3010a20d61ea484febacfae5298d52a2b581f3e305a51f3112a9241b968dccf019f7b11100118b69393c306226f0a0410000038120e0a04200000381a0608691036183712140a04300000381a0c08691036183720192812301612140a04400000381a0c08691036183720192812301612140a04500000381a0c08691036183720192822302612150a04600000381a0d08a901105618572019282230262806300838084204080210034a040880a305520410c0843d421c0a1400000000000000000000000000000000000000001067200f2818");
        let raw_cs = RawClientState::decode(raw_cs.as_slice()).unwrap();
        let raw_cons_state = hex!("0a20000000000000000000000000000000000000000000000000000000000000000010f2a193c3061a2022c0a7b70704f4b53ad38209d3bd6b65acee53b2a3bb09a41a6f94055d13ccd52080022a30b4d15930c89d177627d58c0beae3d8ba6d8b373a9d3bb83dbd9b2eb174b00b7d2debeaf52c4ebe1ac79c4f87c5ae87e13230b87c99df253587f882502475ba00541d608e5bc82c6a488f70ab56c43dbf25ae60e264b77715ffc664ebc4bfa1ba2fc938b69f93c30640b002");
        let raw_cons_state = RawConsensusState::decode(raw_cons_state.as_slice()).unwrap();

        let cs = ClientState::try_from(raw_cs).unwrap();
        let cons_state = ConsensusState::try_from(raw_cons_state).unwrap();
        (cs, cons_state)
    }
    #[test]
    fn test_latest_height() {
        let client = OptimismLightClient::<
            { ethereum_consensus::preset::minimal::PRESET.SYNC_COMMITTEE_SIZE },
        >;
        assert_eq!(client.client_type(), OPTIMISM_CLIENT_TYPE);

        let (cs, _) = get_initial_state();
        let ctx = MockClientReader {
            client_state: Some(cs.clone()),
            consensus_state: BTreeMap::new(),
            time: None,
        };
        let client_id = ClientId::from_str("optimism-1").unwrap();
        let height = client.latest_height(&ctx, &client_id).unwrap();
        assert_eq!(height, cs.latest_height);
    }
    #[test]
    fn test_create_client() {
        let client = OptimismLightClient::<
            { ethereum_consensus::preset::minimal::PRESET.SYNC_COMMITTEE_SIZE },
        >;
        let (cs, cons_state) = get_initial_state();
        let any_cs = Any::try_from(cs.clone()).unwrap();
        let result = client
            .create_client(
                &MockClientReader::default(),
                any_cs.clone(),
                Any::try_from(cons_state.clone()).unwrap(),
            )
            .unwrap();

        assert_eq!(result.height, cs.latest_height);
        match result.message {
            ProxyMessage::UpdateState(UpdateStateProxyMessage {
                prev_height,
                post_height,
                timestamp,
                emitted_states,
                post_state_id,
                ..
            }) => {
                assert!(!post_state_id.to_vec().is_empty());
                assert_eq!(prev_height, None);
                assert_eq!(post_height, result.height);
                assert_eq!(timestamp, cons_state.timestamp);
                assert_eq!(emitted_states.len(), 1);
                assert_eq!(emitted_states[0].0, result.height);
                assert_eq!(emitted_states[0].1, any_cs);
            }
            _ => panic!("Unexpected message type"),
        }
    }

    #[test]
    fn test_create_client_error_frozen() {
        let client = OptimismLightClient::<
            { ethereum_consensus::preset::minimal::PRESET.SYNC_COMMITTEE_SIZE },
        >;
        let (mut cs, cons_state) = get_initial_state();
        cs.frozen = true;
        let any_cs = Any::try_from(cs.clone()).unwrap();
        let err = client
            .create_client(
                &MockClientReader::default(),
                any_cs.clone(),
                Any::try_from(cons_state.clone()).unwrap(),
            )
            .unwrap_err();
        assert!(
            err.to_string().contains("CannotInitializeFrozenClient"),
            "{:?}",
            err
        );
    }

    #[test]
    fn test_create_client_error_invalid_height() {
        let client = OptimismLightClient::<
            { ethereum_consensus::preset::minimal::PRESET.SYNC_COMMITTEE_SIZE },
        >;
        let (mut cs, cons_state) = get_initial_state();
        cs.latest_height = Height::new(0, 0);

        let any_cs = Any::try_from(cs.clone()).unwrap();
        let err = client
            .create_client(
                &MockClientReader::default(),
                any_cs.clone(),
                Any::try_from(cons_state.clone()).unwrap(),
            )
            .unwrap_err();
        assert!(
            err.to_string().contains("UnexpectedLatestHeight"),
            "{:?}",
            err
        );
    }

    #[test]
    fn test_update_client() {
        let client = OptimismLightClient::<
            { ethereum_consensus::preset::minimal::PRESET.SYNC_COMMITTEE_SIZE },
        >;
        let (cs, cons_state) = get_initial_state();

        let mut cons_states = BTreeMap::new();
        cons_states.insert(cs.latest_height, cons_state);

        let client_message =
            std::fs::read("../testdata/update_client_header.bin").expect("file not found");
        let client_message = Any::try_from(client_message).unwrap();

        let ctx = MockClientReader {
            client_state: Some(cs),
            consensus_state: cons_states,
            time: Some(Time::from_unix_timestamp(1751437975, 0).unwrap()),
        };

        let client_id = ClientId::from_str("optimism-1").unwrap();
        client
            .update_client(&ctx, client_id, client_message)
            .unwrap();
    }

    #[test]
    fn test_submit_misbehaviour_success() {
        let client = OptimismLightClient::<
            { ethereum_consensus::preset::minimal::PRESET.SYNC_COMMITTEE_SIZE },
        >;
        let (now, cs, cons_state, client_message, _) = get_misbehaviour_data();
        let mut cons_states = BTreeMap::new();
        cons_states.insert(cs.latest_height, cons_state.clone());

        let ctx = MockClientReader {
            client_state: Some(cs),
            consensus_state: cons_states,
            time: Some(Time::from_unix_timestamp(now, 0).unwrap()),
        };

        let client_id = ClientId::from_str("optimism-01").unwrap();
        let result = client
            .update_client(&ctx, client_id, client_message)
            .unwrap();
        match result {
            UpdateClientResult::Misbehaviour(data) => {
                let frozen = ClientState::try_from(data.new_any_client_state)
                    .unwrap()
                    .frozen;
                assert!(frozen, "Client should be frozen after misbehaviour");
            }
            _ => panic!("Expected success result"),
        }
    }

    #[test]
    fn test_submit_misbehaviour_future_success() {
        let client = OptimismLightClient::<
            { ethereum_consensus::preset::minimal::PRESET.SYNC_COMMITTEE_SIZE },
        >;

        let (now, cs, cons_state, client_message, _) = get_misbehaviour_future_data();
        let mut cons_states = BTreeMap::new();
        cons_states.insert(cs.latest_height, cons_state.clone());

        let ctx = MockClientReader {
            client_state: Some(cs),
            consensus_state: cons_states,
            time: Some(Time::from_unix_timestamp(now, 0).unwrap()),
        };

        let client_id = ClientId::from_str("optimism-01").unwrap();
        let result = client
            .update_client(&ctx, client_id, client_message)
            .unwrap();
        match result {
            UpdateClientResult::Misbehaviour(data) => {
                let frozen = ClientState::try_from(data.new_any_client_state)
                    .unwrap()
                    .frozen;
                assert!(frozen, "Client should be frozen after misbehaviour");
            }
            _ => panic!("Expected success result"),
        }
    }

    #[test]
    fn test_submit_misbehaviour_error() {
        let client = OptimismLightClient::<
            { ethereum_consensus::preset::minimal::PRESET.SYNC_COMMITTEE_SIZE },
        >;
        let (now, cs, mut cons_state, client_message, _) = get_misbehaviour_data();

        // empty output root to raise error
        cons_state.output_root = B256::default();

        let mut cons_states = BTreeMap::new();
        cons_states.insert(cs.latest_height, cons_state.clone());

        let ctx = MockClientReader {
            client_state: Some(cs),
            consensus_state: cons_states,
            time: Some(Time::from_unix_timestamp(now, 0).unwrap()),
        };

        let client_id = ClientId::from_str("optimism-01").unwrap();
        let err = client
            .update_client(&ctx, client_id, client_message)
            .unwrap_err();
        assert!(
            err.to_string().contains("UnexpectedTrustedOutputRoot"),
            "{:?}",
            err
        );
    }

    #[test]
    fn test_submit_misbehaviour_future_error() {
        let client = OptimismLightClient::<
            { ethereum_consensus::preset::minimal::PRESET.SYNC_COMMITTEE_SIZE },
        >;
        let (now, cs, mut cons_state, client_message, _) = get_misbehaviour_future_data();

        // lower l1 origin to raise error
        cons_state.l1_origin = 0;

        let mut cons_states = BTreeMap::new();
        cons_states.insert(cs.latest_height, cons_state);

        let ctx = MockClientReader {
            client_state: Some(cs),
            consensus_state: cons_states,
            time: Some(Time::from_unix_timestamp(now, 0).unwrap()),
        };

        let client_id = ClientId::from_str("optimism-01").unwrap();
        let err = client
            .update_client(&ctx, client_id, client_message.clone())
            .unwrap_err();
        assert!(
            err.to_string().contains("UnexpectedPastL1Header"),
            "{:?}",
            err
        );
    }

    #[test]
    fn test_submit_misbehaviour_error_not_misbehaviour() {
        let client = OptimismLightClient::<
            { ethereum_consensus::preset::minimal::PRESET.SYNC_COMMITTEE_SIZE },
        >;
        let (now, cs, mut cons_state, _, client_message) = get_misbehaviour_data();

        cons_state.output_root =
            hex!("494b7cbd45d1ee5a2c8d68451a1b1d5b83b1cede73c5d8cae19066eabdf600cb").into();

        let mut cons_states = BTreeMap::new();
        cons_states.insert(cs.latest_height, cons_state.clone());

        let ctx = MockClientReader {
            client_state: Some(cs),
            consensus_state: cons_states,
            time: Some(Time::from_unix_timestamp(now, 0).unwrap()),
        };

        let client_id = ClientId::from_str("optimism-01").unwrap();
        let err = client
            .update_client(&ctx, client_id, client_message)
            .unwrap_err();
        assert!(
            err.to_string().contains("UnexpectedMisbehaviourOutput"),
            "{:?}",
            err
        );
    }

    #[test]
    fn test_submit_misbehaviour_future_error_not_misbehaviour() {
        let client = OptimismLightClient::<
            { ethereum_consensus::preset::minimal::PRESET.SYNC_COMMITTEE_SIZE },
        >;
        let (now, mut cs, cons_state, _, client_message) = get_misbehaviour_future_data();

        cs.latest_height = Height::new(0, 14389);

        let mut cons_states = BTreeMap::new();
        cons_states.insert(cs.latest_height, cons_state.clone());

        let ctx = MockClientReader {
            client_state: Some(cs),
            consensus_state: cons_states,
            time: Some(Time::from_unix_timestamp(now, 0).unwrap()),
        };

        let client_id = ClientId::from_str("optimism-01").unwrap();
        let err = client
            .update_client(&ctx, client_id, client_message)
            .unwrap_err();
        assert!(
            err.to_string().contains("UnexpectedMisbehaviourHeight"),
            "{:?}",
            err
        );
    }

    #[test]
    fn test_submit_misbehaviour_l1error() {
        // All the test parameters are created by optimism-ibc-relay-prover#tools/misbehaviour/l1
        let client = OptimismLightClient::<
            { ethereum_consensus::preset::minimal::PRESET.SYNC_COMMITTEE_SIZE },
        >;
        let raw_cs = hex!("220210643aaf010a20d61ea484febacfae5298d52a2b581f3e305a51f3112a9241b968dccf019f7b11100118c1ecf8c206226f0a0410000038120e0a04200000381a0608691036183712140a04300000381a0c08691036183720192812301612140a04400000381a0c08691036183720192812301612140a04500000381a0c08691036183720192822302612150a04600000381a0d08a901105618572019282230262806300838084204080210034a040880a3055200");
        let raw_cs = RawClientState::decode(raw_cs.as_slice()).unwrap();

        let cs = ClientState {
            chain_id: raw_cs.chain_id,
            latest_height: raw_cs.latest_height.unwrap().into(),
            frozen: false,
            l1_config: raw_cs.l1_config.unwrap().try_into().unwrap(),
            fault_dispute_game_config: FaultDisputeGameConfig::default(),
            // unused
            rollup_config: Default::default(),
            ibc_store_address: Default::default(),
            ibc_commitments_slot: Default::default(),
        };

        let raw_cons_state = hex!("0a2000000000000000000000000000000000000000000000000000000000000000001a20000000000000000000000000000000000000000000000000000000000000000020d8252a30af31b52e6aac0da1056ca6dd4393de17ce0888d2f3669b495b96e53a575205ed9752fe2e4b57f15d6e58b0f4b1842677323089e966f8bf6e38515f0ac33fdd6420f22792769e3b4c391e1f5b29f10571eba9a48b9f70c5768dfe1456a7eb1ce42db438d1cefac206");
        let raw_cons_state = RawConsensusState::decode(raw_cons_state.as_slice()).unwrap();
        let cons_state = ConsensusState::try_from(raw_cons_state).unwrap();

        let mut cons_states = BTreeMap::new();
        cons_states.insert(cs.latest_height, cons_state.clone());

        let client_message =
            std::fs::read("../testdata/submit_misbehaviour_l1.bin").expect("file not found");
        let client_message = Any::try_from(client_message).unwrap();

        let ctx = MockClientReader {
            client_state: Some(cs),
            consensus_state: cons_states,
            time: Some(Time::from_unix_timestamp(1751064900, 0).unwrap()),
        };

        let client_id = ClientId::from_str("optimism-01").unwrap();
        let err = client
            .update_client(&ctx, client_id, client_message)
            .unwrap_err();
        assert!(
            err.to_string().contains("L1VerifyMisbehaviourError"),
            "{:?}",
            err
        );
    }

    #[test]
    fn test_verify_membership() {
        let (path, proof, value) = get_membership_proof();
        let proof_height = Height::new(0, 1);
        let client = OptimismLightClient::<
            { ethereum_consensus::preset::minimal::PRESET.SYNC_COMMITTEE_SIZE },
        >;

        let mut cons_states = BTreeMap::new();
        cons_states.insert(
            proof_height,
            ConsensusState {
                storage_root: H256(hex!(
                    "27cd08827e6bf1e435832f4b2660107beb562314287b3fa534f3b189574c0cca"
                )),
                ..Default::default()
            },
        );

        let ctx = MockClientReader {
            client_state: Some(ClientState {
                ibc_store_address: Address(hex!("a7f733a4fEA1071f58114b203F57444969b86524")),
                ibc_commitments_slot: H256(hex!(
                    "1ee222554989dda120e26ecacf756fe1235cd8d726706b57517715dde4f0c900"
                )),
                latest_height: proof_height,
                ..Default::default()
            }),
            consensus_state: cons_states,
            time: None,
        };

        let res = client.verify_membership(
            &ctx,
            ClientId::from_str("optimism-1").unwrap(),
            CommitmentPrefix::new(),
            path,
            value,
            proof_height,
            proof,
        );
        assert!(res.is_ok(), "{:?}", res);
    }

    #[test]
    fn test_verify_non_membership() {
        let (path, proof) = get_non_membership_proof();
        let proof_height = Height::new(0, 1);
        let client = OptimismLightClient::<
            { ethereum_consensus::preset::minimal::PRESET.SYNC_COMMITTEE_SIZE },
        >;

        let mut cons_states = BTreeMap::new();
        cons_states.insert(
            proof_height,
            ConsensusState {
                storage_root: H256(hex!(
                    "27cd08827e6bf1e435832f4b2660107beb562314287b3fa534f3b189574c0cca"
                )),
                ..Default::default()
            },
        );

        let ctx = MockClientReader {
            client_state: Some(ClientState {
                ibc_store_address: Address(hex!("a7f733a4fEA1071f58114b203F57444969b86524")),
                ibc_commitments_slot: H256(hex!(
                    "1ee222554989dda120e26ecacf756fe1235cd8d726706b57517715dde4f0c900"
                )),
                latest_height: proof_height,
                ..Default::default()
            }),
            consensus_state: cons_states,
            time: None,
        };
        let res = client.verify_non_membership(
            &ctx,
            ClientId::from_str("optimism-1").unwrap(),
            CommitmentPrefix::new(),
            path,
            proof_height,
            proof,
        );
        assert!(res.is_ok(), "{:?}", res);
    }

    #[test]
    fn test_verify_membership_frozen_error() {
        let (path, proof, value) = get_membership_proof();
        let proof_height = Height::new(0, 1);
        let client = OptimismLightClient::<
            { ethereum_consensus::preset::minimal::PRESET.SYNC_COMMITTEE_SIZE },
        >;
        let ctx = MockClientReader {
            client_state: Some(ClientState {
                frozen: true,
                ..Default::default()
            }),
            consensus_state: Default::default(),
            time: None,
        };

        let client_id = ClientId::from_str("optimism-1").unwrap();
        let err = client
            .verify_membership(
                &ctx,
                client_id,
                CommitmentPrefix::new(),
                path,
                value,
                proof_height,
                proof,
            )
            .unwrap_err();
        assert!(err.to_string().contains("ClientFrozen"), "{:?}", err);
    }

    #[test]
    fn test_verify_membership_height_error() {
        let (path, proof, value) = get_membership_proof();
        let proof_height = Height::new(0, 1);
        let client = OptimismLightClient::<
            { ethereum_consensus::preset::minimal::PRESET.SYNC_COMMITTEE_SIZE },
        >;
        let ctx = MockClientReader {
            client_state: Some(ClientState {
                latest_height: Height::new(0, proof_height.revision_height() - 1),
                ..Default::default()
            }),
            consensus_state: Default::default(),
            time: None,
        };

        let client_id = ClientId::from_str("optimism-1").unwrap();
        let err = client
            .verify_membership(
                &ctx,
                client_id,
                CommitmentPrefix::new(),
                path,
                value,
                proof_height,
                proof,
            )
            .unwrap_err();
        assert!(
            err.to_string().contains("UnexpectedProofHeight"),
            "{:?}",
            err
        );
    }

    // returns: (path, proof, value)
    fn get_membership_proof() -> (String, Vec<u8>, Vec<u8>) {
        (
            "clients/lcp-client-0/clientState".to_string(),
            hex!("f90159f901118080a0143145e818eeff83817419a6632ea193fd1acaa4f791eb17282f623f38117f56a0e6ee0a993a7254ee9253d766ea005aec74eb1e11656961f0fb11323f4f91075580808080a01efae04adc2e970b4af3517581f41ce2ba4ff60492d33696c1e2a5ab70cb55bba03bac3f5124774e41fb6efdd7219530846f9f6441045c4666d2855c6598cfca00a020d7122ffc86cb37228940b5a9441e9fd272a3450245c9130ca3ab00bc1cd6ef80a0047f255205a0f2b0e7d29d490abf02bfb62c3ed201c338bc7f0088fa9c5d77eda069fecc766fcb2df04eb3a834b1f4ba134df2be114479e251d9cc9b6ba493077b80a094c3ed6a7ef63a6a67e46cc9876b9b1882eeba3d28e6d61bb15cdfb207d077e180f843a03e077f3dfd0489e70c68282ced0126c62fcef50acdcb7f57aa4552b87b456b11a1a05dc044e92e82db28c96fd98edd502949612b06e8da6dd74664a43a5ed857b298").to_vec(),
            hex!("0a242f6962632e6c69676874636c69656e74732e6c63702e76312e436c69656e74537461746512ed010a208083673c69fe3f098ea79a799d9dbb99c39b4b4f17a1a79ef58bdf8ae86299951080f524220310fb012a1353575f48415244454e494e475f4e45454445442a1147524f55505f4f55545f4f465f44415445320e494e54454c2d53412d3030323139320e494e54454c2d53412d3030323839320e494e54454c2d53412d3030333334320e494e54454c2d53412d3030343737320e494e54454c2d53412d3030363134320e494e54454c2d53412d3030363135320e494e54454c2d53412d3030363137320e494e54454c2d53412d30303832383a14cb96f8d6c2d543102184d679d7829b39434e4eec48015001").to_vec()
        )
    }

    // returns: (path, proof)
    fn get_non_membership_proof() -> (String, Vec<u8>) {
        (
            "clients/lcp-client-1/clientState".to_string(),
            hex!("f90114f901118080a0143145e818eeff83817419a6632ea193fd1acaa4f791eb17282f623f38117f56a0e6ee0a993a7254ee9253d766ea005aec74eb1e11656961f0fb11323f4f91075580808080a01efae04adc2e970b4af3517581f41ce2ba4ff60492d33696c1e2a5ab70cb55bba03bac3f5124774e41fb6efdd7219530846f9f6441045c4666d2855c6598cfca00a020d7122ffc86cb37228940b5a9441e9fd272a3450245c9130ca3ab00bc1cd6ef80a0047f255205a0f2b0e7d29d490abf02bfb62c3ed201c338bc7f0088fa9c5d77eda069fecc766fcb2df04eb3a834b1f4ba134df2be114479e251d9cc9b6ba493077b80a094c3ed6a7ef63a6a67e46cc9876b9b1882eeba3d28e6d61bb15cdfb207d077e180").to_vec()
        )
    }

    fn get_misbehaviour_data() -> (i64, ClientState, ConsensusState, Any, Any) {
        // All the test parameters are created by optimism-ibc-relay-prover#tools/misbehaviour/l2/past
        let raw_cs = hex!("220310eb663aaf010a20d61ea484febacfae5298d52a2b581f3e305a51f3112a9241b968dccf019f7b11100118c1ecf8c206226f0a0410000038120e0a04200000381a0608691036183712140a04300000381a0c08691036183720192812301612140a04400000381a0c08691036183720192812301612140a04500000381a0c08691036183720192822302612150a04600000381a0d08a901105618572019282230262806300838084204080210034a040880a3055200421e0a14763ec6446d97cb3fcf6e44fb0ce9273a040073881067200f28183002");
        let raw_cs = RawClientState::decode(raw_cs.as_slice()).unwrap();

        let cs = to_misbehaviour_client_state(raw_cs);

        let raw_cons_state = hex!("0a2000000000000000000000000000000000000000000000000000000000000000001a2066eee1ae7872d4656c332bfb41475cf7631e6069a094c0a1942587af4e9b9fc020d8252a30af31b52e6aac0da1056ca6dd4393de17ce0888d2f3669b495b96e53a575205ed9752fe2e4b57f15d6e58b0f4b1842677323089e966f8bf6e38515f0ac33fdd6420f22792769e3b4c391e1f5b29f10571eba9a48b9f70c5768dfe1456a7eb1ce42db438d1cefac206");
        let raw_cons_state = RawConsensusState::decode(raw_cons_state.as_slice()).unwrap();
        let cons_state = ConsensusState::try_from(raw_cons_state).unwrap();

        let client_message =
            std::fs::read("../testdata/submit_misbehaviour.bin").expect("file not found");
        let client_message = Any::try_from(client_message).unwrap();

        let client_message_not =
            std::fs::read("../testdata/submit_misbehaviour_not_misbehaviour.bin")
                .expect("file not found");
        let client_message_not = Any::try_from(client_message_not).unwrap();

        (
            1751064827,
            cs,
            cons_state,
            client_message,
            client_message_not,
        )
    }

    fn get_misbehaviour_future_data() -> (i64, ClientState, ConsensusState, Any, Any) {
        // All the test parameters are created by optimism-ibc-relay-prover#tools/misbehaviour/l2/future
        let raw_cs = hex!("220310b4703aaf010a20d61ea484febacfae5298d52a2b581f3e305a51f3112a9241b968dccf019f7b11100118c1ecf8c206226f0a0410000038120e0a04200000381a0608691036183712140a04300000381a0c08691036183720192812301612140a04400000381a0c08691036183720192812301612140a04500000381a0c08691036183720192822302612150a04600000381a0d08a901105618572019282230262806300838084204080210034a040880a3055200421e0a14763ec6446d97cb3fcf6e44fb0ce9273a040073881067200f28183002");
        let raw_cs = RawClientState::decode(raw_cs.as_slice()).unwrap();

        let cs = to_misbehaviour_client_state(raw_cs);

        let raw_cons_state = hex!("0a2000000000000000000000000000000000000000000000000000000000000000001a20000000000000000000000000000000000000000000000000000000000000000020d8252a30af31b52e6aac0da1056ca6dd4393de17ce0888d2f3669b495b96e53a575205ed9752fe2e4b57f15d6e58b0f4b1842677323089e966f8bf6e38515f0ac33fdd6420f22792769e3b4c391e1f5b29f10571eba9a48b9f70c5768dfe1456a7eb1ce42db438d1cefac20640d125");
        let raw_cons_state = RawConsensusState::decode(raw_cons_state.as_slice()).unwrap();
        let cons_state = ConsensusState::try_from(raw_cons_state).unwrap();

        let client_message =
            std::fs::read("../testdata/submit_misbehaviour_future.bin").expect("file not found");
        let client_message = Any::try_from(client_message).unwrap();

        let client_message_not =
            std::fs::read("../testdata/submit_misbehaviour_not_misbehaviour_future.bin")
                .expect("file not found");
        let client_message_not = Any::try_from(client_message_not).unwrap();

        (
            1751070709,
            cs,
            cons_state,
            client_message,
            client_message_not,
        )
    }

    fn to_misbehaviour_client_state(mut raw_cs: RawClientState) -> ClientState {
        // Dummy status
        raw_cs
            .fault_dispute_game_config
            .as_mut()
            .unwrap()
            .status_defender_win = 0;

        ClientState {
            chain_id: raw_cs.chain_id,
            latest_height: raw_cs.latest_height.unwrap().into(),
            frozen: false,
            l1_config: raw_cs.l1_config.unwrap().try_into().unwrap(),
            fault_dispute_game_config: raw_cs
                .fault_dispute_game_config
                .unwrap()
                .try_into()
                .unwrap(),
            // unused
            rollup_config: Default::default(),
            ibc_store_address: Default::default(),
            ibc_commitments_slot: Default::default(),
        }
    }
}
