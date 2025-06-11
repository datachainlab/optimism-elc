use crate::client_state::ClientState;
use crate::commitment::{calculate_ibc_commitment_storage_location, decode_eip1184_rlp_proof};
use crate::consensus_state::ConsensusState;
use crate::errors::Error;
use crate::header::Header;
use crate::message::ClientMessage;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use alloy_primitives::keccak256;
use ethereum_consensus::types::H256;
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
            //ClientMessage::Misbehaviour => todo!("misbehaviour"),
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
        let proof = decode_eip1184_rlp_proof(proof)?;
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
    use alloc::collections::BTreeMap;
    use alloc::string::{String, ToString};
    use alloc::vec::Vec;
    use alloy_primitives::hex;
    use core::str::FromStr;
    use ethereum_consensus::types::{Address, H256};
    use light_client::commitments::{CommitmentPrefix, ProxyMessage, UpdateStateProxyMessage};
    use light_client::types::{Any, ClientId, Height, Time};
    use light_client::{ClientReader, HostClientReader, HostContext, LightClient};
    use optimism_ibc_proto::ibc::lightclients::optimism::v1::ClientState as RawClientState;
    use optimism_ibc_proto::ibc::lightclients::optimism::v1::ConsensusState as RawConsensusState;
    use optimism_ibc_proto::ibc::lightclients::optimism::v1::FaultDisputeGameConfig as RawFaultDisputeGameConfig;
    use prost::Message;

    extern crate std;

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
        fn set(&mut self, _key: Vec<u8>, _value: Vec<u8>) {
            todo!()
        }

        fn get(&self, _key: &[u8]) -> Option<Vec<u8>> {
            todo!()
        }

        fn remove(&mut self, _key: &[u8]) {
            todo!()
        }
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
                fault_dispute_game_config:  RawFaultDisputeGameConfig {
                    dispute_game_factory_target_storage_slot: 103,
                    fault_dispute_game_status_slot: 0,
                    fault_dispute_game_status_slot_offset: 15,
                }.into()
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
            }
        }
    }

    fn get_initial_state() -> (ClientState, ConsensusState) {
        // All the test parameters are created by optimism-ibc-relay-prover#prover_test.go#TestSetupHeadersForUpdateShort
        let raw_cs = hex!("08e4ab8301121430346563383746363433353343344435433835331a201ee222554989dda120e26ecacf756fe1235cd8d726706b57517715dde4f0c900220310916f32e0097b2267656e65736973223a7b226c31223a7b2268617368223a22307834623265643664313832333330653534656438656537353563643766623566616338383430313430346130303232636630653964306331656565373534363337222c226e756d626572223a31347d2c226c32223a7b2268617368223a22307864646534326639326562396463343535383132653836376133313666393839373831643033356666653735613862333933666139386432313661363131353364222c226e756d626572223a307d2c226c325f74696d65223a313734383234323438392c2273797374656d5f636f6e666967223a7b226261746368657241646472223a22307864336632633561666232643736663535373966333236623063643764613566356134313236633335222c226f76657268656164223a22307830303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030222c227363616c6172223a22307830313030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303063356663353030303030353538222c226761734c696d6974223a36303030303030302c2265697031353539506172616d73223a22307830303030303030303030303030303030222c226f70657261746f72466565506172616d73223a22307830303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030227d7d2c22626c6f636b5f74696d65223a322c226d61785f73657175656e6365725f6472696674223a3630302c227365715f77696e646f775f73697a65223a333630302c226368616e6e656c5f74696d656f7574223a3330302c226c315f636861696e5f6964223a333135313930382c226c325f636861696e5f6964223a323135313930382c227265676f6c6974685f74696d65223a302c2263616e796f6e5f74696d65223a302c2264656c74615f74696d65223a302c2265636f746f6e655f74696d65223a302c22666a6f72645f74696d65223a302c226772616e6974655f74696d65223a302c22686f6c6f63656e655f74696d65223a302c22697374686d75735f74696d65223a302c2262617463685f696e626f785f61646472657373223a22307830306134666534633661616130373239643736393963333837653766323831646436346166613261222c226465706f7369745f636f6e74726163745f61646472657373223a22307836663162666137323138626438373739373235626166656632363137343232353066393134663034222c226c315f73797374656d5f636f6e6669675f61646472657373223a22307837366336396432653931323734346262363461353939643765376234353534346331306437373435222c2270726f746f636f6c5f76657273696f6e735f61646472657373223a22307830303030303030303030303030303030303030303030303030303030303030303030303030303030222c22636861696e5f6f705f636f6e666967223a7b2265697031353539456c6173746963697479223a362c226569703135353944656e6f6d696e61746f72223a35302c226569703135353944656e6f6d696e61746f7243616e796f6e223a3235307d7d3ab3010a20d61ea484febacfae5298d52a2b581f3e305a51f3112a9241b968dccf019f7b11100118e59fd0c106226f0a0410000038120e0a04200000381a0608691036183712140a04300000381a0c08691036183720192812301612140a04400000381a0c08691036183720192812301612140a04500000381a0c08691036183720192822302612150a04600000381a0d08a901105618572019282230262806300838084204080210034a040880a305520410c0843d");
        let raw_cons_state = hex!("0a20000000000000000000000000000000000000000000000000000000000000000010dbfed1c1061a20b3fd51901751662f8d04bba30c658819044aa4b72ede44ea84501028f7b420bd2080252a308582bbad3f9eee79addd939370c7241ee96d425c6a5d6e7fb89e59ad117c38e62064e56821b77b26353be13b86d6a66c32309325339b023fc50bc744ef7fdd824b7b5bc9315244bb0b39914dec4b902c906f064b9c913de3c16a4a505ca75f5bff2f38e5fdd1c106");
        let mut raw_cs = RawClientState::decode(raw_cs.as_slice()).unwrap();
        raw_cs.fault_dispute_game_config = Some(ClientState::default().fault_dispute_game_config.into());
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
                &MockClientReader {
                    client_state: None,
                    consensus_state: BTreeMap::new(),
                    time: None,
                },
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
            time: Some(Time::from_unix_timestamp(1748337388, 0).unwrap()),
        };

        let client_id = ClientId::from_str("optimism-1").unwrap();
        client
            .update_client(&ctx, client_id, client_message)
            .unwrap();
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
}
