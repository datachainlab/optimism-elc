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

#[cfg(test)]
mod test {
    use alloc::collections::BTreeMap;
    use alloc::vec::Vec;
    use light_client::types::{Any, ClientId, Height, Time};
    use alloy_primitives::hex;
    use light_client::{ClientReader, HostClientReader, HostContext};
    use prost::Message;
    use crate::header::Header;
    use optimism_ibc_proto::ibc::lightclients::optimism::v1::Header as RawHeader;
    use optimism_ibc_proto::ibc::lightclients::optimism::v1::ConsensusState as RawConsensusState;
    use optimism_ibc_proto::ibc::lightclients::optimism::v1::ClientState as RawClientState;
    use crate::client_state::ClientState;
    use crate::consensus_state::ConsensusState;
    extern crate std;

    struct MockClientReader {
        client_state: Option<ClientState>,
        consensus_state: BTreeMap<Height, ConsensusState>,
    }

    impl HostContext for MockClientReader {
        fn host_timestamp(&self) -> Time {
            Time::now()
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

    #[test]
    fn test_update_client_success() {
        let header = std::fs::read("../testdata/test_update_client_success.bin").unwrap();
        let header = RawHeader::decode(header.as_slice()).unwrap();
        let header = Header::<{ethereum_ibc::consensus::preset::minimal::PRESET.SYNC_COMMITTEE_SIZE}>::try_from(header).unwrap();
        let client = super::OptimismLightClient::<{ethereum_ibc::consensus::preset::minimal::PRESET.SYNC_COMMITTEE_SIZE}>;
        let client_id = ClientId::new("optimism", 0).unwrap();

        let cs = hex!("088507121430346563383746363433353343344435433835331a201ee222554989dda120e26ecacf756fe1235cd8d726706b57517715dde4f0c9002204108ac20c2a040880a3053202080a42c3077b2267656e65736973223a7b226c31223a7b2268617368223a22307837383234373266366335303437393463356164373731646633323737383066643436306162373062313162303239356664666665356366643836323036366639222c226e756d626572223a317d2c226c32223a7b2268617368223a22307832303034356338323034373931326539306530633438363539323331306538346132386163336535336131316366623536333532656431373732653031386562222c226e756d626572223a307d2c226c325f74696d65223a313733373732373131372c2273797374656d5f636f6e666967223a7b226261746368657241646472223a22307833633434636464646236613930306661326235383564643239396530336431326661343239336263222c226f76657268656164223a22307830303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030383334222c227363616c6172223a22307830303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030306634323430222c226761734c696d6974223a33303030303030307d7d2c22626c6f636b5f74696d65223a322c226d61785f73657175656e6365725f6472696674223a3330302c227365715f77696e646f775f73697a65223a3230302c226368616e6e656c5f74696d656f7574223a3132302c226c315f636861696e5f6964223a3930302c226c325f636861696e5f6964223a3930312c227265676f6c6974685f74696d65223a302c2263616e796f6e5f74696d65223a302c2264656c74615f74696d65223a302c2265636f746f6e655f74696d65223a302c22666a6f72645f74696d65223a302c2262617463685f696e626f785f61646472657373223a22307866663030303030303030303030303030303030303030303030303030303030303030303030393031222c226465706f7369745f636f6e74726163745f61646472657373223a22307836353039663261383534626137343431303339666365336239353964356261646432666663666364222c226c315f73797374656d5f636f6e6669675f61646472657373223a22307834616638303262333031306530373834356232623863323235303132366539616330626462366239222c2270726f746f636f6c5f76657273696f6e735f61646472657373223a22307830303030303030303030303030303030303030303030303030303030303030303030303030303030227d4a96010a2075da2cb5dbf4d891796935c9dedd02e1aae3a02c9416f97c008c499d87879136100118efb8cebc06225e0a0400000001120e0a04010000011a0608691036183712160a04020000011a0e086910361837201928123016381c12160a04030000011a0e086910361837201928123016381c12160a04040000011a0e086910361837201928223026382c280630083808420408021003");
        let cs = RawClientState::decode(cs.as_ref()).unwrap();
        let cs = ClientState::try_from(cs).unwrap();

        let cons_state= hex!("0a206650104b3587fd764d662c6ce55aad6ebc3a904179cba2e6e7f30087d5282fcb10a1bde7bc061a20528a82fe731c2f5a98c9c0a5dd6756589d39878a0127b0e31b379a77d3b37eba22204fff7afa5053c8df01795dfb9d8e304f02e2a08fa7c6290520e706cff79f62e328809604323084a7328b5fcbb1b77585ec2c6631415d8a930cba472f80080b1f54fae2f89c5ea065adfd784d38e5f791a1f2b02c43463a30b52bd2a5f0b2d9bf4e299343bb893de407bdd0d000673ab4bca8cc1877e19115dd8de7dc335a25c0ca67c3f009112e81");
        let cons_state = RawConsensusState::decode(cons_state.as_ref()).unwrap();
        let cons_state = ConsensusState::try_from(cons_state).unwrap();

        let mut mock_consensus_state = BTreeMap::new();
        mock_consensus_state.insert(cs.latest_height, cons_state);
        let ctx = MockClientReader {
            client_state: Some(cs),
            consensus_state: mock_consensus_state,
        };
        client.update_state(&ctx, client_id, header).unwrap();
    }
}