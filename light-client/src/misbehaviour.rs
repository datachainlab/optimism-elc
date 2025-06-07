use crate::account::AccountUpdateInfo;
use crate::errors::Error;
use alloc::vec::Vec;
use alloy_consensus::Header;
use alloy_primitives::private::alloy_rlp::Decodable;
use alloy_primitives::{keccak256, Sealable, B256};
use core::hash::Hash;
use ethereum_consensus::types::{Address, H256};
use ethereum_light_client_verifier::execution::ExecutionVerifier;
use kona_protocol::{OutputRoot, Predeploys};

/// Confirmed slot of DisputeGameFactoryProxy contract by forge
const DISPUTE_GAME_FACTORY_STORAGE_SLOT: u64 = 103;

/// storage layout of forge is reverse position
/// created_at offset = 0, bytes = 8 -> [24:32]
/// resoled_at offset = 8, bytes = 8 -> [16:23]
/// status offset = 16, bytes = 1 -> [15]
const FAULT_DISPUTE_GAME_STATUS_SLOT: u8 = 0;
const FAULT_DISPUTE_GAME_STATUS_OFFSET: u8 = 15;

const STATUS_DEFENDER_WIN: u8 = 2;

fn calculate_mapping_slot_bytes(key_bytes: &[u8], mapping_slot: u64) -> B256 {
    // Convert mapping_slot to a 32-byte array
    let mapping_slot_bytes = {
        let mut padded = [0u8; 32];
        let slot_bytes = mapping_slot.to_be_bytes();
        padded[32 - slot_bytes.len()..].copy_from_slice(&slot_bytes);
        padded
    };

    // Concatenate key_bytes and mapping_slot_bytes
    let mut concatenated = Vec::with_capacity(key_bytes.len() + 32);
    concatenated.extend_from_slice(key_bytes);
    concatenated.extend_from_slice(&mapping_slot_bytes);

    // Calculate the keccak256 hash
    let slot_hash = keccak256(&concatenated);

    // Convert the hash to H256
    B256::from_slice(slot_hash.as_slice())
}

fn calc_game_uuid(l2_block_num: B256, output_root: B256) -> B256 {
    // Define constants
    // We can split this into words that are 32 bytes long to get:
    // 0000000000000000000000000000000000000000000000000000000000000060  // offset
    // 000000000000000000000000000000000000000000000000000000000000000b  // length
    // 48656c6c6f20576f726c64000000000000000000000000000000000000000000  // extra_data
    let source_game_type =  u64_to_bytes(0);
    // start position of extra_data length
    // 32 (gameType) + 32(rootClaim) + extraOffset(32)
    let extra_offset = u64_to_bytes(96);
    let extra_len = u64_to_bytes(l2_block_num.len() as u64);

    // Build the source array
    let mut source = Vec::new();
    source.extend_from_slice(source_game_type.as_slice());
    source.extend_from_slice(output_root.0.as_slice());
    source.extend_from_slice(extra_offset.as_slice());
    source.extend_from_slice(extra_len.as_slice());
    source.extend_from_slice(l2_block_num.as_slice());

    // Calculate and return the Keccak256 hash
    keccak256(&source)
}

fn u64_to_bytes(n: u64) -> [u8; 32] {
    let mut buf = [0u8; 32];
    let bytes = n.to_be_bytes();
    buf[32 - bytes.len()..].copy_from_slice(&bytes);
    buf
}

fn left_pad(n: Vec<u8>) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[32 - n.len()..].copy_from_slice(&n);
    buf
}

fn unpack_game_id(game_id: [u8; 32]) -> (Vec<u8>, Vec<u8>, [u8; 20]) {
    let game_type = game_id[0..4].to_vec();
    let timestamp = game_id[4..12].to_vec();
    let mut game_proxy = [0u8; 20];
    game_proxy.copy_from_slice(&game_id[12..32]);
    (game_type, timestamp, game_proxy)
}

#[derive(Clone, Debug)]
struct FaultDisputeGameFactoryProof {
    /// Finalized and verified L1 header state root
    state_root: B256,

    /// Proof of DisputeGameFactoryProxy
    dispute_game_factory_address: Address,
    dispute_game_factory_account: AccountUpdateInfo,
    dispute_game_factory_storage_proof: Vec<Vec<u8>>,

    /// Proof of FaultDisputeGame
    fault_dispute_game_account: AccountUpdateInfo,
    fault_dispute_game_storage_proof: Vec<Vec<u8>>,
}

impl FaultDisputeGameFactoryProof {
    pub fn verify_resolved_status(
        &self,
        claimed_l2_number: u64,
        claimed_output_root: B256,
    ) -> Result<(), Error> {
        // Ensure valid account proof
        self.dispute_game_factory_account
            .verify_account_storage(&self.dispute_game_factory_address, self.state_root.0.into())?;

        // Extract game id from DisputeGameFactoryProxy by output_root.
        let game_uuid = calc_game_uuid(B256::from(u64_to_bytes(claimed_l2_number)), claimed_output_root);
        let game_id_key =
            calculate_mapping_slot_bytes(game_uuid.as_slice(), DISPUTE_GAME_FACTORY_STORAGE_SLOT);
        let execution_verifier = ExecutionVerifier;
        let game_id = execution_verifier
            .verify(
                self.dispute_game_factory_account.account_storage_root,
                game_id_key.as_slice(),
                self.dispute_game_factory_storage_proof.clone(),
            )
            .map_err(|err| Error::UnexpectedDisputeGameFactoryProxyProof {
                storage_root: self
                    .dispute_game_factory_account
                    .account_storage_root
                    .clone(),
                proof: self.dispute_game_factory_storage_proof.clone(),
                game_uuid,
                game_id_key,
                l2_block_number: claimed_l2_number,
                output_root: claimed_output_root,
                err: Some(err),
            })?;

        let game_id = game_id.ok_or_else(|| Error::UnexpectedDisputeGameFactoryProxyProof {
            storage_root: self
                .dispute_game_factory_account
                .account_storage_root
                .clone(),
            proof: self.dispute_game_factory_storage_proof.clone(),
            game_uuid,
            game_id_key,
            l2_block_number: claimed_l2_number,
            output_root: claimed_output_root,
            err: None,
        })?;

        // Ensure game is resolved with DIFFENDER_WIN status
        let (_, _, fault_dispute_game_address) = unpack_game_id(left_pad(game_id));
        self.fault_dispute_game_account
            .verify_account_storage(&Address(fault_dispute_game_address), self.state_root.0.into())?;
        let mut status_key = [0u8; 32];
        status_key[status_key.len() - 1] = FAULT_DISPUTE_GAME_STATUS_SLOT;
        let execution_verifier = ExecutionVerifier;
        let packing_slot_value = execution_verifier
            .verify(
                self.fault_dispute_game_account.account_storage_root,
                status_key.as_slice(),
                self.fault_dispute_game_storage_proof.clone(),
            )
            .map_err(|err| Error::UnexpectedFaultDisputeGameProof {
                storage_root: self.fault_dispute_game_account.account_storage_root.clone(),
                proof: self.fault_dispute_game_storage_proof.clone(),
                status_key: B256::from(status_key),
                address: Address(fault_dispute_game_address),
                err: Some(err),
            })?;
        let packing_slot_value=
            packing_slot_value.ok_or_else(|| Error::UnexpectedFaultDisputeGameProof {
                storage_root: self.fault_dispute_game_account.account_storage_root.clone(),
                proof: self.fault_dispute_game_storage_proof.clone(),
                status_key: B256::from(status_key),
                address: Address(fault_dispute_game_address),
                err: None,
            })?;
        let packing_slot_value = left_pad(packing_slot_value);

        let status = packing_slot_value[FAULT_DISPUTE_GAME_STATUS_OFFSET as usize];
        if status != STATUS_DEFENDER_WIN {
            return Err(Error::UnexpectedResolvedStatus {
                status,
                storage_root: self.fault_dispute_game_account.account_storage_root.clone(),
                proof: self.fault_dispute_game_storage_proof.clone(),
                status_key: B256::from(status_key),
                address: Address(fault_dispute_game_address),
                packing_slot_value
            });
        }
        Ok(())
    }
}

fn check_misbehaviour(
    // L2 output in consensus state
    trusted_l2_output_root: B256,
    trusted_l2_message_passer_account: AccountUpdateInfo,
    // Resolved L2 output in FaultDisputeGame
    resolved_l2_output_root: B256,
    resolved_l2_message_passer_account: AccountUpdateInfo,
    // Headers from trusted to resolved
    trusted_to_resolved_l2: Vec<Vec<u8>>,
    // Proof of fault dispute game
    fault_dispute_game_factory_proof: FaultDisputeGameFactoryProof
) -> Result<(), Error> {
    let mut headers: Vec<Header> = Vec::with_capacity(trusted_to_resolved_l2.len());
    for rlp in trusted_to_resolved_l2.into_iter() {
        let mut rlp = rlp.as_slice();
        let header = Header::decode(&mut rlp).map_err(Error::UnexpectedHeaderRLPError)?;
        headers.push(header);
    }

    // Ensure collect header relation
    for (index, header) in headers.iter().enumerate() {
        if index == headers.len() - 1 {
            break;
        }
        let parent = &headers[index + 1];
        if header.parent_hash != parent.hash_slow() {
            return Err(Error::UnexpectedHeaderRelation {
                expected_parent_hash: header.parent_hash,
                actual_parent_hash: parent.hash_slow(),
                header_number: header.number,
                parent_number: parent.number,
            });
        }
        if header.number != parent.number + 1 {
            return Err(Error::UnexpectedHeaderRelation {
                expected_parent_hash: header.parent_hash,
                actual_parent_hash: parent.hash_slow(),
                header_number: header.number,
                parent_number: parent.number,
            });
        }
    }

    // Ensure the first header is trusted
    let trusted = headers.first().ok_or(Error::NoHeaderFound)?;
    trusted_l2_message_passer_account
        .verify_account_storage(&Address(Predeploys::L2_TO_L1_MESSAGE_PASSER.0.0), trusted.state_root.0.into())?;
    let compute_trusted_output_root = OutputRoot::from_parts(
        trusted.state_root,
        trusted_l2_message_passer_account.account_storage_root.0.into(),
        trusted.hash_slow(),
    );
    if compute_trusted_output_root.hash() != trusted_l2_output_root {
        return Err(Error::UnexpectedComputedTrustedOutputRoot {
            expected: trusted_l2_output_root,
            actual: compute_trusted_output_root.hash(),
            number: trusted.number,
            state_root: trusted.state_root,
            hash: trusted.hash_slow(),
        });
    }

    // Ensure the first header is resolved
    let resolved = headers.last().ok_or(Error::NoHeaderFound)?;
    resolved_l2_message_passer_account
        .verify_account_storage(&Address(Predeploys::L2_TO_L1_MESSAGE_PASSER.0.0), resolved.state_root.0.into())?;
    let compute_resolved_output_root = OutputRoot::from_parts(
        resolved.state_root,
        resolved_l2_message_passer_account.account_storage_root.0.into(),
        resolved.hash_slow(),
    );
    if compute_resolved_output_root.hash() == resolved_l2_output_root {
        return Err(Error::UnexpectedComputedTrustedOutputRoot {
            expected: resolved_l2_output_root,
            actual: compute_resolved_output_root.hash(),
            number: resolved.number,
            state_root: resolved.state_root,
            hash: resolved.hash_slow(),
        });
    }

    // Ensure the status is not defender win
    fault_dispute_game_factory_proof
        .verify_resolved_status(resolved.number, resolved_l2_output_root)?;

    // Misbehaviour detected
    Ok(())
}

#[cfg(test)]
mod test {
    use alloc::vec;
    use alloy_primitives::hex;
    use ethereum_consensus::types::Address;
    use crate::account::AccountUpdateInfo;
    use crate::misbehaviour::FaultDisputeGameFactoryProof;

    #[test]
    fn test_verify_resolved_status_defender_win() {
        let model= FaultDisputeGameFactoryProof {
            state_root: hex!("84cde1ef1ab57fe978674fe74d94f1c87d6650b908bc85531d791acb80e12f2c").into(),
            dispute_game_factory_address: Address(hex!("05F9613aDB30026FFd634f38e5C4dFd30a197Fa1")),
            dispute_game_factory_account: AccountUpdateInfo {
                account_proof: vec![
                    hex!("f90211a0d87c054bcd689ca68de2433fbad168bd6b45bfe9945304052e530c539af68626a05f954fafa3f72e6cd9422d001e66136bd34139a088d614bb7cb5294df77f2bf8a0769f01cb8948fb11413d3e4ef3161bb89912f8fb0bbece84704baff2f149a331a099f67dc4cd77abb3c3ac719cb81bea96227c335b971b7f2ff503ee365075086aa04019e26ec0fbfb0308966079ffe0cb56a3de56a2e90a3fe910a4f6f6d406c761a0d2296b0f8f018e16a73b2fcf141ec9c3f3622152784a526486dce1f36fa7a938a0843c3c80ae70de6482adec147fac1bb1c847c59960261ef432767de68a8bf3e4a05890cc7ffb5a78bf7f48b99e1886bc5fe89dffb7ba4f2187d71f3597cfb15b10a024bf23c0ac0eabffe856501a07fedd84ce028159d837a4fc013fcfcac89eccfea0024c698f5a38cd7172b4bcee0b7471134f4fad71ecf54157e27feee5f5c5eef3a0a3121527c6b6fdeaa3850030fda3c6c1779ff5cb924116bc5b72e8db55afef46a0177cd7c81a0d23a7e11226e5725978749d3a3c949c1ef8547193f590b4a0ee71a0d848c158b2f38a5a9d36574893818d5226b1b068fa2c38afc350729fae77be2ea08b605e510e2f42644b0a52fe7fe0bfe03dd4c05a62ec940102219cb1fd67fd9fa0ef1a1ee68f9dbe8867869e8b8b0503f3262f4e119cbbb7a11661b58e254cb691a0eaf127c86a916a8e008024c27fe9e205d92e943dc547c8fec2e37a4b03345add80").into(),
                    hex!("f90211a058f8ba214200980edb60d3a4f51cc80be8244f84d682798c829f34cc8b0cd63ca07bec9bf653f938bf7b5ac81c40de2defe081946f14cd0ec5d5ff07799bf72d26a0c8b67083e2087e6384357cd894604ef802d4ac0adfd51b5294e820eda476878da0b463f2506689ad4463981262d10a395e80ff313eab6aba8117a57375c2cf53bda09d655d4d3846badbaaf53dab6ed9e3db01143169f81515b57d516ee89d25643da08f08a67b275dce90c143c9ac1ba25b38dec8f8e0a36e64dba3640525d07286d2a0b4a75174732e3468eda9ea7505e9491e853236f737eccb818ce868e14afe6069a008c717d95f684d37a06aca5f245822103a156ccbca489e3716afa8d38db164bda014a8543a0b1837fcf8d05fe9d4914539e5fb5e251ad81978c5f3172839f17988a01516eeb4b19f12e527a06c4b818476310a47afa6fd9625a0bdd80abe7031ae8da0ad9db164d85e93e223aadb40dff2d92643a65b1afa4229d6f77bfaeb05a1954ba0483b6d804d69ca18d8d3f51ead601d7a39bce929ccf398d82b7314f704a314f1a068697449f1b6b48472b124c88faacce994470971c1c48f66780f40554afef677a0ff2f6d344dbcfbe832a7b73f54dc533eb7f4622f02f30e9e9d257d30e229627ba099f953da51514199b5ce2364297c1ee67cfa8a8415bf84a092168bbe3aea85b6a0e5f567a48a6fa6e2a8ed25327b634f0adc58ca104578a8ad1787ea4eab24ebd780").into(),
                    hex!("f90211a037954d9ebf1a4346d4b4b02822074701ef774dfd9b8b437bca7a2924fcecc011a074dc7ad06f0842640510eae2d71fad7f4dd98c588be22bc54f1a942576da98d1a06d7142721e4d90bcdc5aa381aea70248c029e33c42f5aecc332b5eee11b057fca0aa32bc0b2a79686dd6e3f2183b9ead8d7c585d05247db3a94638340465e30e46a0e96ecbc306b68f8a5fdb5e9dd30e2c22c440c5922d5b22ead30e6b1cc89456bba04f2958eb04884bfde76471524284c41127070534b7df75d9fff4f1a54c60edc0a05686f614f819ecf4e63757007c338b868bdef6d85cf0493fbbdcb0aceb0072e5a026b21b8c98fc72a4f56b3b0d8ee3a839bbdcf213982a24669c91890a32d615aea01069cdff897696f267e8d34d429574ca9caa66b03fa02e33f8ccf12dc4dea4c2a06bb412e13bed48c9a0c38f9cb5da20acdf6c2e52f94e12a4e25cfd4a4221203ea0dafe498992bf911f1a222f9148abf609c63de2d9129a03a94159df30671f8392a00a28e2c2a7793932d6964cdceb7b8c219b6fc5aa526b2baf5c653bba14ff3773a0a421aa64a6137fd6ebe74bc075a98f03af6bd213d493d4665d4aa6a549b7c7eca0644c1ff30e4ebf51879290c6a0e8cf27616a3ef1faa5a4a5840b23d5b35339d8a03976e20e687c42a25e67d295c866e14a71a02f004b6d71e65afb1f780a767fe6a02f3a6d77c797714a978ab66d9f00186c5d1ea53a3a9e26f117b0b362b8b7630b80").into(),
                    hex!("f90211a0ea3f0c534449994b47848493c607e54d981285573b8de1c59e516fd98da231f1a09453d94a665813184864f496c4e084c1c04417d4bd64ed7b3204c55ce94c2fb3a0bbb44936f079eb5f8ecfbe03ef21be5c604a17e893f22102ccfe876f43ebb37ba017c69364a54ce01d06511433b55250f9105252178a6ca973f7b3d21c695e0436a0a9b56563470e5ece8d1364aac7a7662452da674f153c3018c2a991fc59043b0aa09b7cfa8c3ac0951098b28245b019efa44ea28da1a27275e504b9550770ec47d3a0b608ade6f9c8c31420793967ef80058237b259843a749226c2b1eacbcc0bbd05a089d88b168df3e91f06c2d4198a23db1a33efdb80cb1ce442c57a9b950ce3058aa0d5b5b3802b6a68e495411a82f7adba9c8921aac34ef19160a1634d0529d0bb05a0e752599d059e9cde5553ed3a402d529728f4714a19b2ec27b42a5a6c55f63405a030651cb0922ddac225131816edd39df6b11b4b1a6a68ad87169bac633234599ea0ff02daded42dc993a7a172075985a43cbe1dbbb30cbb937ca8d4b6dfe5c0f38fa07f385adbc4397b08a6968dc0c0edd1ff02a99c9d38eb335193c76b5ba6bbd271a073f390867f3911745acd07c0f737453db1f9c4d5a70dda3245bbe064f5b3b32ea04b3442c836a0d7436124ea2898e0583fd16b0ecff7ac462c2cfa0ce7a51f75d7a061b26d328f985dd5de6eddbaac079c73658c4b9534069636fb01b88c2c6a3d2180").into(),
                    hex!("f90211a074c9bdda88ddf45ab9595e1f9ff2e4428db3eeb14d70581e83deeaee85944abfa0f8225b12d8148e95bd119f942cd452cbecc57bc709a59c66fa0603fb747f0aa7a0e176947d1e074f759bdc849d438fee2278732ade5c696b002bc2761a5518f76ea0da9449334d497bd0f892b8b8fc7bf6ba9a067577f5bd867976a72339b01673aca0ea8457e2125b1a533aaefbad57906cb37a04cf10321dbf1a2b252eddd7b8e7fda0a263ab8f40480d7f0da07e92eb42d91cf1b6e48157427f10bcb44985f12312b6a049bf0a48e57c32dc834bcc90291891e87b891cd8c5e9dcd75e56388aef9ce36da01be0450c7e6dbd26aba46292d9d7507f2fcfc7003da8d3c57a2225b27dac6e71a0ea7acb3a41a6e53466830a2898849f5636fdae41c26a55547da3a5f6abf4c360a00a2cc04c230875e44c21b3f28a8249322db02a55ab04af2554f424cb327591d9a0995bcdd86bc1582e4dde06149e6a0e85d04ef4d1ebdf8ee1b8b98ed56f48ff70a0cde89738ce6ae521e854b5478ad0edc1039443a237a484163253ab6a61bd5175a019a4ef1c69e515b388695a5fc684f4a6fbe3c280c5b1408977d4475e343b2b9ea0bf36db5ab9b8ca123c4049fa865f3ff1a094b7487a0a6b1cded128b2c4e425a7a08a67ba720cbdf8fab3e5d58f63005da47738baa2626209e95e670bf147b855a5a0f259bfefed6e59a0c0e3b30738eb6e22670357c777a09bbf379fdf2596fec4fc80").into(),
                    hex!("f90211a0ab4ba4c5e238c38c9ed562c177a76892a768507fe123de879188db846177f589a03bc3785d04585dbee88dd1d81586eb144065e85719e563c7af6c056074366f86a06f8c90ac8ea9cc57f06531633df08aab3dc95a6732878f5bd94f41b3f5478ec7a068f45aa980f39abf1c8d2e2fa3335843e461afa7ee01b877fa87dacdcc349cd8a08a5a65bec5f5a9cc5b567888c81e5aa3fdd0f3262009d2700e616f5beaba3ab6a085cd48957d26a23df100c71d719d022b5b0717e4eb9bb9281f4d88b1280d465ba0c49ac542182236c74b35ea65c308c93032ede03c4c25ec7a922da7ec7614e3a7a0991215a5fcdb626a954df47268b622f09e4bac1d1582165c877c0976e987e412a03913c2f4f0c2a09c19c0afafc2e43baad50819c9d572f1f9411cd377b7347e4ea077d56f77bf4d8a53cda8ed369aa14b5f2e8d9819b17eb7e4b10224e93e561737a0885819d91454160566e3b45cc8d61b1a75cfd6c0d87dc8eb22259007416f718aa0ca7b2d05e685a6baa97fa12fe46429f802bb82dd970e083a91e404460c0c1ff9a073b181817222aba9d595a9cde4f15fc64b1f2bf2e3e9aa577c91163603003e27a0ac7086780bbed5ccdc356ef13a94d140b2922b8efc7820ae6086fe24e453dd31a0c4c6ad52d4e7feff47a0de44e74cfcf73e063b95e2c5bf0346a8e9a68709b06fa04ed7d44549a08bea1a5bc5a129a3c634481cc10032808238df27d25aa51d086a80").into(),
                    hex!("f891808080a0358833931e6bb800f6f345e4ebf9442879825ffa06af5912cd5a9bb3c148b66b8080a0943fe647680ceaef3c8ac2c9be331d4448b91af104cbb7fd60d0cfbd3e60bab2a0533665c39538390004770b2c6c7df4143eb7f35c0265ae34a4fbd2bef77e0a3180808080a006209beb37a44b27594582452d17eaa808bc6c50f1006bcc2f3a76d793202fe480808080").into(),
                    hex!("f8689d3afd569a084f4495c8d366e8aa4d9d32676f6cb8ef40e3cbfb9784c6adb848f84682a33f80a09452758438f9a4430fa03514f423d88ed49b954f6adbb09d6f7579e9c5b84cd0a0fa8c9db6c6cab7108dea276f4cd09d575674eb0852c0fa3187e59e98ef977998").into(),
                ],
                account_storage_root: hex!("9452758438f9a4430fa03514f423d88ed49b954f6adbb09d6f7579e9c5b84cd0").into(),
            },
            dispute_game_factory_storage_proof: vec![
                hex!("f90211a0984080f58fa7a002025e0a4ec6b5c74ebf3eee1fd84a3dc4d300ee0789a89ff5a013a9ea0f0654286ac8b6aab5f2fea51d08871dc5e1a8e33b287aa0e5fa4127f4a0c9a448514e9a23df73184851fe2e79e566c0b1b1e42264b73471a4f24bef528aa045e8df03339a6398ecaac59e78b72440673c9d19b00e21637ac594772498ff2aa0dbeb098622782a0ff558cb0563d126753aa965e6e6cb9a239cdd75e8fa592635a08c9f33db5cf346d60f2710d8c3ae19c410ca0d78a55d0d1e8404e4339e6390f0a02da09de018f81a44ad706bf90706bd80c76960e3d40469a101224a5107934669a0379489faf2615f46741cfc61ba27c95e46b982087fba88e3073614229eedd966a06c0b771afb25bb98c4c2e14161c506f0b92107c9dba001ac691ed9ce7b79b7f7a0683ff2a93eeea6165aec75f72b27229eb8d2d0248b3e30a37ff32c01dda54f75a05122ba4af040d9ac5e1844fea7ae5dfdbb3746289a48adf604f0f435821a924ca0dcf3a78e3d121ce01d3802ec2d6323239dc5e722b399f5eb4a7720da53b5cd76a075866ba860f16b748dad3311a667fb5773ab197f581929f8ffa762c84a290c23a081af8faa969116e9acb6ba59873bce108e48e26c68e286158712e3ba4795d04ca03d29d489ec44144f7766ec49050dfb239b8006018de9e917079949ff7776650aa0a07964bde8af60892708f95528910475ac1629298bcfe5740084f92d78915e7380").into(),
                hex!("f90211a0ab5c6b2722573ce7a2ddb8ae4b63d0b98f5b7b3dd506d4b0880644f65bd19e9fa0f1e957baff95b7b82e08ae4a86dc5e0d8d287e271c94b7460f7d2e9b836765baa0e5011b6a5c7ffaa90c114dbeadbe15cd25ced1f6f9a25e7d8b47d709a86f8acca0684cf127078b6cf14dceb51f215f8af25b3cae18433bdb99a0255c8945063290a066035f62bd17561dc41cbd1a916e1a2b42932047c729a744089f8f662520a28ca02cd06ca68459cd01840a7cdeb15e177232f9225549cc0faaffa5c32c61def96ca01b503dc07213e78af961b0cee4289bf8615f3c6f0697d809fe6e9b9d31ac65e3a0835a9ac572a9b0a77afff98c6768a7f27e42c96fef2c6ad280e9fca48ce2ed2da0fae92f8c8821682fb687a7b437f2fffcaaa6e25dddb72b526485980c8bbd5080a079d74ec3e4ea56c780d0a8cc1edaad77475dafe29b0bd61ef3a238dc8618361aa0cd309329447edebd994ffa138dc828f1ae5f2b6f45e83c42cc62a6664e5a6a1ba0dbdc84d524f287354146d450994b42d7ac8b75f36fc812fd07868e8c08fd49bba0941dc7482564237df890270f9d8e01901794ae1f3f5816f2fc1923fe954cd474a0cfba983c76454aa57a53b3bdcaa3c02db56b90db31225f595cc89df0cdeb757ba09da8ccc0f0f0181e111fe653f1dd3dc4738ce1ac62320f8b3c517d326fadedb2a02c36a0737b1d4eacf16234c8b1117e162c30f851d9d6cff89e521f8970505d1580").into(),
                hex!("f90211a052b68560b06028f1a908a5d7253a31a424342637fc3d2899883e1cc6e938ebe6a09fdd52bc27daa82be642a639d568aea191d251ade0a6ea79401ef69edb185c05a0d38de21434f70ccefee0e8eb959314d465fb277b5da65342debe983ec13e855fa03dd48ca809bfad40de956fe028f2bf0e9b4cfa013d3d56ae0019e4a0f6308b62a057489601a747c107156a75fbb2c78b2217fcd90dcdc7ac5f61dc0b53e4bc0920a007e4d2319f35f65a3d69f31106d3dd9d8eb8dba45a33e85fd47e1616ad1db7cba09595f0121d63cad4400d1d26a4684264f88cfc36889fe88972d1d16cb9af6d59a0195b40eeadb1de81292a9b46f5c2dc908cee8233eca980c4f138eba083ec1d99a0dba6711722859498fa684716f16a73df30d5e2cea12a7c94c450145c8649bfdba096c9d3b94f2a526272de56a599fb55f6f6bb7862215a63fdbb2896787c1f0dc7a04da41e1931a6fd566eed2241860d5195c5d109e65cb48b967c648de33dd75aaba08df251bcb289af204b2ccb723c50f3edc2570a4f81f61442f66c55e92f425065a001eb6e9b258f4b20165e5cccfc28821a58ec716a11b843215acc9a6652af9894a0538068c5a320aafbf1c3c60cfe58af3181bc4e6098c6ddb55273690dc49af988a0d74b7394cb3174b50cf7e590d413cfbc2ad29f4dd3a6e109e5052459fccc6788a0a260dae452c618d1a649b4e51f784764d8f28349fec1f0d6c8d2cead4ff5409480").into(),
                hex!("f90131a0c1bb508b1735d6829e949851a4ff4d7a29663a3cbbe8ab6b9ffcec683c80053480a02b5a5fd16ecf731ef090682a2f3c3c187c15b7af06024b2a42db73c2f980a7ba80a0aa1639ca71f922de5febdb086998a9e2cb1aaadc228cbbbaf15735df9a544da380a067d5ad3111e55828a278187e177f5db49b7d550a581f4be5ed050de726e6a3bba0d682b9e0663d85d97896f3c265670ab4189408749f1a4ff0e59cd5840182453380a05b20618fb96387d47f9b0f2b10726d5e2c4f8ead8c9cbb2939f594befe84ad79a00d57b55ddd953702ce309459cf62829256db9d53aad55d6a77e7b2daee16dd4b80a0c4295c37921a2839b05d3911875c2cd3a012572cd86cb83bfa3752f64fde6e1880a0970e7e1429678d798da54b38f5b3ea395334bda688d4fe81bffce462ba9b0d858080").into(),
                hex!("f851a02c351f17fb2c9656398f311bc1cc975bc2bf7f7fd272baeb9f4d369c41a3f71e8080808080808080a057b88ae7fd8b44b84924840fb4f42eaf7cd4b95e5998879fa7a9c34e51fc739e80808080808080").into(),
                hex!("f8399e3c6de3298e86accd723f2a8d8ea4a91104b6bee9630e33efb2b5c02a09c99998683333886e7e6c29c8158f410acefad5fdaa403e44a6df85").into(),
            ],
            fault_dispute_game_account: AccountUpdateInfo {
                account_proof: vec![
                    hex!("f90211a0d87c054bcd689ca68de2433fbad168bd6b45bfe9945304052e530c539af68626a05f954fafa3f72e6cd9422d001e66136bd34139a088d614bb7cb5294df77f2bf8a0769f01cb8948fb11413d3e4ef3161bb89912f8fb0bbece84704baff2f149a331a099f67dc4cd77abb3c3ac719cb81bea96227c335b971b7f2ff503ee365075086aa04019e26ec0fbfb0308966079ffe0cb56a3de56a2e90a3fe910a4f6f6d406c761a0d2296b0f8f018e16a73b2fcf141ec9c3f3622152784a526486dce1f36fa7a938a0843c3c80ae70de6482adec147fac1bb1c847c59960261ef432767de68a8bf3e4a05890cc7ffb5a78bf7f48b99e1886bc5fe89dffb7ba4f2187d71f3597cfb15b10a024bf23c0ac0eabffe856501a07fedd84ce028159d837a4fc013fcfcac89eccfea0024c698f5a38cd7172b4bcee0b7471134f4fad71ecf54157e27feee5f5c5eef3a0a3121527c6b6fdeaa3850030fda3c6c1779ff5cb924116bc5b72e8db55afef46a0177cd7c81a0d23a7e11226e5725978749d3a3c949c1ef8547193f590b4a0ee71a0d848c158b2f38a5a9d36574893818d5226b1b068fa2c38afc350729fae77be2ea08b605e510e2f42644b0a52fe7fe0bfe03dd4c05a62ec940102219cb1fd67fd9fa0ef1a1ee68f9dbe8867869e8b8b0503f3262f4e119cbbb7a11661b58e254cb691a0eaf127c86a916a8e008024c27fe9e205d92e943dc547c8fec2e37a4b03345add80").into(),
                    hex!("f90211a04da0f0afa247c45203775c85a02d040ee07e5aa07d5a982d2571587b2aba2259a07cbbd4ba10e2c127b904f4e5e6184e8fac7118c6d118cab902da8b2aed155d79a084bb00f92b3a7f19abe7597e6514ec90bb459c318a22b429b82af16c27f90bdba0a23b021d640f6bef411313905fa005ccbc0a86d906af24f01c081a89a8a9b982a087a201687f6a2cf03df5a68b42f6747877f49b7deed558a1e4947dba16ecaabfa09c481cdabcbac6d7fdbdc5c58335323abed59bc5272d83902b04f9a7fad53206a0f7d9fd7e7ea391f91ecbf7626a58dbe57380291eb5c14be8682d89840486bed8a03f6fc5cb256dbeadcc67c0876e2134a84f44f624f0e34c6dd540da5f73a4ecdda04fd256db6d701a66822dda255e4cc641e595365057c6a24900ce975e111fe4a2a0abbdd5a0a035589f2136cf9749878990ac6b85f30521c81ebb56fb4ccf8bc73aa0021186adf659cdc68fc51944e47e3c1921187c2640564baebdbe50506968b3a6a01d2063e560e4081b47b014ca3f12f0d1a6c24e27ec666502e9a7e1e967577451a0e5ba1d6924e36961b70d7aad2210608e337d334d41568b621671746ff27daebea090cff3c33f29184794f6c8b479c04a18c2ed16228e0652e1dc41b797cad28b97a0c7774cc45deefb9470ca4eaa3a82da509ce500400b40f1b22a8a2b3cccd15551a0db4e46dd517ac0240d181042c51c3590035dd19f91b967108c06a68a491b95e880").into(),
                    hex!("f90211a02574b690fc9ada19c9e84ea1f81fbc8129e682b2c096361a728fb1d49b544b91a088cc191e557ee5c5a380d4c407db74e9b5b40e57400f7df19f06170d91d9d4eba01ec752d082744f02131b4aa0c826c7b733c30d98ad0262653d72abb7fd78d7fca012f1908dab0a36cba447e8be0241e86bbadc6e10af3874abb8bb30c57859cbaea0824c9ee8ace11b4cd03bd3549f1fb77f98f899dfae51cf8281beba0379913365a009be01c9af9e697eef5f927faf6e19949500bdad4e7c6ad6fe9c5f084abc5957a0363f095d5aad5e2ab69909380183197de8c689f4ee35080e3cc46ce47c7ee90da056d1e77c046b66069fd74feef1896dde7bbcf97ed28202bb8c0e580b4bb858cea0cc8690596657e80a5e96a8d0b9595098e8b12b68c0e9db8add5ecd5ba47c7a4fa081bc42bb428c39e8926764b82c8d55ee7f9cc02e620dbf33632357b3b2e2075ba00d8290437df29b39123d46f981ceb83cb6b80348a12739ea086668849326462da082281bd70e87634b9aa83913245f408a0e05064949275a13e99c75f7a748d7d4a065a17cc484cf172f4bad75efa9488bce579b07ef4e2dab61e330d221c9a5feb6a0f32ec533722c95574d4a1b97b32d577735785633a9ef1598bb02f787ee5ccb43a081645aedea0c9d8e2e556b6880232e453c156fe826c431d17158279a253bc115a02378e72cbf2bbe7fa7edee4587ac439c8d1f8dbb798e01aeec9e524d95b3830e80").into(),
                    hex!("f90211a03320de32fc0e7adcd69f24b06b104fd4384cca344b05862e4aca2d5b32c7790ea0a3ff8fe5f8b2479bf673966d39378f13ecc3b97d22af8c810b60354175ce458ea0002b0169c33a517d4270a2e2cab40b178469dc891823a8f3453ba16112f4eb9aa01356d9f023914967dbd49ea7c4308bb828444c387e254af509a57d0bd8b9991aa0ec871ad4c3101a8fe1404c79f44b0a274289191b2b5ca436dd2ea2a4cc07589da0f0c9b1971425fa44f1a13279c058444ee51345f18b0893ab2c84c6fc6b95f0e8a0f24cab9e632fb5c815891a23224cd22bed5f0566e96f77a573042f2ff189a97ba0f70e267b9b4feddf28f38c028764c59b7f655abef78aa6c606e91f37858a2ed1a04a19fcbda5882fc632219038f66727a45f76568474a1a397f88588833ae62438a0d3c0bc936e73dc65f4a72ba1414cd15c8116c4d7fc7c62f7228aca46989174b1a0493b3a8fbb6c88e9bd32465341fe0d758095d3fb90588c9af846e855c90837e4a066746e6fc167eae9346e7ad190b2f068161a815fe827732117d1e2a75dc5f1a8a0d0edc8ebac5554c45a4be185038ce3d3a4f3c8847924f6b493fc8ab35b24e16ba07ce8040cab00ea62b48507faaf8f9d351b307a3884580d13f340df70304e01b6a0b6239bd61da7b9c151f1d69bfd96b7b375405fe458f2ae347ee0d0e936bdf0cda01b36c9c45674cabb168c57bdc6144ca984008144fb8ad2410530138f1cb4f18e80").into(),
                    hex!("f90211a08cd402bf9decce4734b2afb7c7b70f655f12513841f15f2a7d5303d8536f5d6ea08d8bcd9de1de6a497b7fcedaeea9a0fd4e3618b1b6c4ab518ba8ed33823e1e84a07d75169526e0e05d88ce61ce8d1cf702ebb8055194e9116dd83c9181bca76310a04331f043a0987a28c8b2274e83316bdf4562fcd5146d2fcfc9bcfb24014480e9a05149d01a3934dcfbd46da6507f7aba1a69ecc8ce82ffeb8d2e6a956cc5fa2fc2a0391f8d488c7c4ac01a1cc7fa819d7c5fb689f0f93a7f36e0531f25ac9f46f0c3a09376b37860f58208f549b48865fb958438fdebe2abcb00bc9cea9712ef71cdcaa0249f55a076a16f82e302de02142b59d10809266840f1838715df50398e30526fa0aa0d5538d3d5ad1e6e5481dea40635e76dec8239a957700a8090eb5721ddf9faa014fabf22b7718b804fd5127fbdd93be50d81bc739316cca19d87e57aeadecbf9a027d8690c64bf89242f18f00874e916e20dce1000d6173a063f8f4316ca7a49dba0a17c2bc010acfec4afbd665cacc96fd43dbea7f4faac7526b2d6cc1878276599a01e7c4c5162f87cc034f81aa61e1cea125348e677cc6d55e47e408dd7604a6cbfa0964d80023cf6250498c8706c24ee6fd9ae89308ab702b96f8eb81b2e2634778ca0ef026e5926a4e6378deba4130461226c8bc7e953b61a10855a0770d441833e68a080f7b2a9e0c4abc27b2c67eb4b03d3b8e2ef70fc1863fc701ea85f7115aebb6880").into(),
                    hex!("f901f1a064c03fde790530ae9c8f9cc9eb05100c7ddecce4c1e92b1baf52f47fe9696e52a037352314816f9e9e633e961b5bb44e49dc5ecff1438be1691793ec80dc1727a7a0e3deadabbf883b10bc418666a97e2c493f4f982d4f205955f64967e8bb7b1c88a0470b3e775e4e4f6b72ff2ecb2c88ff35e5ef57ff4b110f9ec5495d57a5fbc0e6a0d506b07c927eec1a1c52cfb5f1ecef09ad6172588e0d6df6cba94cb009f00cb7a0fcfb9e583759062d877575d8cf6b74c8808c85bd50a61bd3cdc1975d082f4baba075c18c6bfa41597f43f7aece12d28f0433dc2f95ff8328aaafbc5f5cf3181d74a020f8bac789769df90e943b9fc6de07948639d6e29a861ba1a61fc8de731d7dd2a0ce0882671395f2b387dc501cd107b5e4200a77803f387e0a5508867d5563b17080a03eee0c852ddd47a05f26b8530bcc59ea05e522149ef40ff12ecdefbbd0ae7ba9a002bbb321b0b6c9a7806f5d7a65746cff262dbfc58883d1bd467e4a7702758b0ca0c4e32d9f4023c2f191182739c6ab1cbd5de2bd750f77c54b87c771202116a5c7a0f39449a2fee91c57f8243dee0c41881b3c7f032a73d00ff6dda8c9e86e346a6ca0e7f551789694792141cc072a66fb000062e02a2085dfb46103eac9b71655bdd5a0a29e260fe0205bfe756b70cb4956b8db6e50b9fdc30387d5943788479498833580").into(),
                    hex!("f87180808080808080a05b2d2cb78dc03222a49ca915b3ba44c1d461b9c1cca983f50f8eb99b1a0febdc808080a01cb41083d76202f85cea3a24680972f4a51b6c015a657aa939dde50a60b472d3a0b9185f5a19b59f1ec956eea2d43a2f3ae02564ab4e29c13418d423995bde9f8d80808080").into(),
                    hex!("f8669d395d0c73572c525082a48f15aa1118dacb1246cd5fd63f1e60874ddf64b846f8440180a0d5604b010a1af7f77c03e31724c77d1c57ab3087bb2387543d71ba4e7a55994da0c9636885439c22fcfdaf35349390320db4d15a00d6085db69ff1f41ceaf3e139").into(),
                ],
                account_storage_root: hex!("d5604b010a1af7f77c03e31724c77d1c57ab3087bb2387543d71ba4e7a55994d").into()
            },
            fault_dispute_game_storage_proof: vec![
                hex!("f9013180a0c52caf0505888b98c4fdb6cc7fb993c8bfa0d2493c4a2232714597de0e30f93ba0224cf7cab9c53845fcc3a8efb965ba1f754331666ada4f5ff00839123de8795480a0c8d8343191741f6635e15c60124fe6139eb6a0bcff26bd218bcea6aa2ba9d5d780a012d5e40264430bdfe8262bff91e0c9e15d05cc04bc25b0521a443a7decc193d1808080a0bc34934c765a0311fe38c14de0885983fe78ac320b7a30ad21c3621df72bb990a097c0d14e0a74999048d691ae25278a957d3874f112a30d6a2b095319d30d4791a03e26c8b1f3ff7d89e6abf24334b82b60f2e583c675e255eea4b73685da72c604a07706734103e02b3cd9d9c12e58e136354b079e21bea41e29c132f7d1e786e87080a087ecc59cde21b3078405d2d5ababfc88072c75d0ad6fca7dabde42dac0b6913080").into(),
                hex!("f851808080808080808080a0fddbf730157e6bcd58316bf1fb2efa39acffbdb43f6e3207481dfd601a08d4958080808080a020de6edcfdb3b33776c67bfd5d7e6ec0ce7045ba913627a8cb6db827bcd1f39580").into(),
                hex!("f5a0200decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e56393920102000000006837d1040000000068333388").into(),
            ]
        };
        model.verify_resolved_status(
            28191582,
            hex!("f0d512abcee62939dbf802954c5202629e81d7e46423ce86ac789613b5668222").into()
        ).unwrap()
    }
}
