use alloc::vec::Vec;
use core::hash::Hash;
use alloy_consensus::Header;
use alloy_primitives::{keccak256, Sealable, B256};
use alloy_primitives::private::alloy_rlp::Decodable;
use ethereum_consensus::types::Address;
use ethereum_light_client_verifier::execution::ExecutionVerifier;
use kona_protocol::OutputRoot;
use crate::account::AccountUpdateInfo;
use crate::errors::Error;

/// Confirmed slot of DisputeGameFactoryProxy contract by forge
const DISPUTE_FACTORY_STORAGE_SLOT: u64 = 103;

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
    B256::from_slice(&slot_hash)
}

fn calc_game_uuid(l2_block_num: u64, output_root: B256) -> B256 {
    // Define constants
    // We can split this into words that are 32 bytes long to get:
    // 0000000000000000000000000000000000000000000000000000000000000060  // offset
    // 000000000000000000000000000000000000000000000000000000000000000b  // length
    // 48656c6c6f20576f726c64000000000000000000000000000000000000000000  // extra_data
    let source_game_type = B256::from_low_u64_be(0);
    // start position of extra_data length
    // 32 (gameType) + 32(rootClaim) + extraOffset(32)
    let extra_offset = B256::from_low_u64_be(96);
    let extra_len = B256::from_low_u64_be(l2_block_num.len() as u64);

    // Build the source array
    let mut source = Vec::new();
    source.extend_from_slice(source_game_type.as_bytes());
    source.extend_from_slice(output_root.0.as_slice());
    source.extend_from_slice(extra_offset.as_bytes());
    source.extend_from_slice(extra_len.as_bytes());
    source.extend_from_slice(l2_block_num.to_be_bytes());

    // Calculate and return the Keccak256 hash
    B256::from_slice(&keccak256(&source))
}

fn unpack_game_id(game_id: [u8; 32]) -> (Vec<u8>, Vec<u8>, [u8; 20]) {
    let game_type = game_id[0..4].to_vec();
    let timestamp = game_id[4..12].to_vec();
    let mut game_proxy = [0u8; 20];
    game_proxy.copy_from_slice(&game_id[12..32]);
    (game_type, timestamp, game_proxy)
}

struct FaultDisputeGameFactoryProof {
    state_root: B256,
    dispute_game_factory_address: Address,
    dispute_game_factory_account: AccountUpdateInfo,
    dispute_game_factory_storage_proof: Vec<u8>,

    // For status is collect
    fault_dispute_game_account: AccountUpdateInfo,
    fault_dispute_game_storage_proof: AccountUpdateInfo,
}

impl FaultDisputeGameFactoryProof {

    pub fn verify(&self, claimed_l2_number: u64, claimed_output_root: B256) -> Result<(), Error>{
       self.dispute_game_factory_account.verify_account_storage(
           &self.dispute_game_factory_address,
           self.state_root.into()
        )?;

        let game_uuid = calc_game_uuid(claimed_l2_number, claimed_output_root);
        let key = calculate_mapping_slot_bytes(game_uuid.as_slice(), DISPUTE_FACTORY_STORAGE_SLOT);

        let execution_verifier = ExecutionVerifier;
        let game_id = execution_verifier
            .verify(
                self.dispute_game_factory_account.account_storage_root,
                key.as_slice(),
                &self.dispute_game_factory_storage_proof,
            )?.ok_or()?;

        let (game_type, timestamp, fault_dispute_game_address) = unpack_game_id(game_id);

        self.fault_dispute_game_account.verify_account_storage(
            &fault_dispute_game_address.into(),
            self.state_root.into()
        )?;

        let status_slot = 0;
        let execution_verifier = ExecutionVerifier;
        let packing_slot_zero= execution_verifier
            .verify(
                self.fault_dispute_game_account.account_storage_root,
                status_slot.as_slice(),
                &self.fault_dispute_game_storage_proof,
            )?.ok_or()?;

        // storage layout of forge is reverse position
        // created_at offset = 0, bytes = 8 -> [24:32]
        // resoled_at offset = 8, bytes = 8 -> [16:23]
        // status offset = 16, bytes = 1 -> [15]

        let stauts = packing_slot_zero[15];
        // Must be DIFFENDER_WIN
        if status == 2 {

        }


        Ok(())
    }
}

fn check_misbehaviour(
    agreed_l2_output_root: B256,
    agreed_l2_message_passer_storage_root: B256,
    resolved_l2_output_root: B256,
    resolved_l2_message_passer_storage_root: B256,
    trusted_to_resolved_l2: Vec<Vec<u8>>,
    trusted_l1_game_factory_proxy_storage_root: B256,
    trusted_l1_game_factory_proxy_storage_proof: Vec<u8>,
) -> Result<(), Error>{
    let mut headers : Vec<Header> = Vec::with_capacity(trusted_to_resolved_l2.len());
    for mut rlp in trusted_to_resolved_l2.into_iter() {
        let header = Header::decode(rlp.as_mut())?;
        headers.push(header);
    }

    // Ensure collect header relation
    for (index, header) in headers.iter().enumerate() {
        if index == headers.len() - 1 {
            break;
        }
        let parent = &headers[index + 1];
        if header.parent_hash != parent.hash_slow() {
           //TODO error
        }
    }

    // Ensure the first header is trusted
    let trusted = headers.first().ok_or("No headers found")?;
    let compute_trusted_output_root = OutputRoot::from_parts(trusted.state_root, agreed_l2_message_passer_storage_root, trusted.hash_slow());
    if compute_trusted_output_root.hash () != agreed_l2_output_root {
        //TODO error
    }

    let resolved = headers.last().ok_or("No headers found")?;
    let compute_resolved_output_root = OutputRoot::from_parts(resolved.state_root, resolved_l2_message_passer_storage_root, resolved.hash_slow());
    if compute_resolved_output_root.hash() != resolved_l2_output_root {
        // Misbehaviour detected
        return Ok(())
    }
    // Ensure resolved_output surely in the DisputeGameFactoryProxy
    // TODO check the storage proof

    // Not misbehaviour
    return Err("Output root mismatch");

}