use alloy_primitives::keccak256;
use ethereum_ibc::consensus::types::H256;

pub(crate) use ethereum_ibc::commitment::decode_eip1184_rlp_proof;

pub fn calculate_ibc_commitment_storage_location(ibc_commitments_slot: &H256, path: &str) -> H256 {
    keccak256(
        &[
            keccak256(path.as_bytes()).as_slice(),
            ibc_commitments_slot.as_bytes(),
        ]
        .concat(),
    )
    .0
    .into()
}
