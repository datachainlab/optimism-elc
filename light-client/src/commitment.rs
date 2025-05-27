use crate::errors::Error;
use alloc::vec::Vec;
use alloy_primitives::keccak256;
use ethereum_consensus::types::H256;
use rlp::Rlp;

pub fn calculate_ibc_commitment_storage_location(ibc_commitments_slot: &H256, path: &str) -> H256 {
    keccak256(
        [
            keccak256(path.as_bytes()).as_slice(),
            ibc_commitments_slot.as_bytes(),
        ]
        .concat(),
    )
    .0
    .into()
}

/// decode rlp format `List<List>` to `Vec<List>`
pub fn decode_eip1184_rlp_proof(proof: Vec<u8>) -> Result<Vec<Vec<u8>>, Error> {
    let r = Rlp::new(&proof);
    if r.is_list() {
        Ok(r.into_iter()
            .map(|r| {
                let proof: Vec<Vec<u8>> = r.as_list().unwrap();
                rlp::encode_list::<Vec<u8>, Vec<u8>>(&proof).into()
            })
            .collect())
    } else {
        Err(Error::InvalidProofFormatError(
            "proof must be rlp list".into(),
        ))
    }
}
