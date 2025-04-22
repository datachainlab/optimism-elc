use crate::commitment::decode_eip1184_rlp_proof;
use crate::errors::Error;
use alloc::vec::Vec;
use ethereum_consensus::types::H256;
use optimism_ibc_proto::ibc::lightclients::optimism::v1::AccountUpdate as ProtoAccountUpdate;

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AccountUpdateInfo {
    pub account_proof: Vec<Vec<u8>>,
    pub account_storage_root: H256,
}

impl From<AccountUpdateInfo> for ProtoAccountUpdate {
    fn from(value: AccountUpdateInfo) -> Self {
        Self {
            account_proof: encode_account_proof(value.account_proof),
            account_storage_root: value.account_storage_root.as_bytes().to_vec(),
        }
    }
}

impl TryFrom<ProtoAccountUpdate> for AccountUpdateInfo {
    type Error = Error;
    fn try_from(value: ProtoAccountUpdate) -> Result<Self, Self::Error> {
        Ok(Self {
            account_proof: decode_eip1184_rlp_proof(value.account_proof)?,
            account_storage_root: H256::from_slice(&value.account_storage_root),
        })
    }
}

fn encode_account_proof(bz: Vec<Vec<u8>>) -> Vec<u8> {
    let proof: Vec<Vec<u8>> = bz.into_iter().map(|b| b.to_vec()).collect();
    let mut stream = rlp::RlpStream::new();
    stream.begin_list(proof.len());
    for p in proof.iter() {
        stream.append_raw(p, 1);
    }
    stream.out().freeze().into()
}
