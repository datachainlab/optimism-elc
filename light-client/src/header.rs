use crate::errors::Error;
use crate::l1::L1Header;
use crate::oracle::MemoryOracleClient;
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloy_primitives::B256;
use ethereum_ibc::types::AccountUpdateInfo;
use light_client::types::{Any, Height, Time};
use maili_genesis::RollupConfig;
use optimism_derivation::derivation::Derivation;
use optimism_derivation::types::Preimages;
use optimism_ibc_proto::google::protobuf::Any as IBCAny;
use optimism_ibc_proto::ibc::lightclients::optimism::v1::Header as RawHeader;
use prost::Message;

pub const OPTIMISM_HEADER_TYPE_URL: &str = "/ibc.lightclients.optimism.v1.Header";

pub struct VerifyResult {
    pub l2_header: alloy_consensus::Header,
    pub l2_output_root: B256,
}

#[derive(Clone, Debug)]
pub struct Header<const L1_SYNC_COMMITTEE_SIZE: usize> {
    trusted_height: Height,
    l1_header: L1Header<L1_SYNC_COMMITTEE_SIZE>,
    derivation: Option<Derivation>,
    account_update: Option<AccountUpdateInfo>,
    oracle: MemoryOracleClient,
}

impl<const L1_SYNC_COMMITTEE_SIZE: usize> Header<L1_SYNC_COMMITTEE_SIZE> {
    pub fn verify(
        &self,
        chain_id: u64,
        trusted_output_root: B256,
        rollup_config: &RollupConfig,
    ) -> Result<(alloy_consensus::Header, B256), Error> {
        let derivation = self
            .derivation
            .as_ref()
            .ok_or(Error::UnexpectedEmptyDerivations)?;

        // Ensure trusted
        if derivation.agreed_l2_output_root != trusted_output_root {
            return Err(Error::UnexpectedTrustedOutputRoot(
                derivation.agreed_l2_output_root,
                trusted_output_root,
            ));
        }

        // Ensure honest derivation
        let header = derivation
            .verify(chain_id, rollup_config, self.oracle.clone())
            .map_err(Error::DerivationError)?;
        Ok((header, derivation.l2_output_root.clone()))
    }

    pub fn l1_header(&self) -> &L1Header<L1_SYNC_COMMITTEE_SIZE> {
        &self.l1_header
    }

    pub fn trusted_height(&self) -> Height {
        self.trusted_height
    }

    pub fn account_update_ref(&self) -> &Option<AccountUpdateInfo> {
        &self.account_update
    }

    pub fn is_empty_derivation(&self) -> bool {
        self.derivation.is_none()
    }
}

impl<const L1_SYNC_COMMITTEE_SIZE: usize> TryFrom<RawHeader> for Header<L1_SYNC_COMMITTEE_SIZE> {
    type Error = Error;

    fn try_from(header: RawHeader) -> Result<Self, Self::Error> {
        let l1_header: L1Header<L1_SYNC_COMMITTEE_SIZE> =
            header.l1_head.ok_or(Error::MissingL1Head)?.try_into()?;

        let derivation = match header.derivation {
            Some(derivation) => {
                let l1_head_hash = B256::from(&l1_header.execution_update.block_hash.0);
                Some(Derivation::new(
                    l1_head_hash,
                    B256::try_from(derivation.agreed_l2_head_hash.as_slice())
                        .map_err(Error::UnexpectedAgreedL2HeadHash)?,
                    B256::try_from(derivation.l2_output_root.as_slice())
                        .map_err(Error::UnexpectedL2OutputRoot)?,
                    derivation.l2_block_number,
                ))
            }
            // L1 update
            None => None,
        };

        let preimages = match derivation {
            None => Preimages {
                preimages: Vec::new(),
            },
            Some(_) => {
                Preimages::decode(header.preimages.as_slice()).map_err(Error::ProtoDecodeError)?
            }
        };
        let account_update_info = match derivation {
            None => None,
            Some(_) => Some(
                header
                    .account_update
                    .ok_or(Error::MissingAccountUpdate)?
                    .try_into()
                    .map_err(Error::L1IBCError)?,
            ),
        };
        let oracle: MemoryOracleClient = preimages.preimages.try_into()?;
        let trusted_height = header.trusted_height.ok_or(Error::MissingTrustedHeight)?;
        Ok(Self {
            l1_header,
            trusted_height: Height::new(
                trusted_height.revision_number,
                trusted_height.revision_height,
            ),
            account_update: account_update_info,
            derivation,
            oracle,
        })
    }
}

impl<const L1_SYNC_COMMITTEE_SIZE: usize> TryFrom<IBCAny> for Header<L1_SYNC_COMMITTEE_SIZE> {
    type Error = Error;

    fn try_from(any: IBCAny) -> Result<Header<L1_SYNC_COMMITTEE_SIZE>, Self::Error> {
        if any.type_url != OPTIMISM_HEADER_TYPE_URL {
            return Err(Error::UnknownHeaderType(any.type_url));
        }
        let raw = RawHeader::decode(any.value.as_slice()).map_err(Error::ProtoDecodeError)?;
        raw.try_into()
    }
}

impl<const L1_SYNC_COMMITTEE_SIZE: usize> TryFrom<Any> for Header<L1_SYNC_COMMITTEE_SIZE> {
    type Error = Error;

    fn try_from(any: Any) -> Result<Self, Self::Error> {
        IBCAny::from(any).try_into()
    }
}
