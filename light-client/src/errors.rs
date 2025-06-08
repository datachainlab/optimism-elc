use crate::l1::L1Consensus;
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloy_primitives::private::alloy_rlp;
use alloy_primitives::B256;
use core::array::TryFromSliceError;
use ethereum_consensus::bls::PublicKey;
use ethereum_consensus::errors::{Error as L1ConsensusError, MerkleError};
use ethereum_consensus::sync_protocol::SyncCommitteePeriod;
use ethereum_consensus::types::{Address, H256};
use ethereum_light_client_verifier::errors::Error as L1VerifyError;
use light_client::types::{ClientId, Height, Time, TimeError};
use optimism_derivation::derivation::Derivation;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    // Preimage
    #[error("OracleClientError: err={0:?}")]
    OracleClientError(#[from] optimism_derivation::errors::Error),

    // data conversion error
    #[error("TimeError: err={0:?}")]
    TimeError(TimeError),
    #[error("ProtoDecodeError: err={0:?}")]
    ProtoDecodeError(prost::DecodeError),
    #[error("ProtoEncodeError: err={0:?}")]
    ProtoEncodeError(prost::EncodeError),
    #[error("UnknownHeaderType: type={0}")]
    UnknownHeaderType(String),
    #[error("UnknownClientStateType: type={0}")]
    UnknownClientStateType(String),
    #[error("UnknownConsensusStateType: type={0}")]
    UnknownConsensusStateType(String),
    #[error("UnexpectedClientType: type={0}")]
    UnexpectedClientType(String),

    // ClientState error
    #[error("MissingLatestHeight")]
    MissingLatestHeight,
    #[error("UnexpectedStoreAddress: err={0:?}")]
    UnexpectedStoreAddress(L1ConsensusError),
    #[error("UnexpectedCommitmentSlot: err={0:?}")]
    UnexpectedCommitmentSlot(TryFromSliceError),
    #[error("ClientFrozen: clientId={0}")]
    ClientFrozen(ClientId),
    #[error("UnexpectedProofHeight: proof_height={0} latest_height={1}")]
    UnexpectedProofHeight(Height, Height),
    #[error("MissingTrustedHeight")]
    MissingTrustedHeight,
    #[error("MissingTrustingPeriod")]
    MissingTrustingPeriod,
    #[error("NegativeMaxClockDrift")]
    NegativeMaxClockDrift,
    #[error("UnexpectedRollupConfig: err={0:?}")]
    UnexpectedRollupConfig(serde_json::Error),

    // ConsState error
    #[error("UnexpectedStorageRoot: proof_height={0} latest_height={1}")]
    UnexpectedStorageRoot(Height, Height),
    #[error("UnexpectedConsensusStorageRoot: err={0:?}")]
    UnexpectedConsensusStorageRoot(TryFromSliceError),
    #[error("UnexpectedOutputRoot: err={0:?}")]
    UnexpectedOutputRoot(TryFromSliceError),
    #[error("MissingTrustLevel")]
    MissingTrustLevel,
    #[error("MissingForkParameters")]
    MissingForkParameters,

    // Update
    #[error("MissingL1Config")]
    MissingL1Config,
    #[error("MissingForkSpec")]
    MissingForkSpec,
    #[error("MissingL1Head")]
    MissingL1Head,
    #[error("MissingL1ConsensusUpdate")]
    MissingL1ConsensusUpdate,
    #[error("MissingTrustedSyncCommittee")]
    MissingTrustedSyncCommittee,
    #[error("MissingL1ExecutionUpdate")]
    MissingL1ExecutionUpdate,
    #[error("MissingAccountUpdate")]
    MissingAccountUpdate,
    #[error("UnexpectedEmptyDerivations")]
    UnexpectedEmptyDerivations,
    #[error("UnexpectedTrustedOutputRoot: request={0:?} consensus={1:?}")]
    UnexpectedTrustedOutputRoot(B256, B256),
    #[error("UnexpectedAgreedL2HeadOutput: err={0:?}")]
    UnexpectedAgreedL2HeadOutput(TryFromSliceError),
    #[error("UnexpectedL2OutputRoot: err={0:?}")]
    UnexpectedL2OutputRoot(TryFromSliceError),
    #[error("AccountStorageRootMismatch: account_storage_root={0} storage_root={1} state_root={2} address={3} account_proof={4:?}")]
    AccountStorageRootMismatch(H256, H256, H256, String, Vec<String>),
    #[error("MPTVerificationError: err={0:?} state_root={1} address={2} proof={3:?}")]
    MPTVerificationError(
        ethereum_light_client_verifier::errors::Error,
        H256,
        String,
        Vec<String>,
    ),
    #[error("OutOfTrustingPeriod: current={0} deadline={1}")]
    OutOfTrustingPeriod(Time, Time),
    #[error("HeaderFromFuture: current={0} drift={1:?} header_ts={2}")]
    HeaderFromFuture(Time, core::time::Duration, Time),
    #[error("VerifyMembershipError: err={0:?}")]
    VerifyMembershipError(L1VerifyError),
    #[error("L1VerifyConsensusUpdateError: err={0:?}")]
    L1VerifyConsensusUpdateError(L1VerifyError),
    #[error("L1VerifyExecutionUpdateError: err={0:?}")]
    L1VerifyExecutionUpdateError(L1VerifyError),
    #[error("L1ConsensusError: err={0:?}")]
    L1ConsensusError(L1ConsensusError),
    #[error("L1HeaderTrustedToDeterministicVerifyError: index={0}, prev_updated_as_next={1:?} prev={2:?}, err={3:?}")]
    L1HeaderTrustedToDeterministicVerifyError(usize, bool, L1Consensus, Box<Error>),
    #[error("L1HeaderDeterministicToLatestVerifyError: index={0}, prev_updated_as_next={1:?} prev={2:?}, err={3:?}")]
    L1HeaderDeterministicToLatestVerifyError(usize, bool, L1Consensus, Box<Error>),
    #[error("DerivationError: derivation={0:?}, preimage_size={1:?} err={2:?}")]
    DerivationError(Derivation, usize, optimism_derivation::errors::Error),
    #[error("UnexpectedCurrentSyncCommitteeKeys: request={0:?} consensus={1:?}")]
    UnexpectedCurrentSyncCommitteeKeys(PublicKey, PublicKey),
    #[error("UnexpectedNextSyncCommitteeKeys: request={0:?} consensus={1:?}")]
    UnexpectedNextSyncCommitteeKeys(PublicKey, PublicKey),
    #[error(
        "NoNextSyncCommitteeInConsensusUpdate: store_period={0:?} update_finalized_period={1:?}"
    )]
    NoNextSyncCommitteeInConsensusUpdate(SyncCommitteePeriod, SyncCommitteePeriod),
    #[error("StoreNotSupportedFinalizedPeriod store_period={0:?} update_finalized_period={1:?}")]
    StoreNotSupportedFinalizedPeriod(SyncCommitteePeriod, SyncCommitteePeriod),
    #[error("ProtoMissingFieldError: field={0}")]
    ProtoMissingFieldError(String),
    #[error("DeserializeSyncCommitteeBitsError: parent={parent:?} size={sync_committee_size} bits={sync_committee_bits:?}")]
    DeserializeSyncCommitteeBitsError {
        parent: ethereum_consensus::ssz_rs::DeserializeError,
        sync_committee_size: usize,
        sync_committee_bits: Vec<u8>,
    },
    #[error("InvalidProofFormatError: description={0}")]
    InvalidProofFormatError(String),
    #[error("InvalidExecutionBlockHashMerkleBranch: err={0:?}")]
    InvalidExecutionBlockHashMerkleBranch(MerkleError),
    #[error("UnexpectedL1Timestamp: compute={0} request={1}")]
    UnexpectedL1Timestamp(u128, u128),
    #[error("TimestampOverflowError: time={0}")]
    TimestampOverflowError(u64),
    #[error("ZeroL1ExecutionBlockNumberError")]
    ZeroL1ExecutionBlockNumberError,
    #[error("SyncCommitteeValidateError: err={0:?}")]
    SyncCommitteeValidateError(L1ConsensusError),

    // Misbehaviour
    #[error("NoHeaderFound")]
    NoHeaderFound,
    #[error("UnexpectedHeaderRelation: expected_parent_hash={expected_parent_hash:?} actual_parent_hash={actual_parent_hash:?} header_number={header_number} parent_number={parent_number}")]
    UnexpectedHeaderRelation {
        expected_parent_hash: B256,
        actual_parent_hash: B256,
        header_number: u64,
        parent_number: u64,
    },
    #[error("UnexpectedHeaderRLPError err={0:?}")]
    UnexpectedHeaderRLPError(alloy_rlp::Error),
    #[error("UnexpectedDisputeGameFactoryProxyProof: storage_root={storage_root:?} proof={proof:?} game_uuid={game_uuid:?} game_id_key={game_id_key:?} output_root={output_root:?} l2_block_number={l2_block_number} err={err:?}")]
    UnexpectedDisputeGameFactoryProxyProof {
        storage_root: H256,
        proof: Vec<Vec<u8>>,
        game_uuid: B256,
        game_id_key: B256,
        output_root: B256,
        l2_block_number: u64,
        err: Option<L1VerifyError>,
    },
    #[error("UnexpectedFaultDisputeGameProof: storage_root={storage_root:?} proof={proof:?} status_key={status_key:?} address={address:?} err={err:?}")]
    UnexpectedFaultDisputeGameProof {
        storage_root: H256,
        proof: Vec<Vec<u8>>,
        status_key: B256,
        address: Address,
        err: Option<L1VerifyError>,
    },
    #[error("UnexpectedGameID: game_id={0:?}")]
    UnexpectedGameID(Vec<u8>),
    #[error("UnexpectedResolvedStatus: status={status} storage_root={storage_root:?} proof={proof:?} status_key={status_key:?} address={address:?} packing_slot_value={packing_slot_value:?}")]
    UnexpectedResolvedStatus {
        status: u8,
        storage_root: H256,
        proof: Vec<Vec<u8>>,
        status_key: B256,
        address: Address,
        packing_slot_value: [u8; 32],
    },
    #[error("UnexpectedComputedOutputRoot: expected={expected:?} actual={actual:?} state_root={state_root:?} hash={hash:?}")]
    UnexpectedComputedOutputRoot {
        expected: B256,
        actual: B256,
        state_root: B256,
        hash: B256,
    },
    #[error("UnexpectedComputedResolvedOutputRoot: expected={expected:?} actual={actual:?} number={number} state_root={state_root:?} hash={hash:?}")]
    UnexpectedComputedResolvedOutputRoot {
        expected: B256,
        actual: B256,
        number: u64,
        state_root: B256,
        hash: B256,
    },
    #[error("L1VerifyMisbehaviourError: err={0:?}")]
    L1VerifyMisbehaviourError(L1VerifyError),

    // Framework
    #[error("LCPError: err={0:?}")]
    LCPError(light_client::Error),
}

impl Error {
    pub fn proto_missing(s: &str) -> Self {
        Error::ProtoMissingFieldError(s.to_string())
    }
}

impl light_client::LightClientSpecificError for Error {}
