use crate::l1::L1ConsensusState;
use crate::misbehaviour::FaultDisputeGameProof;
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloy_primitives::private::alloy_rlp;
use alloy_primitives::B256;
use core::array::TryFromSliceError;
use ethereum_consensus::errors::Error as L1ConsensusError;
use ethereum_consensus::types::Address;
use ethereum_light_client_types::errors::Error as EthLightClientTypesError;
use ethereum_light_client_verifier::errors::Error as L1VerifyError;
use light_client::types::{ClientId, Height, TimeError, TypeError};
use optimism_derivation::derivation::Derivation;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    // Preimage
    #[error("OracleClientError: err={0:?}")]
    OracleClientError(#[from] optimism_derivation::errors::Error),

    // data conversion error
    #[error("TimeError: err={0:?}")]
    TimeError(TimeError),
    #[error("TimestampOverflow: timestamp={0}")]
    TimestampOverflow(u64),
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
    // ClientState error
    #[error("MissingLatestHeight")]
    MissingLatestHeight,
    #[error("UnexpectedStoreAddress: err={0:?}")]
    UnexpectedStoreAddress(L1ConsensusError),
    #[error("UnexpectedCommitmentSlot: err={0:?}")]
    UnexpectedCommitmentSlot(TryFromSliceError),
    #[error("ClientFrozen: clientId={0}")]
    ClientFrozen(ClientId),
    #[error("MissingTrustedHeight")]
    MissingTrustedHeight,
    #[error("MissingTrustingPeriod")]
    MissingTrustingPeriod,
    #[error("NegativeMaxClockDrift")]
    NegativeMaxClockDrift,
    #[error("CannotInitializeFrozenClient")]
    CannotInitializeFrozenClient,
    #[error("UnexpectedLatestHeight: height={0}")]
    UnexpectedLatestHeight(Height),

    // ConsState error
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
    #[error("MissingFaultDisputeGameConfig")]
    MissingFaultDisputeGameConfig,
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
    #[error("L1VerifyUpdatesError: err={0:?}")]
    L1VerifyUpdatesError(L1VerifyError),
    #[error("L1ConsensusError: err={0:?}")]
    L1ConsensusError(L1ConsensusError),
    #[error("L1HeaderTrustedToDeterministicVerifyError: index={0}, prev_updated_as_next={1:?} prev={2:?}, err={3:?}")]
    L1HeaderTrustedToDeterministicVerifyError(usize, bool, L1ConsensusState, Box<Error>),
    #[error("L1HeaderDeterministicToLatestVerifyError: index={0}, prev_updated_as_next={1:?} prev={2:?}, err={3:?}")]
    L1HeaderDeterministicToLatestVerifyError(usize, bool, L1ConsensusState, Box<Error>),
    #[error("DerivationError: derivation={0:?}, preimage_size={1:?} err={2:?}")]
    DerivationError(Derivation, usize, optimism_derivation::errors::Error),
    #[error("ProtoMissingFieldError: field={0}")]
    ProtoMissingFieldError(String),
    #[error("InvalidProofFormatError: description={0}")]
    InvalidProofFormatError(String),
    #[error("ZeroL1ExecutionBlockNumberError")]
    ZeroL1ExecutionBlockNumberError,
    // Misbehaviour
    #[error("NoHeaderFound")]
    NoHeaderFound,
    #[error("UnexpectedResolvedL2Number: expected={0} actual={1}")]
    UnexpectedResolvedL2Number(u64, u64),
    #[error("UnexpectedHeaderRelation: expected_parent_hash={expected_parent_hash:?} actual_parent_hash={actual_parent_hash:?} header_number={header_number} parent_number={parent_number}")]
    UnexpectedHeaderRelation {
        expected_parent_hash: B256,
        actual_parent_hash: B256,
        header_number: u64,
        parent_number: u64,
    },
    #[error("UnexpectedHeaderRLPError err={0:?}")]
    UnexpectedHeaderRLPError(alloy_rlp::Error),
    #[error("UnexpectedDisputeGameFactoryProxyProof: proof={proof:?} output_root={output_root:?} l2_block_number={l2_block_number} err={err:?}")]
    UnexpectedDisputeGameFactoryProxyProof {
        proof: FaultDisputeGameProof,
        output_root: B256,
        l2_block_number: u64,
        err: Option<L1VerifyError>,
    },
    #[error("UnexpectedFaultDisputeGameProof: proof={proof:?} address={address:?} err={err:?}")]
    UnexpectedFaultDisputeGameProof {
        proof: FaultDisputeGameProof,
        address: Address,
        err: Option<L1VerifyError>,
    },
    #[error("UnexpectedResolvedStatus: proof={proof:?} status={status} address={address:?} packing_slot_value={packing_slot_value:?}")]
    UnexpectedResolvedStatus {
        proof: FaultDisputeGameProof,
        status: u8,
        address: Address,
        packing_slot_value: [u8; 32],
    },
    #[error("L1VerifyMisbehaviourError: err={0:?}")]
    L1VerifyMisbehaviourError(L1VerifyError),
    #[error("UnknownMisbehaviourType: type={0:?}")]
    UnknownMisbehaviourType(String),
    #[error("UnexpectedDisputeGameFactoryAddress: err={0:?}")]
    UnexpectedDisputeGameFactoryAddress(L1ConsensusError),
    #[error("UnexpectedClientId: err={0:?}")]
    UnexpectedClientId(TypeError),
    #[error("UnexpectedClientIdInMisbehaviour: request={0:?} misbehaviour={1:?}")]
    UnexpectedClientIdInMisbehaviour(ClientId, ClientId),
    #[error("UnexpectedMisbehaviourOutput: resolved_output_root={0:?}")]
    UnexpectedMisbehaviourOutput(B256),
    #[error("UnexpectedMisbehaviourHeight: trusted={0} requested={1}")]
    UnexpectedMisbehaviourHeight(u64, u64),
    #[error("UnexpectedPastL1Header: trusted_l1_origin={0} requested={1}")]
    UnexpectedPastL1Header(u64, u64),
    #[error("UnexpectedSealedL1Number: expected={0} actual={1}")]
    UnexpectedL1HeaderNumber(u64, u64),
    #[error("UnexpectedL1HeaderStateRoot: expected={0:?} actual={1:?}")]
    UnexpectedL1HeaderStateRoot(B256, B256),
    #[error("UnexpectedSubmittedL1HeaderStateRoot: expected={0:?} actual={1:?}")]
    UnexpectedSubmittedL1HeaderStateRoot(B256, B256),
    #[error("UnexpectedStateRoot: state_root={0:?}")]
    UnexpectedStateRoot(Vec<u8>),
    #[error("UnexpectedGameCreatedAt: created_at={0} l1_timestamp={1}")]
    UnexpectedGameCreatedAt(u64, u64),
    #[error("UnexpectedCreatedAt: data={0}")]
    UnexpectedCreatedAt(TryFromSliceError),
    #[error("UnexpectedStatusDefenderWin: data={0}")]
    UnexpectedStatusDefenderWin(u32),

    // Framework
    #[error("LCPError: err={0:?}")]
    LCPError(light_client::Error),

    #[error("EthLightClientTypesError: err={0:?}")]
    EthLightClientTypesError(EthLightClientTypesError),
}

impl Error {
    pub fn proto_missing(s: &str) -> Self {
        Error::ProtoMissingFieldError(s.to_string())
    }
}

impl light_client::LightClientSpecificError for Error {}

impl From<EthLightClientTypesError> for Error {
    fn from(e: EthLightClientTypesError) -> Self {
        Error::EthLightClientTypesError(e)
    }
}
