#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TrustedSyncCommittee {
    #[prost(message, optional, tag = "2")]
    pub sync_committee: ::core::option::Option<SyncCommittee>,
    #[prost(bool, tag = "3")]
    pub is_next: bool,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ForkParameters {
    #[prost(bytes = "vec", tag = "1")]
    pub genesis_fork_version: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, repeated, tag = "2")]
    pub forks: ::prost::alloc::vec::Vec<Fork>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Fraction {
    #[prost(uint64, tag = "1")]
    pub numerator: u64,
    #[prost(uint64, tag = "2")]
    pub denominator: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Fork {
    #[prost(bytes = "vec", tag = "1")]
    pub version: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub epoch: u64,
    #[prost(message, optional, tag = "3")]
    pub spec: ::core::option::Option<ForkSpec>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ForkSpec {
    #[prost(uint32, tag = "1")]
    pub finalized_root_gindex: u32,
    #[prost(uint32, tag = "2")]
    pub current_sync_committee_gindex: u32,
    #[prost(uint32, tag = "3")]
    pub next_sync_committee_gindex: u32,
    #[prost(uint32, tag = "4")]
    pub execution_payload_gindex: u32,
    #[prost(uint32, tag = "5")]
    pub execution_payload_state_root_gindex: u32,
    #[prost(uint32, tag = "6")]
    pub execution_payload_block_number_gindex: u32,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConsensusUpdate {
    #[prost(message, optional, tag = "1")]
    pub attested_header: ::core::option::Option<BeaconBlockHeader>,
    #[prost(message, optional, tag = "2")]
    pub next_sync_committee: ::core::option::Option<SyncCommittee>,
    #[prost(bytes = "vec", repeated, tag = "3")]
    pub next_sync_committee_branch: ::prost::alloc::vec::Vec<
        ::prost::alloc::vec::Vec<u8>,
    >,
    #[prost(message, optional, tag = "4")]
    pub finalized_header: ::core::option::Option<BeaconBlockHeader>,
    #[prost(bytes = "vec", repeated, tag = "5")]
    pub finalized_header_branch: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    #[prost(bytes = "vec", tag = "6")]
    pub finalized_execution_root: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", repeated, tag = "7")]
    pub finalized_execution_branch: ::prost::alloc::vec::Vec<
        ::prost::alloc::vec::Vec<u8>,
    >,
    #[prost(message, optional, tag = "8")]
    pub sync_aggregate: ::core::option::Option<SyncAggregate>,
    #[prost(uint64, tag = "9")]
    pub signature_slot: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SyncCommittee {
    #[prost(bytes = "vec", repeated, tag = "1")]
    pub pubkeys: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    #[prost(bytes = "vec", tag = "2")]
    pub aggregate_pubkey: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SyncAggregate {
    #[prost(bytes = "vec", tag = "1")]
    pub sync_committee_bits: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub sync_committee_signature: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExecutionUpdate {
    #[prost(bytes = "vec", tag = "1")]
    pub state_root: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub state_root_branch: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    #[prost(uint64, tag = "3")]
    pub block_number: u64,
    #[prost(bytes = "vec", repeated, tag = "4")]
    pub block_number_branch: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    #[prost(bytes = "vec", tag = "5")]
    pub block_hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", repeated, tag = "6")]
    pub block_hash_branch: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AccountUpdate {
    #[prost(bytes = "vec", tag = "1")]
    pub account_proof: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub account_storage_root: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BeaconBlockHeader {
    #[prost(uint64, tag = "1")]
    pub slot: u64,
    #[prost(uint64, tag = "2")]
    pub proposer_index: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub parent_root: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub state_root: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub body_root: ::prost::alloc::vec::Vec<u8>,
}
