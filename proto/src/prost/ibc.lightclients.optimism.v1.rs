#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ClientState {
    #[prost(uint64, tag = "1")]
    pub chain_id: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub ibc_store_address: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub ibc_commitments_slot: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "4")]
    pub latest_height: ::core::option::Option<
        super::super::super::core::client::v1::Height,
    >,
    #[prost(message, optional, tag = "5")]
    pub trusting_period: ::core::option::Option<
        super::super::super::super::google::protobuf::Duration,
    >,
    #[prost(message, optional, tag = "6")]
    pub max_clock_drift: ::core::option::Option<
        super::super::super::super::google::protobuf::Duration,
    >,
    #[prost(bool, tag = "7")]
    pub frozen: bool,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Derivation {
    #[prost(bytes = "vec", tag = "1")]
    pub l1_header: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub agreed_l2_header: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub claimed_l2_header: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Header {
    #[prost(message, optional, tag = "1")]
    pub trusted_height: ::core::option::Option<
        super::super::super::core::client::v1::Height,
    >,
    #[prost(bytes = "vec", tag = "2")]
    pub account_proof: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, repeated, tag = "3")]
    pub derivations: ::prost::alloc::vec::Vec<Derivation>,
    #[prost(bytes = "vec", tag = "4")]
    pub preimage: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConsensusState {
    #[prost(bytes = "vec", tag = "1")]
    pub state_root: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub timestamp: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub output_root: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub hash: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Misbehaviour {
    #[prost(string, tag = "1")]
    pub client_id: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub header_1: ::core::option::Option<Header>,
    #[prost(message, optional, tag = "3")]
    pub header_2: ::core::option::Option<Header>,
}
