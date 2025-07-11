#![no_std]
#![allow(clippy::result_large_err)]
extern crate alloc;

use alloc::string::ToString;

pub use ethereum_consensus::preset;

pub mod client;
pub mod client_state;
pub mod consensus_state;

mod account;
mod commitment;
pub mod errors;
pub mod header;
mod l1;
mod message;
mod misbehaviour;
mod misc;

pub fn register_implementations<const SYNC_COMMITTEE_SIZE: usize>(
    registry: &mut dyn light_client::LightClientRegistry,
) {
    registry
        .put_light_client(
            client_state::OPTIMISM_CLIENT_STATE_TYPE_URL.to_string(),
            alloc::boxed::Box::new(client::OptimismLightClient::<SYNC_COMMITTEE_SIZE>),
        )
        .unwrap()
}

#[cfg(test)]
mod test {
    use crate::client_state;
    use light_client::LightClientResolver;

    #[test]
    fn test_register_implementation() {
        let mut registry = light_client::MapLightClientRegistry::new();
        super::register_implementations::<1>(&mut registry);
        assert!(registry
            .get_light_client(client_state::OPTIMISM_CLIENT_STATE_TYPE_URL)
            .is_some());
    }
}
