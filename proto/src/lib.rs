//! optimism_ibc_proto library gives the developer access to the Cosmos SDK IBC proto-defined structs.

// This module setup is necessary because the generated code contains "super::" calls for dependencies.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(warnings, trivial_casts, trivial_numeric_casts, unused_import_braces)]
#![allow(clippy::large_enum_variant)]
#![allow(rustdoc::bare_urls)]
#![forbid(unsafe_code)]

pub use ibc_proto::cosmos;
pub use ibc_proto::google;

extern crate alloc;

#[macro_export]
macro_rules! include_proto {
    ($path:literal) => {
        include!(concat!("prost/", $path));
    };
}

/// The version (commit hash) of IBC Go used when generating this library.
pub const IBC_GO_COMMIT: &str = include_str!("IBC_GO_COMMIT");

pub mod ibc {

    pub use ibc_proto::ibc::core;

    pub mod lightclients {

        pub mod ethereum {
            pub mod v1 {
                include_proto!("ibc.lightclients.ethereum.v1.rs");
            }
        }

        pub mod optimism {
            pub mod v1 {
                include_proto!("ibc.lightclients.optimism.v1.rs");
            }
        }
    }
}
