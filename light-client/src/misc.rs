//! Helpers bridging the LCP framework types (`Time`, `Height`) and the
//! framework-agnostic types used by `ethereum-light-client-types`.

use crate::errors::Error;
use ethereum_light_client_types::height::Height as LcTypesHeight;
use light_client::types::{Height, Time};

/// Creates a [`Time`] from a Unix timestamp in seconds.
pub fn new_timestamp(second: u64) -> Result<Time, Error> {
    let second = i64::try_from(second).map_err(|_| Error::TimestampOverflow(second))?;
    Time::from_unix_timestamp(second, 0).map_err(Error::Time)
}

/// Converts an `ethereum-light-client-types` height into an LCP height.
pub fn to_lcp_height(height: LcTypesHeight) -> Height {
    Height::new(height.revision_number(), height.revision_height())
}

/// Converts an LCP height into an `ethereum-light-client-types` height.
pub fn to_lc_types_height(height: Height) -> LcTypesHeight {
    LcTypesHeight::new(height.revision_number(), height.revision_height())
}
