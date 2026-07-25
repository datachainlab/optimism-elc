use crate::errors::Error;
use ethereum_light_client_types::height::Height as LcTypesHeight;
use light_client::types::{Height, Time};

/// Converts an `ethereum-light-client-types` height into an LCP height.
pub fn to_lcp_height(height: LcTypesHeight) -> Height {
    Height::new(height.revision_number(), height.revision_height())
}

/// Converts an LCP height into an `ethereum-light-client-types` height.
pub fn to_lc_types_height(height: Height) -> LcTypesHeight {
    LcTypesHeight::new(height.revision_number(), height.revision_height())
}

pub fn new_timestamp(second: u64) -> Result<Time, Error> {
    let second = i64::try_from(second).map_err(|_| Error::TimestampOverflow(second))?;
    Time::from_unix_timestamp(second, 0).map_err(Error::TimeError)
}
