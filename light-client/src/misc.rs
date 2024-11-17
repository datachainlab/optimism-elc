use light_client::types::Time;
use crate::errors::Error;

pub fn new_timestamp(second: u64) -> Result<Time, Error> {
    let second = second as u128;
    let nanos = second
        .checked_mul(1_000_000_000)
        .ok_or_else(|| Error::TimestampOverflowError(second))?;
    Time::from_unix_timestamp_nanos(nanos).map_err(Error::TimeError)
}