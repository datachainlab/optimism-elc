use crate::errors::Error;
use core::time::Duration;
use light_client::types::Time;

pub fn new_timestamp(second: u64) -> Result<Time, Error> {
    Time::from_unix_timestamp(second as i64, 0).map_err(Error::TimeError)
}

pub fn validate_state_timestamp_within_trusting_period(
    current_timestamp: Time,
    trusting_period: Duration,
    trusted_consensus_state_timestamp: Time,
) -> Result<(), Error> {
    let trusting_period_end =
        (trusted_consensus_state_timestamp + trusting_period).map_err(Error::TimeError)?;
    if !trusting_period_end.gt(&current_timestamp) {
        return Err(Error::OutOfTrustingPeriod(
            current_timestamp,
            trusting_period_end,
        ));
    }
    Ok(())
}

pub fn validate_header_timestamp_not_future(
    current_timestamp: Time,
    clock_drift: Duration,
    untrusted_header_timestamp: Time,
) -> Result<(), Error> {
    let drifted_current_timestamp = (current_timestamp + clock_drift).map_err(Error::TimeError)?;
    if !drifted_current_timestamp.gt(&untrusted_header_timestamp) {
        return Err(Error::HeaderFromFuture(
            current_timestamp,
            clock_drift,
            untrusted_header_timestamp,
        ));
    }
    Ok(())
}
