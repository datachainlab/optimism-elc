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

#[cfg(test)]
mod test {
    use crate::errors::Error;
    use crate::misc::{
        validate_header_timestamp_not_future, validate_state_timestamp_within_trusting_period,
    };
    use core::time::Duration;
    use light_client::types::Time;
    use time::macros::datetime;
    use time::OffsetDateTime;

    #[test]
    fn test_trusting_period_validation() {
        {
            let current_timestamp = datetime!(2023-08-20 0:00 UTC);
            let trusted_state_timestamp = datetime!(2023-08-20 0:00 UTC);
            validate_and_assert_trusting_period_no_error(
                current_timestamp,
                1,
                trusted_state_timestamp,
            );
        }

        // trusting_period
        {
            let current_timestamp = datetime!(2023-08-20 0:00 UTC);
            let untrusted_header_timestamp = current_timestamp - Duration::new(0, 1);
            let trusted_state_timestamp = untrusted_header_timestamp - Duration::new(0, 1);
            validate_and_assert_trusting_period_error(
                current_timestamp,
                1,
                trusted_state_timestamp,
            );
            validate_and_assert_trusting_period_error(
                current_timestamp,
                2,
                trusted_state_timestamp,
            );
            validate_and_assert_trusting_period_no_error(
                current_timestamp,
                3,
                trusted_state_timestamp,
            );
        }

        // clock drift
        {
            let current_timestamp = datetime!(2023-08-20 0:00 UTC);
            let untrusted_header_timestamp = current_timestamp + Duration::new(0, 1);
            validate_and_assert_clock_drift_error(current_timestamp, 0, untrusted_header_timestamp);
            validate_and_assert_clock_drift_error(current_timestamp, 1, untrusted_header_timestamp);
            validate_and_assert_clock_drift_no_error(
                current_timestamp,
                2,
                untrusted_header_timestamp,
            );
        }
    }

    fn validate_and_assert_trusting_period_no_error(
        current_timestamp: OffsetDateTime,
        trusting_period: u64,
        trusted_state_timestamp: OffsetDateTime,
    ) {
        let result = validate_state_timestamp_within_trusting_period(
            Time::from_unix_timestamp_nanos(current_timestamp.unix_timestamp_nanos() as u128)
                .unwrap(),
            Duration::from_nanos(trusting_period),
            Time::from_unix_timestamp_nanos(trusted_state_timestamp.unix_timestamp_nanos() as u128)
                .unwrap(),
        );
        assert!(result.is_ok());
    }

    fn validate_and_assert_trusting_period_error(
        current_timestamp: OffsetDateTime,
        trusting_period: u64,
        trusted_state_timestamp: OffsetDateTime,
    ) {
        let result = validate_state_timestamp_within_trusting_period(
            Time::from_unix_timestamp_nanos(current_timestamp.unix_timestamp_nanos() as u128)
                .unwrap(),
            Duration::from_nanos(trusting_period),
            Time::from_unix_timestamp_nanos(trusted_state_timestamp.unix_timestamp_nanos() as u128)
                .unwrap(),
        );
        if let Err(e) = result {
            match e {
                Error::OutOfTrustingPeriod(_, _) => {}
                _ => panic!("unexpected error: {e}"),
            }
        } else {
            panic!("expected error");
        }
    }

    fn validate_and_assert_clock_drift_no_error(
        current_timestamp: OffsetDateTime,
        clock_drift: u64,
        untrusted_header_timestamp: OffsetDateTime,
    ) {
        let result = validate_header_timestamp_not_future(
            Time::from_unix_timestamp_nanos(current_timestamp.unix_timestamp_nanos() as u128)
                .unwrap(),
            Duration::from_nanos(clock_drift),
            Time::from_unix_timestamp_nanos(
                untrusted_header_timestamp.unix_timestamp_nanos() as u128
            )
            .unwrap(),
        );
        assert!(result.is_ok());
    }

    fn validate_and_assert_clock_drift_error(
        current_timestamp: OffsetDateTime,
        clock_drift: u64,
        untrusted_header_timestamp: OffsetDateTime,
    ) {
        let result = validate_header_timestamp_not_future(
            Time::from_unix_timestamp_nanos(current_timestamp.unix_timestamp_nanos() as u128)
                .unwrap(),
            Duration::from_nanos(clock_drift),
            Time::from_unix_timestamp_nanos(
                untrusted_header_timestamp.unix_timestamp_nanos() as u128
            )
            .unwrap(),
        );
        if let Err(e) = result {
            match e {
                Error::HeaderFromFuture(_, _, _) => {}
                _ => panic!("unexpected error: {e}"),
            }
        } else {
            panic!("expected error");
        }
    }
}
