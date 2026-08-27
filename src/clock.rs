//! UTC timestamp helpers shared by leases, sessions, billing, and audit records.

use time::OffsetDateTime;

use crate::error::ApiError;

pub fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

pub fn format(value: OffsetDateTime) -> Result<String, ApiError> {
    value
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| ApiError::Internal)
}

pub fn now_iso() -> Result<String, ApiError> {
    format(now())
}

#[cfg(test)]
mod tests {
    use super::format;
    use time::OffsetDateTime;

    #[test]
    fn format_uses_utc_contract_units() {
        assert!(
            format(OffsetDateTime::UNIX_EPOCH).is_ok_and(|value| value == "1970-01-01T00:00:00Z")
        );
    }
}
