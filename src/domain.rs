//! Refined licensing, authentication, plan, and entitlement domain values.

use std::collections::BTreeSet;
use std::fmt::{Display, Formatter};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{ApiError, FieldIssue};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct CanonicalEmail(String);

impl CanonicalEmail {
    pub fn parse(value: &str) -> Result<Self, ApiError> {
        let canonical = value.trim().to_lowercase();
        let valid = canonical.len() <= 254
            && canonical.split_once('@').is_some_and(|(local, domain)| {
                !local.is_empty() && domain.contains('.') && !domain.ends_with('.')
            });
        if valid {
            Ok(Self(canonical))
        } else {
            Err(validation("email", "Enter a valid email address"))
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for CanonicalEmail {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantId(Uuid);

impl TenantId {
    pub fn parse(value: &str) -> Result<Self, ApiError> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(|_| validation("tenant_id", "Expected a UUID tenant identifier"))
    }

    #[must_use]
    pub fn as_string(&self) -> String {
        self.0.to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentId(String);

impl DeploymentId {
    pub fn parse(value: &str) -> Result<Self, ApiError> {
        let value = value.trim();
        if (8..=200).contains(&value.len())
            && value
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || "._:-".contains(character))
        {
            Ok(Self(value.to_owned()))
        } else {
            Err(validation(
                "deployment_id",
                "Use 8 to 200 letters, numbers, dots, underscores, colons, or hyphens",
            ))
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationCode(String);

impl ActivationCode {
    pub fn parse(value: &str) -> Result<Self, ApiError> {
        let value = value.trim();
        if value.starts_with("cpact_") && (20..=300).contains(&value.len()) {
            Ok(Self(value.to_owned()))
        } else {
            Err(validation(
                "activation_code",
                "The activation code is invalid",
            ))
        }
    }

    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallationCredential(String);

impl InstallationCredential {
    pub fn parse(value: &str) -> Result<Self, ApiError> {
        let value = value.trim();
        if value.starts_with("cpinst_") && value.len() >= 40 {
            Ok(Self(value.to_owned()))
        } else {
            Err(ApiError::client(
                "installation_unauthorized",
                "Installation authentication failed",
                401,
            ))
        }
    }

    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct PaymentProviderKey(String);

impl PaymentProviderKey {
    pub fn parse(value: &str) -> Result<Self, ApiError> {
        let value = value.trim().to_lowercase();
        if (2..=40).contains(&value.len())
            && value.chars().all(|character| {
                character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
            })
        {
            Ok(Self(value))
        } else {
            Err(validation(
                "provider",
                "Use 2 to 40 lowercase letters, numbers, or underscores",
            ))
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct CurrencyCode(String);

impl CurrencyCode {
    pub fn parse(value: &str) -> Result<Self, ApiError> {
        let value = value.trim().to_uppercase();
        if value.len() == 3
            && value
                .chars()
                .all(|character| character.is_ascii_uppercase())
        {
            Ok(Self(value))
        } else {
            Err(validation(
                "currency",
                "Expected a three-letter ISO 4217 currency code",
            ))
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Money {
    pub currency: CurrencyCode,
    pub exponent: u8,
    pub amount_minor: i64,
}

impl Money {
    pub fn price(currency: &str, exponent: u8, amount_minor: i64) -> Result<Self, ApiError> {
        if exponent > 4 {
            return Err(validation(
                "currency_exponent",
                "Expected a currency exponent from 0 to 4",
            ));
        }
        if amount_minor < 0 {
            return Err(validation("amount_minor", "Expected a non-negative amount"));
        }
        Ok(Self {
            currency: CurrencyCode::parse(currency)?,
            exponent,
            amount_minor,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LimitPeriod {
    None,
    Day,
    Month,
    Year,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LimitEnforcement {
    Report,
    Hard,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LicenseLimit {
    pub key: String,
    pub unit: String,
    pub period: LimitPeriod,
    pub value: u64,
    pub enforcement: LimitEnforcement,
}

impl LicenseLimit {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        module_key_is_valid(&self.key) && !self.unit.trim().is_empty() && self.unit.len() <= 50
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeaseClaims {
    pub contract_version: String,
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub installation_id: String,
    pub jti: String,
    pub sequence: i64,
    pub catalog_version: String,
    pub iat: i64,
    pub nbf: i64,
    pub refresh_after: i64,
    pub lease_expires_at: i64,
    pub grace_until: i64,
    pub exp: i64,
    pub modules: Vec<String>,
    pub features: Vec<String>,
    pub limits: Vec<LicenseLimit>,
    pub min_app_version: Option<String>,
    pub max_app_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntitlementSet {
    pub modules: BTreeSet<String>,
    pub features: BTreeSet<String>,
    pub limits: Vec<LicenseLimit>,
    pub period_end: Option<OffsetDateTime>,
    pub grace_until: Option<OffsetDateTime>,
}

impl EntitlementSet {
    pub fn from_storage(
        modules_json: &str,
        features_json: &str,
        limits_json: &str,
        period_end: Option<&str>,
        grace_until: Option<&str>,
    ) -> Result<Self, ApiError> {
        let modules = parse_keys(modules_json)?;
        let features = parse_keys(features_json)?;
        let limits: Vec<LicenseLimit> =
            serde_json::from_str(limits_json).map_err(|_| ApiError::Internal)?;
        if limits.iter().any(|limit| !limit.is_valid()) {
            return Err(ApiError::Internal);
        }
        Ok(Self {
            modules,
            features,
            limits,
            period_end: parse_optional_timestamp(period_end)?,
            grace_until: parse_optional_timestamp(grace_until)?,
        })
    }
}

pub fn parse_iso_timestamp(field: &'static str, value: &str) -> Result<OffsetDateTime, ApiError> {
    OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .map_err(|_| validation(field, "Expected an RFC 3339 timestamp"))
}

#[must_use]
pub fn module_key_is_valid(value: &str) -> bool {
    let mut characters = value.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_lowercase())
        && characters.all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || character == '_'
                || character == '.'
        })
}

pub fn required_text(
    field: &'static str,
    value: &str,
    minimum: usize,
    maximum: usize,
) -> Result<String, ApiError> {
    let value = value.trim();
    if (minimum..=maximum).contains(&value.len()) {
        Ok(value.to_owned())
    } else {
        Err(validation(
            field,
            &format!("Use between {minimum} and {maximum} characters"),
        ))
    }
}

fn parse_keys(value: &str) -> Result<BTreeSet<String>, ApiError> {
    let values: Vec<String> = serde_json::from_str(value).map_err(|_| ApiError::Internal)?;
    if values.iter().any(|key| !module_key_is_valid(key)) {
        return Err(ApiError::Internal);
    }
    Ok(values.into_iter().collect())
}

fn parse_optional_timestamp(value: Option<&str>) -> Result<Option<OffsetDateTime>, ApiError> {
    value
        .map(|timestamp| {
            parse_iso_timestamp("timestamp", timestamp).map_err(|_| ApiError::Internal)
        })
        .transpose()
}

fn validation(field: &'static str, detail: &str) -> ApiError {
    ApiError::Validation {
        issues: vec![FieldIssue {
            field,
            detail: detail.to_owned(),
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ActivationCode, CanonicalEmail, CurrencyCode, DeploymentId, EntitlementSet,
        InstallationCredential, Money, PaymentProviderKey, TenantId, module_key_is_valid,
    };

    #[test]
    fn canonical_email_is_trimmed_and_lowercase() {
        let email = CanonicalEmail::parse("  Admin@Example.COM ");
        assert!(email.is_ok_and(|value| value.to_string() == "admin@example.com"));
    }

    #[test]
    fn refined_identifiers_reject_untrusted_shapes() {
        assert!(TenantId::parse("not-a-uuid").is_err());
        assert!(DeploymentId::parse("../bad").is_err());
        assert!(ActivationCode::parse("short").is_err());
        assert!(InstallationCredential::parse("Bearer anything").is_err());
        assert!(PaymentProviderKey::parse("PayNow").is_ok());
        assert!(PaymentProviderKey::parse("bad-provider").is_err());
        assert!(CurrencyCode::parse("zwg").is_ok_and(|code| code.as_str() == "ZWG"));
        assert!(Money::price("USD", 2, 10_00).is_ok());
        assert!(Money::price("USD", 5, 10_00).is_err());
    }

    #[test]
    fn money_keeps_currency_precision_explicit() {
        let examples = [
            ("ZWG", 2, 12_550),
            ("USD", 2, 12_550),
            ("ZAR", 2, 12_550),
            ("JPY", 0, 125),
            ("KWD", 3, 125_500),
        ];
        for (currency, exponent, amount_minor) in examples {
            let money = Money::price(currency, exponent, amount_minor);
            assert!(money.is_ok_and(|value| {
                value.currency.as_str() == currency
                    && value.exponent == exponent
                    && value.amount_minor == amount_minor
            }));
        }
    }

    #[test]
    fn module_keys_have_one_canonical_shape() {
        assert!(module_key_is_valid("hr_payroll"));
        assert!(module_key_is_valid("agent.chat"));
        assert!(!module_key_is_valid("HR-Payroll"));
    }

    #[test]
    fn entitlement_storage_is_parsed_once() {
        let entitlement = EntitlementSet::from_storage(
            r#"["sis","agent","sis"]"#,
            r#"["agent.chat"]"#,
            "[]",
            None,
            None,
        );
        assert!(entitlement.is_ok_and(|value| value.modules.len() == 2));
    }
}
