//! Stable API errors for control-plane requests and dependency failures.

use serde::Serialize;
use thiserror::Error;
use worker::{Response, Result as WorkerResult};

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("{message}")]
    Client {
        code: &'static str,
        message: &'static str,
        status: u16,
    },
    #[error("The request is invalid")]
    Validation { issues: Vec<FieldIssue> },
    #[error("A required service is not configured")]
    Configuration,
    #[error("A dependency could not complete the request")]
    Dependency,
    #[error("The request could not be completed")]
    Internal,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FieldIssue {
    pub field: &'static str,
    pub detail: String,
}

#[derive(Debug, Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
    code: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    issues: Option<&'a [FieldIssue]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<&'a str>,
}

impl ApiError {
    pub const fn client(code: &'static str, message: &'static str, status: u16) -> Self {
        Self::Client {
            code,
            message,
            status,
        }
    }

    #[must_use]
    pub const fn status(&self) -> u16 {
        match self {
            Self::Client { status, .. } => *status,
            Self::Validation { .. } => 400,
            Self::Configuration | Self::Dependency => 503,
            Self::Internal => 500,
        }
    }

    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Client { code, .. } => code,
            Self::Validation { .. } => "request_invalid",
            Self::Configuration => "service_unavailable",
            Self::Dependency => "dependency_unavailable",
            Self::Internal => "internal_error",
        }
    }

    pub fn into_response(self, request_id: &str) -> WorkerResult<Response> {
        let issues = match &self {
            Self::Validation { issues } => Some(issues.as_slice()),
            _ => None,
        };
        let body = ErrorBody {
            error: &self.to_string(),
            code: self.code(),
            issues,
            request_id: (self.status() >= 500).then_some(request_id),
        };
        Ok(Response::from_json(&body)?.with_status(self.status()))
    }
}

impl From<worker::Error> for ApiError {
    fn from(_value: worker::Error) -> Self {
        Self::Internal
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(_value: serde_json::Error) -> Self {
        Self::Validation {
            issues: vec![FieldIssue {
                field: "body",
                detail: "Expected a valid JSON body".to_owned(),
            }],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ApiError;

    #[test]
    fn stable_error_metadata_matches_status_class() {
        let invalid = ApiError::client("activation_invalid", "Activation failed", 400);
        assert_eq!(invalid.code(), "activation_invalid");
        assert_eq!(invalid.status(), 400);
        assert_eq!(ApiError::Configuration.status(), 503);
        assert_eq!(ApiError::Internal.code(), "internal_error");
    }
}
