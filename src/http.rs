//! API response, request parsing, cookie, origin, and request-correlation helpers.

use serde::Serialize;
use serde::de::DeserializeOwned;
use uuid::Uuid;
use worker::{Headers, Request, Response, Result as WorkerResult};

use crate::config::Config;
use crate::error::{ApiError, FieldIssue};

pub type ApiResult<T> = Result<T, ApiError>;

pub fn request_id(request: &Request) -> String {
    request
        .headers()
        .get("cf-ray")
        .ok()
        .flatten()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| Uuid::new_v4().to_string())
}

pub async fn json_body<T: DeserializeOwned>(request: &mut Request) -> ApiResult<T> {
    let text = request.text().await.map_err(ApiError::from)?;
    serde_json::from_str(&text).map_err(|_| ApiError::Validation {
        issues: vec![FieldIssue {
            field: "body",
            detail: "Expected a valid JSON body".to_owned(),
        }],
    })
}

pub fn json<T: Serialize>(value: &T) -> ApiResult<Response> {
    Response::from_json(value).map_err(ApiError::from)
}

pub fn json_status<T: Serialize>(value: &T, status: u16) -> ApiResult<Response> {
    Ok(json(value)?.with_status(status))
}

pub fn finish(result: ApiResult<Response>, request_id: &str) -> WorkerResult<Response> {
    let mut response = match result {
        Ok(response) => response,
        Err(error) => {
            if error.status() >= 500 {
                worker::console_error!(
                    "request failed request_id={request_id} code={}",
                    error.code()
                );
            }
            error.into_response(request_id)?
        }
    };
    response.headers_mut().set("x-request-id", request_id)?;
    response
        .headers_mut()
        .set("cache-control", "no-store, max-age=0")?;
    response.headers_mut().set("pragma", "no-cache")?;
    Ok(response)
}

pub fn assert_same_origin(
    request: &Request,
    expected_app_url: &str,
    config: &Config,
) -> ApiResult<()> {
    let origin = request.headers().get("origin").map_err(ApiError::from)?;
    if origin.is_none() && !config.is_production() {
        return Ok(());
    }
    let expected = url::Url::parse(expected_app_url)
        .ok()
        .map(|url| url.origin().ascii_serialization());
    if origin.as_deref() == expected.as_deref() {
        Ok(())
    } else {
        Err(ApiError::client(
            "origin_not_allowed",
            "The request origin is not allowed",
            403,
        ))
    }
}

pub fn cookie(request: &Request, name: &str) -> Option<String> {
    request
        .headers()
        .get("cookie")
        .ok()
        .flatten()
        .and_then(|header| {
            header.split(';').find_map(|part| {
                let (key, value) = part.trim().split_once('=')?;
                (key == name).then(|| value.to_owned())
            })
        })
}

pub fn bearer_token(request: &Request) -> Option<String> {
    let header = request.headers().get("authorization").ok().flatten()?;
    let (scheme, token) = header.split_once(' ')?;
    if scheme.eq_ignore_ascii_case("bearer") && !token.trim().is_empty() {
        Some(token.trim().to_owned())
    } else {
        None
    }
}

pub fn set_cookie(
    response: &mut Response,
    name: &str,
    value: &str,
    max_age_seconds: i64,
    secure: bool,
) -> ApiResult<()> {
    response
        .headers_mut()
        .set(
            "set-cookie",
            &cookie_value(name, value, max_age_seconds, secure),
        )
        .map_err(ApiError::from)
}

pub fn delete_cookie(response: &mut Response, name: &str) -> ApiResult<()> {
    response
        .headers_mut()
        .set("set-cookie", &cookie_value(name, "", 0, false))
        .map_err(ApiError::from)
}

pub fn redirect(app_url: &str, path: &str) -> ApiResult<Response> {
    let url = url::Url::parse(&format!("{}{}", app_url.trim_end_matches('/'), path))
        .map_err(|_| ApiError::Configuration)?;
    let headers = Headers::new();
    headers
        .set("location", url.as_str())
        .map_err(ApiError::from)?;
    Ok(Response::empty()
        .map_err(ApiError::from)?
        .with_status(303)
        .with_headers(headers))
}

fn cookie_value(name: &str, value: &str, max_age_seconds: i64, secure: bool) -> String {
    let secure_suffix = if secure { "; Secure" } else { "" };
    format!(
        "{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age_seconds}{secure_suffix}"
    )
}

#[cfg(test)]
mod tests {
    use super::cookie_value;

    #[test]
    fn production_session_cookie_is_http_only_and_secure() {
        assert_eq!(
            cookie_value("session", "secret", 60, true),
            "session=secret; Path=/; HttpOnly; SameSite=Lax; Max-Age=60; Secure"
        );
    }

    #[test]
    fn deletion_cookie_expires_immediately() {
        assert_eq!(
            cookie_value("session", "", 0, false),
            "session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
        );
    }
}
