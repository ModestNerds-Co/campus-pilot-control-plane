//! Short-link provider adapter used to keep authentication tokens out of emailed URLs.

use serde::{Deserialize, Serialize};
use worker::wasm_bindgen::JsValue;
use worker::{Fetch, Headers, Method, Request, RequestInit};

use crate::error::ApiError;

const REROUT_API_ROOT: &str = "https://api.rerout.co";
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Debug, Serialize)]
struct CreateLinkInput<'a> {
    target_url: &'a str,
    expires_at: i64,
    seo_noindex: bool,
}

#[derive(Debug, Deserialize)]
struct CreatedLink {
    short_url: String,
}

pub async fn create_short_link(
    target_url: &str,
    expires_at: i64,
    api_key: &str,
) -> Result<String, ApiError> {
    let body = serde_json::to_string(&CreateLinkInput {
        target_url,
        expires_at,
        seo_noindex: true,
    })
    .map_err(|_| ApiError::Internal)?;
    let headers = Headers::new();
    headers
        .set("authorization", &format!("Bearer {api_key}"))
        .map_err(ApiError::from)?;
    headers
        .set("content-type", "application/json")
        .map_err(ApiError::from)?;
    headers
        .set("accept", "application/json")
        .map_err(ApiError::from)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(JsValue::from_str(&body)));
    let request = Request::new_with_init(&format!("{REROUT_API_ROOT}/v1/links"), &init)
        .map_err(ApiError::from)?;
    let mut response = Fetch::Request(request)
        .send()
        .await
        .map_err(|_| provider_error())?;
    let status = response.status_code();
    let body = response.text().await.map_err(|_| provider_error())?;
    if body.len() > MAX_RESPONSE_BYTES || !(200..300).contains(&status) {
        return Err(provider_error());
    }
    parse_short_url(&body)
}

fn parse_short_url(body: &str) -> Result<String, ApiError> {
    let created: CreatedLink = serde_json::from_str(body).map_err(|_| provider_error())?;
    let url = url::Url::parse(&created.short_url).map_err(|_| provider_error())?;
    if url.scheme() != "https" || url.host_str().is_none() {
        return Err(provider_error());
    }
    Ok(url.to_string())
}

fn provider_error() -> ApiError {
    ApiError::client(
        "short_link_provider_unavailable",
        "The sign-in link could not be created",
        502,
    )
}

#[cfg(test)]
mod tests {
    use super::parse_short_url;

    #[test]
    fn accepts_https_short_url_from_provider() {
        assert_eq!(
            parse_short_url(r#"{"short_url":"https://rerout.co/Ab3xYz9"}"#)
                .ok()
                .as_deref(),
            Some("https://rerout.co/Ab3xYz9")
        );
    }

    #[test]
    fn rejects_non_https_or_malformed_provider_response() {
        assert!(parse_short_url(r#"{"short_url":"http://rerout.co/code"}"#).is_err());
        assert!(parse_short_url(r#"{"short_url":42}"#).is_err());
    }
}
