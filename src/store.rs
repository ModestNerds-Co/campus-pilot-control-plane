//! D1 query helpers and persistence row types for the control plane.

use serde::de::DeserializeOwned;
use worker::wasm_bindgen::JsValue;
use worker::{D1Database, D1PreparedStatement};

use crate::error::ApiError;

pub type Bindings = Vec<JsValue>;

pub fn bind_text(value: &str) -> JsValue {
    JsValue::from_str(value)
}

pub fn bind_optional_text(value: Option<&str>) -> JsValue {
    value.map_or_else(JsValue::null, JsValue::from_str)
}

pub fn bind_i64(value: i64) -> Result<JsValue, ApiError> {
    if !is_safe_js_integer(value) {
        return Err(ApiError::Internal);
    }
    Ok(JsValue::from_f64(value as f64))
}

const fn is_safe_js_integer(value: i64) -> bool {
    const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
    value.unsigned_abs() <= MAX_SAFE_INTEGER.unsigned_abs()
}

pub fn bind_bool(value: bool) -> JsValue {
    JsValue::from_bool(value)
}

pub async fn all<T: DeserializeOwned>(
    db: &D1Database,
    sql: &str,
    bindings: Bindings,
) -> Result<Vec<T>, ApiError> {
    let statement = bind(db.prepare(sql), &bindings)?;
    statement
        .all()
        .await
        .map_err(ApiError::from)?
        .results::<T>()
        .map_err(ApiError::from)
}

pub async fn first<T: DeserializeOwned>(
    db: &D1Database,
    sql: &str,
    bindings: Bindings,
) -> Result<Option<T>, ApiError> {
    bind(db.prepare(sql), &bindings)?
        .first::<T>(None)
        .await
        .map_err(ApiError::from)
}

pub async fn execute(db: &D1Database, sql: &str, bindings: Bindings) -> Result<usize, ApiError> {
    let result = bind(db.prepare(sql), &bindings)?
        .run()
        .await
        .map_err(ApiError::from)?;
    let changes = result
        .meta()
        .map_err(ApiError::from)?
        .and_then(|metadata| metadata.changes)
        .unwrap_or(0);
    Ok(changes)
}

pub async fn batch(db: &D1Database, statements: Vec<D1PreparedStatement>) -> Result<(), ApiError> {
    db.batch(statements).await.map_err(ApiError::from)?;
    Ok(())
}

pub fn prepared(
    db: &D1Database,
    sql: &str,
    bindings: Bindings,
) -> Result<D1PreparedStatement, ApiError> {
    bind(db.prepare(sql), &bindings)
}

fn bind(
    statement: D1PreparedStatement,
    bindings: &[JsValue],
) -> Result<D1PreparedStatement, ApiError> {
    statement.bind(bindings).map_err(ApiError::from)
}

#[cfg(test)]
mod tests {
    use super::is_safe_js_integer;

    #[test]
    fn rejects_integer_values_that_javascript_cannot_preserve() {
        assert!(is_safe_js_integer(9_007_199_254_740_991));
        assert!(!is_safe_js_integer(9_007_199_254_740_992));
    }
}
