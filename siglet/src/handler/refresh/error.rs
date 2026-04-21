use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use dsdk_facet_core::token::TokenError;
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RefreshApiError {
    #[error(transparent)]
    Token(#[from] TokenError),
    #[error("Unsupported grant_type: {0}")]
    UnsupportedGrantType(String),
    #[error("Unauthorized: {0}")]
    InvalidAuthHeader(String),
}

impl IntoResponse for RefreshApiError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            RefreshApiError::Token(TokenError::NotAuthorized(msg)) => (StatusCode::UNAUTHORIZED, msg),
            RefreshApiError::Token(TokenError::TokenNotFound { .. }) => {
                (StatusCode::UNAUTHORIZED, "Invalid token".to_string())
            }
            e @ RefreshApiError::UnsupportedGrantType(..) => (StatusCode::BAD_REQUEST, e.to_string()),
            e @ RefreshApiError::InvalidAuthHeader(..) => (StatusCode::UNAUTHORIZED, e.to_string()),
            e => {
                tracing::error!("Unexpected error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string())
            }
        };

        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}
