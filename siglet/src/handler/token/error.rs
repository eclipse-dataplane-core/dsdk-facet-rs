use axum::{Json, http::StatusCode, response::IntoResponse};
use dsdk_facet_core::token::TokenError;
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TokenApiError {
    #[error(transparent)]
    Token(#[from] TokenError),
}

impl IntoResponse for TokenApiError {
    fn into_response(self) -> axum::response::Response {
        let (status, error_message) = match self {
            TokenApiError::Token(TokenError::TokenNotFound { .. }) => {
                (StatusCode::NOT_FOUND, "Token not found".to_string())
            }
            TokenApiError::Token(TokenError::NotAuthorized(msg)) => (StatusCode::UNAUTHORIZED, msg),
            TokenApiError::Token(TokenError::Invalid) => (StatusCode::UNAUTHORIZED, "Invalid token".to_string()),
            TokenApiError::Token(TokenError::VerificationError(e)) => (StatusCode::UNAUTHORIZED, e.to_string()),
            e => {
                tracing::error!("Unexpected error: {}", e);
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
            }
        };

        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}
