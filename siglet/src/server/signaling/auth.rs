use std::{
    collections::HashMap,
    pin::Pin,
    task::{Context, Poll},
};

use axum::{
    RequestPartsExt,
    body::Body,
    extract::{Path, Request},
    response::{IntoResponse, Response},
};
use dataplane_sdk::core::model::participant::ParticipantContext;
use reqwest::StatusCode;
use tower::{Layer, Service};

// Auth middleware that extracts the participant context ID from the request path and injects a ParticipantContext into the request extensions.
// Currently it only extracts the participant context ID from the path, but once we have the DPS authentication
// enabled it should take care of validating the authentication token and extracting the participant context ID from it.
#[derive(Clone)]
pub struct AuthLayer;

impl<S> Layer<S> for AuthLayer {
    type Service = AuthMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthMiddleware { inner }
    }
}

#[derive(Clone)]
pub struct AuthMiddleware<S> {
    inner: S,
}

impl<S> Service<Request<Body>> for AuthMiddleware<S>
where
    S: Service<Request<Body>, Response = Response> + Send + Clone + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let (mut parts, body) = req.into_parts();
            match parts.extract::<Path<HashMap<String, String>>>().await {
                Ok(path) => {
                    let mut req = Request::from_parts(parts.clone(), body);
                    if let Some(p) = path.get("participant_context_id") {
                        req.extensions_mut().insert(ParticipantContext::builder().id(p).build());
                    }
                    inner.call(req).await
                }
                Err(e) => {
                    tracing::error!("Failed to extract participant context ID from path: {}", e);
                    Ok((StatusCode::BAD_REQUEST, "missing path parameters").into_response())
                }
            }
        })
    }
}
