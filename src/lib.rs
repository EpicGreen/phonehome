//! PhoneHome Server Library
//!
//! A secure HTTPS server for handling Cloud Init phone home requests with configurable
//! data processing and external application execution.

pub mod config;
pub mod handlers;
pub mod models;
pub mod tls;

pub use config::Config;
pub use handlers::phone_home_handler;
pub use models::{PhoneHomeData, ProcessedPhoneHomeData};

use std::sync::Arc;
use axum::{http::StatusCode, response::Json};

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
}

/// Health check endpoint handler
pub async fn health_check() -> Result<Json<serde_json::Value>, StatusCode> {
    Ok(Json(serde_json::json!({
        "status": "ok",
        "service": "phonehome"
    })))
}
