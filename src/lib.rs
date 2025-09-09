//! PhoneHome Server Library
//!
//! A secure HTTPS server for handling Cloud Init phone home requests with configurable
//! data processing and external application execution.

pub mod config;
pub mod handlers;
pub mod models;
pub mod tls;
pub mod web;

pub use config::Config;
pub use handlers::phone_home_handler;
pub use models::{PhoneHomeData, ProcessedPhoneHomeData};

use axum::{http::StatusCode, response::Json};
use std::sync::Arc;
use tracing::{debug, info};

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
}

/// Health check endpoint handler
pub async fn health_check() -> Result<Json<serde_json::Value>, StatusCode> {
    debug!("Health check endpoint accessed");
    
    let response = serde_json::json!({
        "status": "ok",
        "service": "phonehome",
        "timestamp": chrono::Utc::now().to_rfc3339()
    });
    
    info!("Health check successful");
    debug!("Health check response: {}", serde_json::to_string_pretty(&response).unwrap_or_default());
    
    Ok(Json(response))
}
