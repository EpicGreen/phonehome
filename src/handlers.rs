use std::process::Stdio;
use std::time::Duration;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    Json as JsonExtractor,
};
use serde_json::Value;
use tokio::process::Command;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

use crate::models::PhoneHomeData;
use crate::AppState;

/// Handle phone home requests from Cloud Init
pub async fn phone_home_handler(
    State(state): State<AppState>,
    Path(token): Path<String>,
    JsonExtractor(payload): JsonExtractor<Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    info!("Received phone home request with token: {}", token);
    debug!(
        "Phone home payload: {}",
        serde_json::to_string_pretty(&payload).unwrap_or_default()
    );

    // Verify token
    if token != state.config.server.token {
        warn!("Invalid token provided: {}", token);
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Parse the phone home data
    let phone_home_data: PhoneHomeData = match serde_json::from_value(payload) {
        Ok(data) => data,
        Err(err) => {
            error!("Failed to parse phone home data: {}", err);
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    info!(
        "Processing phone home data for instance: {:?}",
        phone_home_data.instance_id
    );

    // Process the data according to configuration
    let processed_data = phone_home_data.process(&state.config.phone_home);

    info!(
        "Extracted data: {} fields, formatted as: '{}'",
        processed_data.extracted_fields.len(),
        processed_data.formatted_data
    );

    // Execute external application
    match execute_external_app(&state.config.external_app, &processed_data.formatted_data).await {
        Ok(output) => {
            info!(
                "External application executed successfully for instance: {:?}",
                processed_data.instance_id
            );
            debug!("External application output: {}", output);
        }
        Err(err) => {
            error!(
                "Failed to execute external application for instance {:?}: {}",
                processed_data.instance_id, err
            );
            // Don't return error to client - log and continue
        }
    }

    // Return success response
    Ok(Json(serde_json::json!({
        "status": "success",
        "message": "Phone home data processed successfully",
        "instance_id": processed_data.instance_id,
        "timestamp": processed_data.timestamp,
        "processed_fields": processed_data.extracted_fields.len()
    })))
}

/// Execute the configured external application with the processed data
async fn execute_external_app(
    config: &crate::config::ExternalAppConfig,
    data: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    info!("Executing external application: {}", config.command);
    debug!("Command args: {:?}", config.args);
    debug!("Data to pass: '{}'", data);

    let mut cmd = Command::new(&config.command);

    // Add configured arguments
    for arg in &config.args {
        cmd.arg(arg);
    }

    // Add the data as the final argument
    cmd.arg(data);

    // Set working directory if configured
    if let Some(ref working_dir) = config.working_directory {
        cmd.current_dir(working_dir);
        debug!("Working directory: {:?}", working_dir);
    }

    // Set environment variables if configured
    if let Some(ref env_vars) = config.environment {
        for (key, value) in env_vars {
            cmd.env(key, value);
        }
        debug!("Environment variables: {:?}", env_vars);
    }

    // Configure stdio
    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());

    // Execute with timeout
    let timeout_duration = Duration::from_secs(config.timeout_seconds);

    let result = timeout(timeout_duration, cmd.output()).await;

    match result {
        Ok(Ok(output)) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);

            if output.status.success() {
                info!("External application completed successfully");
                if !stderr.is_empty() {
                    debug!("External application stderr: {}", stderr);
                }
                Ok(stdout.to_string())
            } else {
                let error_msg = format!(
                    "External application failed with exit code: {:?}, stderr: {}",
                    output.status.code(),
                    stderr
                );
                error!("{}", error_msg);
                Err(error_msg.into())
            }
        }
        Ok(Err(err)) => {
            let error_msg = format!("Failed to execute external application: {}", err);
            error!("{}", error_msg);
            Err(error_msg.into())
        }
        Err(_) => {
            let error_msg = format!(
                "External application timed out after {} seconds",
                config.timeout_seconds
            );
            error!("{}", error_msg);
            Err(error_msg.into())
        }
    }
}

/// Validate that the external application is accessible and executable
pub async fn validate_external_app(
    config: &crate::config::ExternalAppConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("Validating external application: {}", config.command);

    // Check if the command exists and is executable
    let mut cmd = Command::new(&config.command);
    cmd.arg("--version")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());

    // Set working directory if configured
    if let Some(ref working_dir) = config.working_directory {
        cmd.current_dir(working_dir);
    }

    let timeout_duration = Duration::from_secs(5); // Short timeout for validation

    match timeout(timeout_duration, cmd.output()).await {
        Ok(Ok(_)) => {
            info!("External application validation successful");
            Ok(())
        }
        Ok(Err(err)) => {
            if err.kind() == std::io::ErrorKind::NotFound {
                let error_msg = format!("External application not found: {}", config.command);
                error!("{}", error_msg);
                Err(error_msg.into())
            } else {
                warn!(
                    "External application validation failed, but command exists: {}",
                    err
                );
                // Don't fail validation for other errors (like --version not supported)
                Ok(())
            }
        }
        Err(_) => {
            warn!("External application validation timed out, but command may still work");
            // Don't fail validation for timeout
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ExternalAppConfig;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_execute_external_app_success() {
        let config = ExternalAppConfig {
            command: "echo".to_string(),
            args: vec!["Processing:".to_string()],
            timeout_seconds: 5,
            working_directory: None,
            environment: None,
        };

        let result = execute_external_app(&config, "test-data").await;
        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.contains("Processing: test-data"));
    }

    #[tokio::test]
    async fn test_execute_external_app_with_env() {
        let mut env_vars = HashMap::new();
        env_vars.insert("TEST_VAR".to_string(), "test_value".to_string());

        let config = ExternalAppConfig {
            command: "sh".to_string(),
            args: vec!["-c".to_string(), "echo $TEST_VAR".to_string()],
            timeout_seconds: 5,
            working_directory: None,
            environment: Some(env_vars),
        };

        let result = execute_external_app(&config, "ignored").await;
        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.trim() == "test_value");
    }

    #[tokio::test]
    async fn test_execute_external_app_timeout() {
        let config = ExternalAppConfig {
            command: "sh".to_string(),
            args: vec!["-c".to_string(), "sleep 10".to_string()],
            timeout_seconds: 1,
            working_directory: None,
            environment: None,
        };

        let result = execute_external_app(&config, "test-data").await;
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("timed out"));
    }

    #[tokio::test]
    async fn test_execute_external_app_not_found() {
        let config = ExternalAppConfig {
            command: "non-existent-command-12345".to_string(),
            args: vec![],
            timeout_seconds: 5,
            working_directory: None,
            environment: None,
        };

        let result = execute_external_app(&config, "test-data").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_external_app_success() {
        let config = ExternalAppConfig {
            command: "echo".to_string(),
            args: vec![],
            timeout_seconds: 5,
            working_directory: None,
            environment: None,
        };

        let result = validate_external_app(&config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_validate_external_app_not_found() {
        let config = ExternalAppConfig {
            command: "non-existent-command-12345".to_string(),
            args: vec![],
            timeout_seconds: 5,
            working_directory: None,
            environment: None,
        };

        let result = validate_external_app(&config).await;
        assert!(result.is_err());
    }
}
