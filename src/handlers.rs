use std::process::Stdio;
use std::time::Duration;

use axum::{
    extract::{Path, State},
    response::{IntoResponse, Json, Response},
    Json as JsonExtractor,
};
use serde_json::Value;
use tokio::process::Command;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::models::PhoneHomeData;
use crate::web;
use crate::AppState;

/// Handle phone home requests from Cloud Init
pub async fn phone_home_handler(
    State(state): State<AppState>,
    Path(token): Path<String>,
    JsonExtractor(payload): JsonExtractor<Value>,
) -> Response {
    // Generate correlation ID for this request
    let correlation_id = Uuid::new_v4();
    
    info!("Received phone home request [{}] with token: {}", correlation_id, token);
    debug!(
        "[{}] Phone home payload: {}",
        correlation_id,
        serde_json::to_string_pretty(&payload).unwrap_or_default()
    );
    debug!("[{}] Request size: {} bytes", correlation_id, serde_json::to_string(&payload).map(|s| s.len()).unwrap_or(0));

    // Verify token
    if token != state.config.server.token {
        warn!("[{}] Invalid token provided: {}", correlation_id, token);
        error!("[{}] Authentication failed - rejecting request", correlation_id);
        return web::unauthorized().await;
    }
    debug!("[{}] Token authentication successful", correlation_id);

    // Parse the phone home data
    debug!("[{}] Parsing phone home data", correlation_id);
    let phone_home_data: PhoneHomeData = match serde_json::from_value(payload) {
        Ok(data) => {
            debug!("[{}] Phone home data parsed successfully", correlation_id);
            data
        },
        Err(err) => {
            error!("[{}] Failed to parse phone home data: {}", correlation_id, err);
            return web::bad_request().await;
        }
    };

    info!(
        "[{}] Processing phone home data for instance: {:?}",
        correlation_id,
        phone_home_data.instance_id
    );
    debug!("[{}] Instance data: hostname={:?}, fqdn={:?}, cloud={:?}", 
        correlation_id,
        phone_home_data.hostname,
        phone_home_data.fqdn,
        phone_home_data.cloud_name
    );

    // Process the data according to configuration
    debug!("[{}] Starting data processing with configuration", correlation_id);
    let processed_data = phone_home_data.process(&state.config.phone_home);

    info!(
        "[{}] Extracted data: {} fields, formatted as: '{}'",
        correlation_id,
        processed_data.extracted_fields.len(),
        processed_data.formatted_data
    );
    debug!("[{}] Extracted fields: {:?}", correlation_id, processed_data.extracted_fields);

    // Execute external application
    debug!("[{}] Executing external application", correlation_id);
    match execute_external_app(&state.config.external_app, &processed_data.formatted_data, &correlation_id).await {
        Ok(output) => {
            info!(
                "[{}] External application executed successfully for instance: {:?}",
                correlation_id,
                processed_data.instance_id
            );
            debug!("[{}] External application output: {}", correlation_id, output);
        }
        Err(err) => {
            error!(
                "[{}] Failed to execute external application for instance {:?}: {}",
                correlation_id, processed_data.instance_id, err
            );
            // Don't return error to client - log and continue
        }
    }

    // Return success response
    let response = serde_json::json!({
        "status": "success",
        "message": "Phone home data processed successfully",
        "instance_id": processed_data.instance_id,
        "timestamp": processed_data.timestamp,
        "processed_fields": processed_data.extracted_fields.len(),
        "correlation_id": correlation_id.to_string()
    });
    
    info!("[{}] Request processed successfully", correlation_id);
    debug!("[{}] Response: {}", correlation_id, serde_json::to_string_pretty(&response).unwrap_or_default());
    
    Json(response).into_response()
}

/// Execute the configured external application with the processed data
async fn execute_external_app(
    config: &crate::config::ExternalAppConfig,
    data: &str,
    correlation_id: &Uuid,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    info!("[{}] Executing external application: {}", correlation_id, config.command);
    debug!("[{}] Command args: {:?}", correlation_id, config.args);
    debug!("[{}] Data to pass: '{}'", correlation_id, data);
    debug!("[{}] Timeout: {} seconds", correlation_id, config.timeout_seconds);

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
        debug!("[{}] Working directory: {:?}", correlation_id, working_dir);
    }

    // Set environment variables if configured
    if let Some(ref env_vars) = config.environment {
        debug!("[{}] Setting {} environment variables", correlation_id, env_vars.len());
        for (key, value) in env_vars {
            cmd.env(key, value);
            debug!("[{}] ENV: {}={}", correlation_id, key, value);
        }
    }

    // Configure stdio
    debug!("[{}] Configuring stdio pipes", correlation_id);
    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());

    // Execute with timeout
    let timeout_duration = Duration::from_secs(config.timeout_seconds);
    debug!("[{}] Starting external application with timeout: {:?}", correlation_id, timeout_duration);

    let start_time = std::time::Instant::now();
    let result = timeout(timeout_duration, cmd.output()).await;
    let execution_time = start_time.elapsed();

    match result {
        Ok(Ok(output)) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);

            debug!("[{}] External application completed in {:?}", correlation_id, execution_time);
            debug!("[{}] Exit status: {:?}", correlation_id, output.status);
            debug!("[{}] Stdout length: {} bytes", correlation_id, stdout.len());
            debug!("[{}] Stderr length: {} bytes", correlation_id, stderr.len());

            if output.status.success() {
                info!("[{}] External application completed successfully in {:?}", correlation_id, execution_time);
                if !stderr.is_empty() {
                    debug!("[{}] External application stderr: {}", correlation_id, stderr);
                }
                Ok(stdout.to_string())
            } else {
                let error_msg = format!(
                    "External application failed with exit code: {:?}, stderr: {}",
                    output.status.code(),
                    stderr
                );
                error!("[{}] {}", correlation_id, error_msg);
                Err(error_msg.into())
            }
        }
        Ok(Err(err)) => {
            let error_msg = format!("Failed to execute external application: {}", err);
            error!("[{}] {} (execution time: {:?})", correlation_id, error_msg, execution_time);
            Err(error_msg.into())
        }
        Err(_) => {
            let error_msg = format!(
                "External application timed out after {} seconds",
                config.timeout_seconds
            );
            error!("[{}] {} (execution time: {:?})", correlation_id, error_msg, execution_time);
            Err(error_msg.into())
        }
    }
}

/// Validate that the external application is accessible and executable
pub async fn validate_external_app(
    config: &crate::config::ExternalAppConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("Validating external application: {}", config.command);
    debug!("Validation command: {} --version", config.command);

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

    let start_time = std::time::Instant::now();
    match timeout(timeout_duration, cmd.output()).await {
        Ok(Ok(output)) => {
            let validation_time = start_time.elapsed();
            info!("External application validation successful in {:?}", validation_time);
            debug!("Validation exit status: {:?}", output.status);
            debug!("Validation stdout: {}", String::from_utf8_lossy(&output.stdout));
            if !output.stderr.is_empty() {
                debug!("Validation stderr: {}", String::from_utf8_lossy(&output.stderr));
            }
            Ok(())
        }
        Ok(Err(err)) => {
            let validation_time = start_time.elapsed();
            if err.kind() == std::io::ErrorKind::NotFound {
                let error_msg = format!("External application not found: {}", config.command);
                error!("{} (validation time: {:?})", error_msg, validation_time);
                Err(error_msg.into())
            } else {
                warn!(
                    "External application validation failed, but command exists: {} (validation time: {:?})",
                    err, validation_time
                );
                // Don't fail validation for other errors (like --version not supported)
                Ok(())
            }
        }
        Err(_) => {
            let validation_time = start_time.elapsed();
            warn!("External application validation timed out after {:?}, but command may still work", validation_time);
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

        let correlation_id = Uuid::new_v4();
        let result = execute_external_app(&config, "test-data", &correlation_id).await;
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

        let correlation_id = Uuid::new_v4();
        let result = execute_external_app(&config, "ignored", &correlation_id).await;
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

        let correlation_id = Uuid::new_v4();
        let result = execute_external_app(&config, "test-data", &correlation_id).await;
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

        let correlation_id = Uuid::new_v4();
        let result = execute_external_app(&config, "test-data", &correlation_id).await;
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
