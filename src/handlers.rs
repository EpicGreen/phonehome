use std::collections::HashMap;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    extract::{ConnectInfo, Form, Path, State},
    response::{IntoResponse, Json, Response},
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use tokio::process::Command;
use tokio::sync::RwLock;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::models::PhoneHomeData;
use crate::web;
use crate::AppState;

// Rate limiting structure
#[derive(Clone)]
pub struct RateLimiter {
    requests: Arc<RwLock<HashMap<String, Vec<Instant>>>>,
    max_requests: usize,
    window_duration: Duration,
}

/// Cloud-init phone home form data structure
/// This matches the form fields that cloud-init sends
#[derive(Debug, Clone, Deserialize)]
pub struct PhoneHomeFormData {
    /// RSA public key
    pub pub_key_rsa: Option<String>,
    /// ECDSA public key
    pub pub_key_ecdsa: Option<String>,
    /// Ed25519 public key
    pub pub_key_ed25519: Option<String>,
    /// Instance ID
    pub instance_id: Option<String>,
    /// Hostname
    pub hostname: Option<String>,
    /// Fully qualified domain name
    pub fqdn: Option<String>,
}

impl RateLimiter {
    pub fn new(max_requests: usize, window_seconds: u64) -> Self {
        Self {
            requests: Arc::new(RwLock::new(HashMap::new())),
            max_requests,
            window_duration: Duration::from_secs(window_seconds),
        }
    }

    pub async fn check_rate_limit(&self, client_id: &str) -> bool {
        let mut requests = self.requests.write().await;
        let now = Instant::now();

        // Clean old entries
        let cutoff = now - self.window_duration;
        requests
            .entry(client_id.to_string())
            .or_insert_with(Vec::new)
            .retain(|&timestamp| timestamp > cutoff);

        let client_requests = requests.get_mut(client_id).unwrap();

        if client_requests.len() >= self.max_requests {
            return false; // Rate limit exceeded
        }

        client_requests.push(now);
        true
    }
}

/// Handle phone home requests from Cloud Init
pub async fn phone_home_handler(
    State(state): State<AppState>,
    Path(token): Path<String>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Form(form_data): Form<PhoneHomeFormData>,
) -> Response {
    // Generate correlation ID for this request
    let correlation_id = Uuid::new_v4();
    let client_ip = addr.ip().to_string();

    info!(
        "Received phone home request [{}] from {} with token: {}",
        correlation_id, client_ip, token
    );

    // Check rate limit
    if !state.rate_limiter.check_rate_limit(&client_ip).await {
        warn!(
            "[{}] Rate limit exceeded for IP: {}",
            correlation_id, client_ip
        );
        return web::bad_request().await;
    }
    debug!(
        "[{}] Phone home form data: {:#?}",
        correlation_id, form_data
    );

    // Verify token
    if token != state.config.server.token {
        warn!("[{}] Invalid token provided: {}", correlation_id, token);
        error!(
            "[{}] Authentication failed - rejecting request",
            correlation_id
        );
        return web::unauthorized().await;
    }
    debug!("[{}] Token authentication successful", correlation_id);

    // Convert form data to PhoneHomeData structure
    debug!(
        "[{}] Converting form data to phone home data",
        correlation_id
    );
    let mut public_keys = Vec::new();
    if let Some(rsa_key) = &form_data.pub_key_rsa {
        if !rsa_key.is_empty() {
            public_keys.push(rsa_key.clone());
        }
    }
    if let Some(ecdsa_key) = &form_data.pub_key_ecdsa {
        if !ecdsa_key.is_empty() {
            public_keys.push(ecdsa_key.clone());
        }
    }
    if let Some(ed25519_key) = &form_data.pub_key_ed25519 {
        if !ed25519_key.is_empty() {
            public_keys.push(ed25519_key.clone());
        }
    }

    let phone_home_data = PhoneHomeData {
        instance_id: form_data.instance_id.clone(),
        public_keys: if public_keys.is_empty() {
            None
        } else {
            Some(public_keys)
        },
        hostname: form_data.hostname.clone(),
        fqdn: form_data.fqdn.clone(),
        ..Default::default()
    };

    debug!(
        "[{}] Phone home data converted successfully",
        correlation_id
    );

    info!(
        "[{}] Processing phone home data for instance: {:?}",
        correlation_id, phone_home_data.instance_id
    );
    debug!(
        "[{}] Instance data: hostname={:?}, fqdn={:?}, cloud={:?}",
        correlation_id, phone_home_data.hostname, phone_home_data.fqdn, phone_home_data.cloud_name
    );

    // Process the data according to configuration
    debug!(
        "[{}] Starting data processing with configuration",
        correlation_id
    );
    let processed_data = phone_home_data.process(&state.config.phone_home);

    info!(
        "[{}] Extracted data: {} fields, formatted as: '{}'",
        correlation_id,
        processed_data.extracted_fields.len(),
        processed_data.formatted_data
    );

    // Security logging and monitoring
    let data_hash = Sha256::digest(processed_data.formatted_data.as_bytes());
    info!(
        "[{}] SECURITY: External app execution requested - IP: {}, Data hash: {:x}, Length: {}",
        correlation_id,
        client_ip,
        data_hash,
        processed_data.formatted_data.len()
    );

    // Check for suspicious patterns
    if processed_data.formatted_data.len() > 1000 {
        warn!(
            "[{}] SECURITY: Large data payload detected: {} bytes",
            correlation_id,
            processed_data.formatted_data.len()
        );
    }

    if processed_data.formatted_data.contains("../")
        || processed_data.formatted_data.contains("..\\")
    {
        warn!(
            "[{}] SECURITY: Path traversal attempt detected",
            correlation_id
        );
    }
    debug!(
        "[{}] Extracted fields: {:?}",
        correlation_id, processed_data.extracted_fields
    );

    // Execute external application
    debug!("[{}] Executing external application", correlation_id);
    match execute_external_app(
        &state.config.external_app,
        &processed_data.formatted_data,
        &correlation_id,
    )
    .await
    {
        Ok(output) => {
            info!(
                "[{}] External application executed successfully for instance: {:?}",
                correlation_id, processed_data.instance_id
            );
            debug!(
                "[{}] External application output: {}",
                correlation_id, output
            );
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
    debug!(
        "[{}] Response: {}",
        correlation_id,
        serde_json::to_string_pretty(&response).unwrap_or_default()
    );

    Json(response).into_response()
}

/// Sanitize and validate data before passing to external application
fn sanitize_external_app_data(
    data: &str,
    config: &crate::config::ExternalAppConfig,
    correlation_id: &Uuid,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    // Maximum length check
    if data.len() > config.max_data_length {
        let error_msg = format!(
            "Data too long: {} bytes (max: {})",
            data.len(),
            config.max_data_length
        );
        warn!("[{}] {}", correlation_id, error_msg);
        return Err(error_msg.into());
    }

    // Check for null bytes (can terminate strings unexpectedly)
    if data.contains('\0') {
        let error_msg = "Data contains null bytes";
        warn!("[{}] {}", correlation_id, error_msg);
        return Err(error_msg.into());
    }

    // Check for control characters that could be problematic
    if !config.allow_control_chars {
        let has_dangerous_chars = data
            .chars()
            .any(|c| c.is_control() && c != '\t' && c != '\n' && c != '\r');

        if has_dangerous_chars {
            let error_msg = "Data contains dangerous control characters";
            warn!("[{}] {}", correlation_id, error_msg);
            return Err(error_msg.into());
        }
    }

    // Optional: Sanitize input if configured
    let sanitized = if config.sanitize_input {
        data.chars()
            .filter(|&c| {
                // Allow alphanumeric, common punctuation, and safe whitespace
                c.is_ascii_alphanumeric()
                    || c.is_ascii_punctuation()
                    || c == ' '
                    || c == '\t'
                    || c == '\n'
                    || c == '\r'
            })
            .collect::<String>()
    } else {
        data.to_string()
    };

    // Log if data was modified
    if sanitized != data {
        info!(
            "[{}] Data sanitized: {} -> {} chars",
            correlation_id,
            data.len(),
            sanitized.len()
        );
    }

    debug!("[{}] Sanitized data: '{}'", correlation_id, sanitized);
    Ok(sanitized)
}

/// Execute the configured external application with the processed data
async fn execute_external_app(
    config: &crate::config::ExternalAppConfig,
    data: &str,
    correlation_id: &Uuid,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    info!(
        "[{}] Executing external application: {}",
        correlation_id, config.command
    );

    // SECURITY: Sanitize input data
    let sanitized_data = sanitize_external_app_data(data, config, correlation_id)?;

    debug!("[{}] Command args: {:?}", correlation_id, config.args);
    debug!("[{}] Original data length: {}", correlation_id, data.len());
    debug!("[{}] Sanitized data: '{}'", correlation_id, sanitized_data);
    debug!(
        "[{}] Timeout: {} seconds",
        correlation_id, config.timeout_seconds
    );

    let mut cmd = Command::new(&config.command);

    // Add configured arguments
    for arg in &config.args {
        cmd.arg(arg);
    }

    // SECURITY: Use sanitized data with optional quoting
    // Rust's arg() method handles argument separation safely
    let data_arg = if config.quote_data {
        format!("\"{}\"", sanitized_data)
    } else {
        sanitized_data.to_string()
    };
    debug!(
        "[{}] Quote data enabled: {}",
        correlation_id, config.quote_data
    );
    cmd.arg(&data_arg);

    // Set working directory if configured
    if let Some(ref working_dir) = config.working_directory {
        cmd.current_dir(working_dir);
        debug!("[{}] Working directory: {:?}", correlation_id, working_dir);
    }

    // Set environment variables if configured
    if let Some(ref env_vars) = config.environment {
        debug!(
            "[{}] Setting {} environment variables",
            correlation_id,
            env_vars.len()
        );
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
    debug!(
        "[{}] Starting external application with timeout: {:?}",
        correlation_id, timeout_duration
    );

    let start_time = std::time::Instant::now();
    let result = timeout(timeout_duration, cmd.output()).await;
    let execution_time = start_time.elapsed();

    match result {
        Ok(Ok(output)) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);

            debug!(
                "[{}] External application completed in {:?}",
                correlation_id, execution_time
            );
            debug!("[{}] Exit status: {:?}", correlation_id, output.status);
            debug!("[{}] Stdout length: {} bytes", correlation_id, stdout.len());
            debug!("[{}] Stderr length: {} bytes", correlation_id, stderr.len());

            if output.status.success() {
                info!(
                    "[{}] External application completed successfully in {:?}",
                    correlation_id, execution_time
                );
                if !stderr.is_empty() {
                    debug!(
                        "[{}] External application stderr: {}",
                        correlation_id, stderr
                    );
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
            error!(
                "[{}] {} (execution time: {:?})",
                correlation_id, error_msg, execution_time
            );
            Err(error_msg.into())
        }
        Err(_) => {
            let error_msg = format!(
                "External application timed out after {} seconds",
                config.timeout_seconds
            );
            error!(
                "[{}] {} (execution time: {:?})",
                correlation_id, error_msg, execution_time
            );
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
            info!(
                "External application validation successful in {:?}",
                validation_time
            );
            debug!("Validation exit status: {:?}", output.status);
            debug!(
                "Validation stdout: {}",
                String::from_utf8_lossy(&output.stdout)
            );
            if !output.stderr.is_empty() {
                debug!(
                    "Validation stderr: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
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
            warn!(
                "External application validation timed out after {:?}, but command may still work",
                validation_time
            );
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
            max_data_length: 4096,
            allow_control_chars: false,
            sanitize_input: true,
            quote_data: false,
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
            max_data_length: 4096,
            allow_control_chars: false,
            sanitize_input: true,
            quote_data: false,
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
            max_data_length: 4096,
            allow_control_chars: false,
            sanitize_input: true,
            quote_data: false,
        };

        let correlation_id = Uuid::new_v4();
        let result = execute_external_app(&config, "ignored", &correlation_id).await;
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("timed out"));
    }

    #[tokio::test]
    async fn test_execute_external_app_not_found() {
        let config = ExternalAppConfig {
            command: "nonexistentcommand".to_string(),
            args: vec![],
            timeout_seconds: 5,
            working_directory: None,
            environment: None,
            max_data_length: 4096,
            allow_control_chars: false,
            sanitize_input: true,
            quote_data: false,
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
            max_data_length: 4096,
            allow_control_chars: false,
            sanitize_input: true,
            quote_data: false,
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
            max_data_length: 4096,
            allow_control_chars: false,
            sanitize_input: true,
            quote_data: false,
        };

        let result = validate_external_app(&config).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_quote_data_with_execution() {
        // Test with quote_data = true
        let config_with_quotes = ExternalAppConfig {
            command: "echo".to_string(),
            args: vec!["Data:".to_string()],
            timeout_seconds: 5,
            working_directory: None,
            environment: None,
            max_data_length: 4096,
            allow_control_chars: false,
            sanitize_input: true,
            quote_data: true,
        };

        let correlation_id = Uuid::new_v4();
        let test_data = "test|data|with|pipes";

        let result = execute_external_app(&config_with_quotes, test_data, &correlation_id).await;
        assert!(result.is_ok());
        let output = result.unwrap();
        // With quotes, the output should contain the quoted data
        assert!(output.contains("\"test|data|with|pipes\""));

        // Test with quote_data = false
        let config_without_quotes = ExternalAppConfig {
            command: "echo".to_string(),
            args: vec!["Data:".to_string()],
            timeout_seconds: 5,
            working_directory: None,
            environment: None,
            max_data_length: 4096,
            allow_control_chars: false,
            sanitize_input: true,
            quote_data: false,
        };

        let result = execute_external_app(&config_without_quotes, test_data, &correlation_id).await;
        assert!(result.is_ok());
        let output = result.unwrap();
        // Without quotes, the output should contain the unquoted data
        assert!(output.contains("test|data|with|pipes"));
        assert!(!output.contains("\"test|data|with|pipes\""));
    }
}
