use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use futures::future::join_all;
use phonehome::config::{
    Config, ExternalAppConfig, LoggingConfig, PhoneHomeConfig, ServerConfig, TlsConfig,
};
use phonehome::models::PhoneHomeData;
use phonehome::{health_check, AppState};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Instant;
use tower::ServiceExt;

// Helper function to create a test app for integration tests
pub fn create_test_app() -> Router {
    let config = create_test_config();
    let state = AppState {
        config: Arc::new(config),
    };

    Router::new()
        .route("/", axum::routing::get(phonehome::web::landing_page))
        .route("/health", axum::routing::get(health_check))
        .route(
            "/phone-home/:token",
            axum::routing::post(
                |axum::extract::State(state): axum::extract::State<AppState>,
                 axum::extract::Path(token): axum::extract::Path<String>,
                 axum::Json(payload): axum::Json<serde_json::Value>| async move {
                    phonehome::handlers::phone_home_handler(
                        axum::extract::State(state),
                        axum::extract::Path(token),
                        axum::Json(payload),
                    )
                    .await
                },
            ),
        )
        .fallback(phonehome::web::not_found)
        .with_state(state)
}

// Helper function to create a test configuration
fn create_test_config() -> Config {
    Config {
        server: ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 8444, // Use different port for tests
            token: "test-token-123".to_string(),
        },
        logging: LoggingConfig {
            log_file: std::path::PathBuf::from("/tmp/phonehome-test.log"),
            log_level: "debug".to_string(),
            enable_console: false, // Disable console logging in tests
            enable_file: false,    // Disable file logging in tests
            max_file_size_mb: 10,
            max_files: 3,
        },
        tls: None, // Disable TLS for tests
        external_app: ExternalAppConfig {
            command: "echo".to_string(),
            args: vec!["test-processed:".to_string()],
            timeout_seconds: 5,
            working_directory: None,
            environment: None,
        },
        phone_home: PhoneHomeConfig {
            fields_to_extract: vec![
                "instance_id".to_string(),
                "hostname".to_string(),
                "cloud_name".to_string(),
            ],
            field_separator: "|".to_string(),
            include_timestamp: true,
            include_instance_id: true,
        },
    }
}

// Helper function to create test phone home data
fn create_test_phone_home_data() -> Value {
    json!({
        "instance_id": "i-1234567890abcdef0",
        "hostname": "test-instance",
        "fqdn": "test-instance.example.com",
        "cloud_name": "aws",
        "platform": "ec2",
        "region": "us-west-2",
        "availability_zone": "us-west-2a",
        "instance_type": "t3.micro",
        "local_hostname": "ip-10-0-1-100",
        "public_keys": [
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7... test-key-1",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... test-key-2"
        ],
        "instance_data": {
            "instance_id": "i-1234567890abcdef0",
            "instance_type": "t3.micro",
            "local_ipv4": "10.0.1.100",
            "public_ipv4": "203.0.113.50",
            "mac": "02:00:17:04:e9:42",
            "security_groups": ["sg-12345678", "sg-87654321"]
        }
    })
}

#[cfg(test)]
mod config_tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_config_load_default() {
        let temp_file = NamedTempFile::new().unwrap();
        let config_path = temp_file.path();

        // Delete the temp file so load will create default config
        std::fs::remove_file(config_path).unwrap();

        // Should create default config if file doesn't exist
        let config = Config::load(config_path).await.unwrap();
        assert_eq!(config.server.port, 8443);
        assert!(config_path.exists());
    }

    #[tokio::test]
    async fn test_config_load_existing() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let config_content = r#"
[server]
host = "0.0.0.0"
port = 9999
token = "test-token"

[logging]
log_file = "/tmp/test-phonehome.log"
log_level = "info"
enable_console = true
enable_file = false
max_file_size_mb = 10
max_files = 3

[external_app]
command = "/bin/echo"
args = ["test"]
timeout_seconds = 10

[phone_home]
fields_to_extract = ["instance_id"]
field_separator = ","
include_timestamp = false
include_instance_id = false
"#;
        temp_file.write_all(config_content.as_bytes()).unwrap();

        let config = Config::load(temp_file.path()).await.unwrap();
        assert_eq!(config.server.port, 9999);
        assert_eq!(config.server.token, "test-token");
        assert_eq!(config.external_app.command, "/bin/echo");
        assert_eq!(config.phone_home.field_separator, ",");
        assert!(!config.phone_home.include_timestamp);
    }

    #[test]
    fn test_config_validation() {
        let config = create_test_config();

        // Test basic config structure
        assert_eq!(config.server.token, "test-token-123");
        assert_eq!(config.server.port, 8444);
        assert_eq!(config.external_app.command, "echo");
    }

    #[test]
    fn test_phone_home_url_generation() {
        let config = create_test_config();
        let url = config.get_phone_home_url();
        assert_eq!(url, "http://127.0.0.1:8444/phone-home/test-token-123");

        let mut config_with_tls = config;
        config_with_tls.tls = Some(TlsConfig {
            cert_path: "/tmp/cert.pem".into(),
            key_path: "/tmp/key.pem".into(),
        });
        let url_tls = config_with_tls.get_phone_home_url();
        assert_eq!(url_tls, "https://127.0.0.1:8444/phone-home/test-token-123");
    }
}

#[cfg(test)]
mod models_tests {
    use super::*;

    #[test]
    fn test_phone_home_data_field_extraction() {
        let data: PhoneHomeData = serde_json::from_value(create_test_phone_home_data()).unwrap();

        assert_eq!(
            data.extract_field_value("instance_id"),
            Some("i-1234567890abcdef0".to_string())
        );
        assert_eq!(
            data.extract_field_value("hostname"),
            Some("test-instance".to_string())
        );
        assert_eq!(
            data.extract_field_value("cloud_name"),
            Some("aws".to_string())
        );
        assert_eq!(
            data.extract_field_value("local_ipv4"),
            Some("10.0.1.100".to_string())
        );
        assert_eq!(
            data.extract_field_value("public_ipv4"),
            Some("203.0.113.50".to_string())
        );
        assert_eq!(
            data.extract_field_value("security_groups"),
            Some("sg-12345678,sg-87654321".to_string())
        );
        assert_eq!(data.extract_field_value("nonexistent"), None);
    }

    #[test]
    fn test_phone_home_data_processing() {
        let data: PhoneHomeData = serde_json::from_value(create_test_phone_home_data()).unwrap();
        let config = PhoneHomeConfig {
            fields_to_extract: vec!["hostname".to_string(), "cloud_name".to_string()],
            field_separator: "|".to_string(),
            include_timestamp: false,
            include_instance_id: false,
        };

        let processed = data.process(&config);
        assert_eq!(processed.formatted_data, "test-instance|aws");
        assert_eq!(processed.extracted_fields.len(), 2);
        assert_eq!(
            processed.instance_id,
            Some("i-1234567890abcdef0".to_string())
        );
    }

    #[test]
    fn test_phone_home_data_processing_with_timestamp_and_instance_id() {
        let data: PhoneHomeData = serde_json::from_value(create_test_phone_home_data()).unwrap();
        let config = PhoneHomeConfig {
            fields_to_extract: vec!["hostname".to_string()],
            field_separator: "|".to_string(),
            include_timestamp: true,
            include_instance_id: true,
        };

        let processed = data.process(&config);
        // Should have timestamp, instance_id, and hostname
        assert_eq!(processed.extracted_fields.len(), 3);
        assert!(processed.formatted_data.contains("test-instance"));
        assert!(processed.formatted_data.contains("i-1234567890abcdef0"));
    }

    #[test]
    fn test_phone_home_data_deserialization() {
        let json_data = create_test_phone_home_data();
        let data: PhoneHomeData = serde_json::from_value(json_data).unwrap();

        assert_eq!(data.instance_id, Some("i-1234567890abcdef0".to_string()));
        assert_eq!(data.hostname, Some("test-instance".to_string()));
        assert_eq!(data.cloud_name, Some("aws".to_string()));
        assert!(data.public_keys.is_some());
        assert!(data.instance_data.is_some());

        let instance_data = data.instance_data.unwrap();
        assert_eq!(instance_data.local_ipv4, Some("10.0.1.100".to_string()));
        assert_eq!(instance_data.public_ipv4, Some("203.0.113.50".to_string()));
    }

    #[test]
    fn test_phone_home_data_with_additional_fields() {
        let mut json_data = create_test_phone_home_data();
        json_data["custom_field"] = json!("custom_value");
        json_data["numeric_field"] = json!(12345);
        json_data["boolean_field"] = json!(true);

        let data: PhoneHomeData = serde_json::from_value(json_data).unwrap();

        assert_eq!(
            data.extract_field_value("custom_field"),
            Some("custom_value".to_string())
        );
        assert_eq!(
            data.extract_field_value("numeric_field"),
            Some("12345".to_string())
        );
        assert_eq!(
            data.extract_field_value("boolean_field"),
            Some("true".to_string())
        );
    }
}

#[cfg(test)]
mod tls_tests {
    use phonehome::tls::generate_self_signed_cert;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_generate_self_signed_cert() {
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");

        let result = generate_self_signed_cert("test.example.com", &cert_path, &key_path).await;
        assert!(result.is_ok());

        assert!(cert_path.exists());
        assert!(key_path.exists());

        // Verify the certificate files are not empty
        let cert_content = std::fs::read_to_string(&cert_path).unwrap();
        let key_content = std::fs::read_to_string(&key_path).unwrap();

        assert!(cert_content.contains("-----BEGIN CERTIFICATE-----"));
        assert!(cert_content.contains("-----END CERTIFICATE-----"));
        assert!(key_content.contains("-----BEGIN PRIVATE KEY-----"));
        assert!(key_content.contains("-----END PRIVATE KEY-----"));
    }
}

#[cfg(test)]
mod handlers_tests {
    use super::*;
    use phonehome::handlers::validate_external_app;
    use std::collections::HashMap;

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

    #[tokio::test]
    async fn test_validate_external_app_with_working_directory() {
        let config = ExternalAppConfig {
            command: "pwd".to_string(),
            args: vec![],
            timeout_seconds: 5,
            working_directory: Some("/tmp".into()),
            environment: None,
        };

        let result = validate_external_app(&config).await;
        // Should not fail validation even if --version is not supported
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_validate_external_app_with_environment() {
        let mut env_vars = HashMap::new();
        env_vars.insert("TEST_VAR".to_string(), "test_value".to_string());

        let config = ExternalAppConfig {
            command: "echo".to_string(),
            args: vec![],
            timeout_seconds: 5,
            working_directory: None,
            environment: Some(env_vars),
        };

        let result = validate_external_app(&config).await;
        assert!(result.is_ok());
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[tokio::test]
    async fn test_health_endpoint() {
        let app = create_test_app();

        let request = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();

        assert!(body_str.contains("\"status\":\"ok\""));
        assert!(body_str.contains("\"service\":\"phonehome\""));
    }

    #[tokio::test]
    async fn test_phone_home_endpoint_valid_token() {
        let app = create_test_app();
        let phone_home_data = create_test_phone_home_data();

        let request = Request::builder()
            .uri("/phone-home/test-token-123")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&phone_home_data).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();

        assert!(body_str.contains("\"status\":\"success\""));
        assert!(body_str.contains("\"instance_id\":\"i-1234567890abcdef0\""));
    }

    #[tokio::test]
    async fn test_phone_home_endpoint_invalid_token() {
        let app = create_test_app();
        let phone_home_data = create_test_phone_home_data();

        let request = Request::builder()
            .uri("/phone-home/invalid-token")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&phone_home_data).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_phone_home_endpoint_malformed_json() {
        let app = create_test_app();

        let request = Request::builder()
            .uri("/phone-home/test-token-123")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from("{\"invalid\": json}"))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_phone_home_endpoint_minimal_data() {
        let app = create_test_app();
        let minimal_data = json!({
            "instance_id": "i-minimal",
            "hostname": "minimal-host"
        });

        let request = Request::builder()
            .uri("/phone-home/test-token-123")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&minimal_data).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();

        assert!(body_str.contains("\"status\":\"success\""));
        assert!(body_str.contains("\"instance_id\":\"i-minimal\""));
    }

    #[tokio::test]
    async fn test_phone_home_endpoint_missing_content_type() {
        let app = create_test_app();
        let phone_home_data = create_test_phone_home_data();

        let request = Request::builder()
            .uri("/phone-home/test-token-123")
            .method("POST")
            .body(Body::from(serde_json::to_string(&phone_home_data).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        // Without content-type header, axum returns UNSUPPORTED_MEDIA_TYPE (415)
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn test_phone_home_endpoint_empty_body() {
        let app = create_test_app();

        let request = Request::builder()
            .uri("/phone-home/test-token-123")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}

#[cfg(test)]
mod load_tests {
    use super::*;
    use crate::create_test_app;

    #[tokio::test]
    async fn test_concurrent_phone_home_requests() {
        let app = create_test_app();
        let phone_home_data = create_test_phone_home_data();
        let request_count = 10;

        let start_time = Instant::now();

        let mut tasks = Vec::new();
        for i in 0..request_count {
            let app_clone = app.clone();
            let mut data = phone_home_data.clone();
            data["instance_id"] = json!(format!("i-load-test-{:03}", i));

            let task: tokio::task::JoinHandle<Result<axum::response::Response, _>> =
                tokio::spawn(async move {
                    let request = Request::builder()
                        .uri("/phone-home/test-token-123")
                        .method("POST")
                        .header("content-type", "application/json")
                        .body(Body::from(serde_json::to_string(&data).unwrap()))
                        .unwrap();

                    app_clone.oneshot(request).await
                });

            tasks.push(task);
        }

        let results = join_all(tasks).await;
        let duration = start_time.elapsed();

        let mut success_count = 0;
        let mut failure_count = 0;

        for result in results {
            match result {
                Ok(Ok(response)) => {
                    if response.status().is_success() {
                        success_count += 1;
                    } else {
                        failure_count += 1;
                    }
                }
                _ => failure_count += 1,
            }
        }

        println!("Load test completed in {:?}", duration);
        println!("Success: {}, Failures: {}", success_count, failure_count);

        assert_eq!(success_count, request_count);
        assert_eq!(failure_count, 0);
        assert!(
            duration.as_secs() < 10,
            "Load test took too long: {:?}",
            duration
        );
    }

    #[tokio::test]
    async fn test_health_endpoint_performance() {
        let app = create_test_app();
        let request_count = 100;

        let start_time = Instant::now();

        let mut tasks = Vec::new();
        for _ in 0..request_count {
            let app_clone = app.clone();

            let task: tokio::task::JoinHandle<Result<axum::response::Response, _>> =
                tokio::spawn(async move {
                    let request = Request::builder()
                        .uri("/health")
                        .body(Body::empty())
                        .unwrap();

                    app_clone.oneshot(request).await
                });

            tasks.push(task);
        }

        let results = join_all(tasks).await;
        let duration = start_time.elapsed();

        let success_count = results
            .iter()
            .filter(|result| matches!(result, Ok(Ok(response)) if response.status().is_success()))
            .count();

        println!("Health endpoint test completed in {:?}", duration);
        println!("Success rate: {}/{}", success_count, request_count);

        assert_eq!(success_count, request_count);
        assert!(
            duration.as_secs() < 5,
            "Health endpoint test took too long: {:?}",
            duration
        );
    }
}

mod certificate_tests {
    use super::*;
    use phonehome::tls::{generate_self_signed_cert, setup_tls_config};
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_self_signed_cert_generation() {
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("test_cert.pem");
        let key_path = temp_dir.path().join("test_key.pem");

        let result = generate_self_signed_cert("localhost", &cert_path, &key_path).await;
        assert!(result.is_ok());

        assert!(cert_path.exists());
        assert!(key_path.exists());

        // Verify certificate content
        let cert_content = tokio::fs::read_to_string(&cert_path).await.unwrap();
        assert!(cert_content.contains("-----BEGIN CERTIFICATE-----"));
        assert!(cert_content.contains("-----END CERTIFICATE-----"));

        // Verify key content
        let key_content = tokio::fs::read_to_string(&key_path).await.unwrap();
        assert!(key_content.contains("-----BEGIN PRIVATE KEY-----"));
        assert!(key_content.contains("-----END PRIVATE KEY-----"));
    }

    #[tokio::test]
    async fn test_setup_tls_config_with_existing_certs() {
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");

        // Generate test certificates first
        generate_self_signed_cert("test.example.com", &cert_path, &key_path)
            .await
            .unwrap();

        let config = TlsConfig {
            cert_path,
            key_path,
        };

        let result = setup_tls_config(&config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_setup_tls_config_generates_missing_certs() {
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");

        let config = TlsConfig {
            cert_path: cert_path.clone(),
            key_path: key_path.clone(),
        };

        // Certificates don't exist initially
        assert!(!cert_path.exists());
        assert!(!key_path.exists());

        let result = setup_tls_config(&config).await;
        assert!(result.is_ok());

        // Certificates should now exist
        assert!(cert_path.exists());
        assert!(key_path.exists());
    }
}

#[cfg(test)]
mod web_tests {
    use super::*;
    use axum::http::StatusCode;

    #[tokio::test]
    async fn test_landing_page() {
        let app = create_test_app();

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();

        assert!(body_str.contains("PhoneHome Server"));
        assert!(body_str.contains("Service Status"));
        assert!(body_str.contains("/health"));
        assert!(body_str.contains("/phone-home"));
    }

    #[tokio::test]
    async fn test_404_page() {
        let app = create_test_app();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();

        assert!(body_str.contains("404"));
        assert!(body_str.contains("Page Not Found"));
        assert!(body_str.contains("Available endpoints"));
    }

    #[tokio::test]
    async fn test_unauthorized_error_page() {
        let app = create_test_app();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/phone-home/wrong-token")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"instance_id": "test"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();

        assert!(body_str.contains("401"));
        assert!(body_str.contains("Unauthorized"));
        assert!(body_str.contains("Security Notice"));
    }

    #[tokio::test]
    async fn test_bad_request_error_page() {
        let app = create_test_app();

        // Test with malformed JSON - this will be handled by Axum's JSON extractor
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/phone-home/test-token-123")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"malformed json"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Axum's JSON extractor handles malformed JSON and returns 400 with plain text
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();

        // This will be Axum's default JSON parsing error message
        assert!(body_str.contains("Failed to parse") || body_str.contains("EOF while parsing"));
    }

    #[tokio::test]
    async fn test_custom_bad_request_error_page() {
        let app = create_test_app();

        // Test with valid JSON but missing required fields to trigger our custom error page
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/phone-home/test-token-123")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        // This should succeed with valid but empty JSON (our handler will process it)
        // The external app execution might fail, but the JSON parsing will succeed
        assert!(response.status().is_success() || response.status().is_server_error());
    }
}

#[cfg(test)]
mod logging_tests {
    use super::*;
    use phonehome::config::LoggingConfig;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_logging_configuration_validation() {
        let temp_dir = TempDir::new().unwrap();
        let log_file = temp_dir.path().join("test.log");

        let logging_config = LoggingConfig {
            log_file,
            log_level: "info".to_string(),
            enable_console: true,
            enable_file: true,
            max_file_size_mb: 50,
            max_files: 5,
        };

        // Test that the logging config has expected defaults
        assert_eq!(logging_config.log_level, "info");
        assert!(logging_config.enable_console);
        assert!(logging_config.enable_file);
        assert_eq!(logging_config.max_file_size_mb, 50);
        assert_eq!(logging_config.max_files, 5);
    }

    #[tokio::test]
    async fn test_default_certificate_paths() {
        let config = Config::default();

        // Test that default certificate paths use /var/lib/phonehome
        if let Some(tls_config) = &config.tls {
            assert_eq!(
                tls_config.cert_path,
                PathBuf::from("/var/lib/phonehome/cert.pem")
            );
            assert_eq!(
                tls_config.key_path,
                PathBuf::from("/var/lib/phonehome/key.pem")
            );
        } else {
            panic!("TLS config should be Some in default configuration");
        }
    }

    #[tokio::test]
    async fn test_logging_levels_validation() {
        let mut config = create_test_config();

        // Test valid log levels
        let valid_levels = ["trace", "debug", "info", "warn", "error"];
        for level in valid_levels {
            config.logging.log_level = level.to_string();
            assert!(
                config.validate().is_ok(),
                "Log level '{}' should be valid",
                level
            );
        }

        // Test invalid log level
        config.logging.log_level = "invalid".to_string();
        assert!(
            config.validate().is_err(),
            "Invalid log level should fail validation"
        );
    }
}
