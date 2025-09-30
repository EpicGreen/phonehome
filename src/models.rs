use serde::{Deserialize, Serialize};
use serde_json;
use tracing::{debug, info, warn};

/// Cloud Init phone home data structure
/// This represents the data that Cloud Init sends in its phone home request
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct PhoneHomeData {
    /// Instance ID from cloud metadata
    pub instance_id: Option<String>,

    /// Hostname of the instance
    pub hostname: Option<String>,

    /// Fully qualified domain name
    pub fqdn: Option<String>,

    /// RSA public key
    pub pub_key_rsa: Option<String>,

    /// ECDSA public key
    pub pub_key_ecdsa: Option<String>,

    /// Ed25519 public key
    pub pub_key_ed25519: Option<String>,
}

/// Processed data that will be passed to the external application
#[derive(Debug, Clone, Serialize)]
pub struct ProcessedPhoneHomeData {
    /// Timestamp when the request was received
    pub timestamp: chrono::DateTime<chrono::Utc>,

    /// Original instance ID
    pub instance_id: Option<String>,

    /// Extracted field values in the order specified in configuration
    pub extracted_fields: Vec<String>,

    /// Formatted string ready for external application
    pub formatted_data: String,

    /// Raw phone home data for debugging
    pub raw_data: PhoneHomeData,
}

impl PhoneHomeData {
    /// Extract field values based on configuration
    pub fn extract_field_value(&self, field_name: &str) -> Option<String> {
        debug!("Extracting field value for: '{}'", field_name);

        let result = match field_name {
            "instance_id" => self.instance_id.clone(),
            "hostname" => self.hostname.clone(),
            "fqdn" => self.fqdn.clone(),
            "pub_key_rsa" => self.pub_key_rsa.clone(),
            "pub_key_ecdsa" => self.pub_key_ecdsa.clone(),
            "pub_key_ed25519" => self.pub_key_ed25519.clone(),
            _ => {
                warn!("Unknown field requested: '{}'", field_name);
                None
            }
        };

        if let Some(value) = &result {
            debug!("Field '{}' extracted: '{}'", field_name, value);
        } else {
            debug!("Field '{}' not found or empty", field_name);
        }

        result
    }

    /// Process the phone home data according to configuration
    pub fn process(&self, config: &crate::config::PhoneHomeConfig) -> ProcessedPhoneHomeData {
        info!("Starting phone home data processing");
        debug!("Processing configuration: {:#?}", config);
        debug!("Raw phone home data: {:#?}", self);

        let mut extracted_fields = Vec::new();

        // Add timestamp if configured
        if config.include_timestamp {
            let timestamp = chrono::Utc::now().to_rfc3339();
            debug!("Adding timestamp: {}", timestamp);
            extracted_fields.push(timestamp);
        } else {
            debug!("Timestamp not included in configuration");
        }

        // Add instance ID if configured and available
        if config.include_instance_id {
            if let Some(ref instance_id) = self.instance_id {
                debug!("Adding instance ID: {}", instance_id);
                extracted_fields.push(instance_id.clone());
            } else {
                debug!("Instance ID not available, using 'unknown'");
                extracted_fields.push("unknown".to_string());
            }
        } else {
            debug!("Instance ID not included in configuration");
        }

        // Extract configured fields
        debug!(
            "Extracting {} configured fields",
            config.fields_to_extract.len()
        );
        for (index, field_name) in config.fields_to_extract.iter().enumerate() {
            debug!(
                "Processing field {}/{}: '{}'",
                index + 1,
                config.fields_to_extract.len(),
                field_name
            );
            let value = self.extract_field_value(field_name).unwrap_or_default();
            if value.is_empty() {
                warn!("Field '{}' extracted as empty value", field_name);
            }
            extracted_fields.push(value);
        }

        // Format the data according to output type
        debug!(
            "Formatting {} extracted fields with output type: '{}'",
            extracted_fields.len(),
            config.output_type
        );
        let formatted_data = match config.output_type.to_lowercase().as_str() {
            "json" => format_as_json(&extracted_fields, config),
            "sql" => format_as_sql(&extracted_fields, config),
            "string" => {
                debug!(
                    "Using string format with separator: '{}'",
                    config.field_separator
                );
                extracted_fields.join(&config.field_separator)
            }
            _ => {
                debug!(
                    "Using string format with separator: '{}'",
                    config.field_separator
                );
                extracted_fields.join(&config.field_separator)
            }
        };
        debug!("Formatted data result: '{}'", formatted_data);
        info!(
            "Data processing completed - extracted {} fields as {}",
            extracted_fields.len(),
            config.output_type
        );

        let processed_data = ProcessedPhoneHomeData {
            timestamp: chrono::Utc::now(),
            instance_id: self.instance_id.clone(),
            extracted_fields,
            formatted_data,
            raw_data: self.clone(),
        };

        debug!("Final processed data: {:#?}", processed_data);
        processed_data
    }
}

/// Format extracted fields as JSON
fn format_as_json(extracted_fields: &[String], config: &crate::config::PhoneHomeConfig) -> String {
    debug!("Formatting data as JSON");

    let mut json_obj = serde_json::Map::new();
    let mut field_index = 0;

    // Add timestamp if configured
    if config.include_timestamp && !extracted_fields.is_empty() {
        json_obj.insert(
            "timestamp".to_string(),
            serde_json::Value::String(extracted_fields[field_index].clone()),
        );
        field_index += 1;
        debug!("Added timestamp to JSON object");
    }

    // Add instance ID if configured
    if config.include_instance_id && field_index < extracted_fields.len() {
        json_obj.insert(
            "instance_id".to_string(),
            serde_json::Value::String(extracted_fields[field_index].clone()),
        );
        field_index += 1;
        debug!("Added instance_id to JSON object");
    }

    // Add configured fields
    for field_name in &config.fields_to_extract {
        if field_index < extracted_fields.len() {
            json_obj.insert(
                field_name.clone(),
                serde_json::Value::String(extracted_fields[field_index].clone()),
            );
            field_index += 1;
            debug!("Added field '{}' to JSON object", field_name);
        }
    }

    let json_result = serde_json::to_string(&json_obj).unwrap_or_else(|e| {
        warn!("Failed to serialize JSON: {}", e);
        "{}".to_string()
    });

    debug!("JSON formatting completed");
    json_result
}

/// Format extracted fields as SQL INSERT query
fn format_as_sql(extracted_fields: &[String], config: &crate::config::PhoneHomeConfig) -> String {
    debug!("Formatting data as SQL INSERT query");

    let mut columns = Vec::new();
    let mut values = Vec::new();
    let mut field_index = 0;

    // Add timestamp if configured
    if config.include_timestamp && !extracted_fields.is_empty() {
        columns.push("timestamp".to_string());
        values.push(format!(
            "'{}'",
            escape_sql_value(&extracted_fields[field_index])
        ));
        field_index += 1;
        debug!("Added timestamp to SQL columns");
    }

    // Add instance ID if configured
    if config.include_instance_id && field_index < extracted_fields.len() {
        columns.push("instance_id".to_string());
        values.push(format!(
            "'{}'",
            escape_sql_value(&extracted_fields[field_index])
        ));
        field_index += 1;
        debug!("Added instance_id to SQL columns");
    }

    // Add configured fields
    for field_name in &config.fields_to_extract {
        if field_index < extracted_fields.len() {
            columns.push(field_name.clone());
            values.push(format!(
                "'{}'",
                escape_sql_value(&extracted_fields[field_index])
            ));
            field_index += 1;
            debug!("Added field '{}' to SQL columns", field_name);
        }
    }

    let sql_query = if columns.is_empty() {
        "INSERT INTO phone_home_data DEFAULT VALUES;".to_string()
    } else {
        format!(
            "INSERT INTO phone_home_data ({}) VALUES ({});",
            columns.join(", "),
            values.join(", ")
        )
    };

    debug!("SQL formatting completed");
    sql_query
}

/// Escape SQL values to prevent injection
fn escape_sql_value(value: &str) -> String {
    value.replace('\'', "''")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PhoneHomeConfig;

    #[test]
    fn test_format_as_json() {
        let fields = vec![
            "2023-12-01T10:00:00Z".to_string(),
            "i-1234567890abcdef0".to_string(),
            "test-host".to_string(),
        ];

        let config = PhoneHomeConfig {
            fields_to_extract: vec!["hostname".to_string()],
            field_separator: "|".to_string(),
            include_timestamp: true,
            include_instance_id: true,
            output_type: "json".to_string(),
        };

        let result = format_as_json(&fields, &config);
        assert!(result.contains("\"timestamp\""));
        assert!(result.contains("\"instance_id\""));
        assert!(result.contains("\"hostname\""));
        assert!(result.contains("2023-12-01T10:00:00Z"));
        assert!(result.contains("i-1234567890abcdef0"));
        assert!(result.contains("test-host"));
    }

    #[test]
    fn test_format_as_sql() {
        let fields = vec![
            "2023-12-01T10:00:00Z".to_string(),
            "i-1234567890abcdef0".to_string(),
            "test-host".to_string(),
        ];

        let config = PhoneHomeConfig {
            fields_to_extract: vec!["hostname".to_string()],
            field_separator: "|".to_string(),
            include_timestamp: true,
            include_instance_id: true,
            output_type: "sql".to_string(),
        };

        let result = format_as_sql(&fields, &config);
        assert!(result.starts_with("INSERT INTO phone_home_data"));
        assert!(result.contains("timestamp"));
        assert!(result.contains("instance_id"));
        assert!(result.contains("hostname"));
        assert!(result.contains("'2023-12-01T10:00:00Z'"));
        assert!(result.contains("'i-1234567890abcdef0'"));
        assert!(result.contains("'test-host'"));
        assert!(result.ends_with(");"));
    }

    #[test]
    fn test_sql_value_escaping() {
        let value_with_quote = "test'value";
        let escaped = escape_sql_value(value_with_quote);
        assert_eq!(escaped, "test''value");
    }

    #[test]
    fn test_field_extraction() {
        let phone_home_data = PhoneHomeData {
            instance_id: Some("i-1234567890abcdef0".to_string()),
            hostname: Some("test-host".to_string()),
            pub_key_rsa: Some("ssh-rsa AAAAB3...".to_string()),
            pub_key_ed25519: Some("ssh-ed25519 AAAAC3...".to_string()),
            ..Default::default()
        };

        assert_eq!(
            phone_home_data.extract_field_value("instance_id"),
            Some("i-1234567890abcdef0".to_string())
        );
        assert_eq!(
            phone_home_data.extract_field_value("hostname"),
            Some("test-host".to_string())
        );
        assert_eq!(
            phone_home_data.extract_field_value("pub_key_rsa"),
            Some("ssh-rsa AAAAB3...".to_string())
        );
        assert_eq!(
            phone_home_data.extract_field_value("pub_key_ed25519"),
            Some("ssh-ed25519 AAAAC3...".to_string())
        );
        assert_eq!(phone_home_data.extract_field_value("nonexistent"), None);
    }

    #[test]
    fn test_data_processing() {
        let phone_home_data = PhoneHomeData {
            instance_id: Some("i-1234567890abcdef0".to_string()),
            hostname: Some("test-host".to_string()),
            ..Default::default()
        };

        let config = PhoneHomeConfig {
            fields_to_extract: vec!["hostname".to_string(), "instance_id".to_string()],
            field_separator: "|".to_string(),
            include_timestamp: false,
            include_instance_id: false,
            output_type: "string".to_string(),
        };

        let processed = phone_home_data.process(&config);
        assert_eq!(processed.formatted_data, "test-host|i-1234567890abcdef0");
        assert_eq!(processed.extracted_fields.len(), 2);
    }

    #[test]
    fn test_data_processing_with_timestamp_and_instance_id() {
        let phone_home_data = PhoneHomeData {
            instance_id: Some("i-1234567890abcdef0".to_string()),
            hostname: Some("test-host".to_string()),
            ..Default::default()
        };

        let config = PhoneHomeConfig {
            fields_to_extract: vec!["hostname".to_string()],
            field_separator: "|".to_string(),
            include_timestamp: true,
            include_instance_id: true,
            output_type: "string".to_string(),
        };

        let processed = phone_home_data.process(&config);
        // Should have timestamp, instance_id, and hostname
        assert_eq!(processed.extracted_fields.len(), 3);
        assert!(processed.formatted_data.contains("test-host"));
        assert!(processed.formatted_data.contains("i-1234567890abcdef0"));
    }

    #[test]
    fn test_all_supported_fields() {
        let phone_home_data = PhoneHomeData {
            instance_id: Some("i-1234567890abcdef0".to_string()),
            hostname: Some("test-host".to_string()),
            fqdn: Some("test-host.example.com".to_string()),
            pub_key_rsa: Some("ssh-rsa AAAAB3...".to_string()),
            pub_key_ecdsa: Some("ecdsa-sha2-nistp256 AAAAE2V...".to_string()),
            pub_key_ed25519: Some("ssh-ed25519 AAAAC3...".to_string()),
        };

        // Test all supported fields
        assert!(phone_home_data.extract_field_value("instance_id").is_some());
        assert!(phone_home_data.extract_field_value("hostname").is_some());
        assert!(phone_home_data.extract_field_value("fqdn").is_some());
        assert!(phone_home_data.extract_field_value("pub_key_rsa").is_some());
        assert!(phone_home_data
            .extract_field_value("pub_key_ecdsa")
            .is_some());
        assert!(phone_home_data
            .extract_field_value("pub_key_ed25519")
            .is_some());
    }

    #[test]
    fn test_json_output_type() {
        let phone_home_data = PhoneHomeData {
            instance_id: Some("i-1234567890abcdef0".to_string()),
            hostname: Some("test-host".to_string()),
            ..Default::default()
        };

        let config = PhoneHomeConfig {
            fields_to_extract: vec!["hostname".to_string()],
            field_separator: "|".to_string(),
            include_timestamp: false,
            include_instance_id: true,
            output_type: "json".to_string(),
        };

        let processed = phone_home_data.process(&config);
        assert!(processed.formatted_data.starts_with("{"));
        assert!(processed.formatted_data.ends_with("}"));
        assert!(processed.formatted_data.contains("\"instance_id\""));
        assert!(processed.formatted_data.contains("\"hostname\""));
    }

    #[test]
    fn test_sql_output_type() {
        let phone_home_data = PhoneHomeData {
            instance_id: Some("i-1234567890abcdef0".to_string()),
            hostname: Some("test-host".to_string()),
            ..Default::default()
        };

        let config = PhoneHomeConfig {
            fields_to_extract: vec!["hostname".to_string()],
            field_separator: "|".to_string(),
            include_timestamp: false,
            include_instance_id: true,
            output_type: "sql".to_string(),
        };

        let processed = phone_home_data.process(&config);
        assert!(processed
            .formatted_data
            .starts_with("INSERT INTO phone_home_data"));
        assert!(processed.formatted_data.contains("instance_id"));
        assert!(processed.formatted_data.contains("hostname"));
        assert!(processed.formatted_data.ends_with(");"));
    }
}
