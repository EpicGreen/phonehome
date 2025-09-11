use serde::{Deserialize, Serialize};
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

        // Format the data string
        debug!(
            "Formatting {} extracted fields with separator: '{}'",
            extracted_fields.len(),
            config.field_separator
        );
        let formatted_data = extracted_fields.join(&config.field_separator);
        debug!("Formatted data result: '{}'", formatted_data);
        info!(
            "Data processing completed - extracted {} fields",
            extracted_fields.len()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PhoneHomeConfig;

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
}
