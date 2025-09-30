use phonehome::{config::PhoneHomeConfig, models::PhoneHomeData};

#[cfg(test)]
mod output_type_tests {
    use super::*;

    fn create_sample_data() -> PhoneHomeData {
        PhoneHomeData {
            instance_id: Some("i-1234567890abcdef0".to_string()),
            hostname: Some("test-host".to_string()),
            fqdn: Some("test-host.example.com".to_string()),
            pub_key_rsa: Some("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ...".to_string()),
            pub_key_ecdsa: Some("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTI...".to_string()),
            pub_key_ed25519: Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...".to_string()),
        }
    }

    fn create_base_config() -> PhoneHomeConfig {
        PhoneHomeConfig {
            fields_to_extract: vec![
                "hostname".to_string(),
                "fqdn".to_string(),
                "pub_key_rsa".to_string(),
            ],
            field_separator: "|".to_string(),
            include_timestamp: true,
            include_instance_id: true,
            output_type: "string".to_string(),
        }
    }

    #[test]
    fn test_string_output_type_complete() {
        let data = create_sample_data();
        let config = PhoneHomeConfig {
            output_type: "string".to_string(),
            ..create_base_config()
        };

        let result = data.process(&config);

        // Should have 5 fields: timestamp, instance_id, hostname, fqdn, pub_key_rsa
        assert_eq!(result.extracted_fields.len(), 5);

        // Should contain pipe separators
        assert!(result.formatted_data.contains("|"));

        // Should contain expected data
        assert!(result.formatted_data.contains("test-host"));
        assert!(result.formatted_data.contains("test-host.example.com"));
        assert!(result.formatted_data.contains("i-1234567890abcdef0"));
        assert!(result.formatted_data.contains("ssh-rsa"));

        // Should start with timestamp (ISO format)
        assert!(result.formatted_data.contains("T") && result.formatted_data.contains("+"));
    }

    #[test]
    fn test_json_output_type_complete() {
        let data = create_sample_data();
        let config = PhoneHomeConfig {
            output_type: "json".to_string(),
            ..create_base_config()
        };

        let result = data.process(&config);

        // Should have 5 fields extracted
        assert_eq!(result.extracted_fields.len(), 5);

        // Should be valid JSON
        assert!(result.formatted_data.starts_with("{"));
        assert!(result.formatted_data.ends_with("}"));

        // Parse as JSON to verify structure
        let json_value: serde_json::Value =
            serde_json::from_str(&result.formatted_data).expect("Should be valid JSON");

        // Verify all expected fields are present
        assert!(json_value.get("timestamp").is_some());
        assert!(json_value.get("instance_id").is_some());
        assert!(json_value.get("hostname").is_some());
        assert!(json_value.get("fqdn").is_some());
        assert!(json_value.get("pub_key_rsa").is_some());

        // Verify field values
        assert_eq!(json_value["hostname"], "test-host");
        assert_eq!(json_value["fqdn"], "test-host.example.com");
        assert_eq!(json_value["instance_id"], "i-1234567890abcdef0");
        assert!(json_value["pub_key_rsa"]
            .as_str()
            .unwrap()
            .starts_with("ssh-rsa"));
    }

    #[test]
    fn test_sql_output_type_complete() {
        let data = create_sample_data();
        let config = PhoneHomeConfig {
            output_type: "sql".to_string(),
            ..create_base_config()
        };

        let result = data.process(&config);

        // Should have 5 fields extracted
        assert_eq!(result.extracted_fields.len(), 5);

        // Should be valid SQL INSERT statement
        assert!(result
            .formatted_data
            .starts_with("INSERT INTO phone_home_data"));
        assert!(result.formatted_data.ends_with(");"));
        assert!(result.formatted_data.contains("VALUES"));

        // Should contain all expected columns
        assert!(result.formatted_data.contains("timestamp"));
        assert!(result.formatted_data.contains("instance_id"));
        assert!(result.formatted_data.contains("hostname"));
        assert!(result.formatted_data.contains("fqdn"));
        assert!(result.formatted_data.contains("pub_key_rsa"));

        // Should contain quoted values
        assert!(result.formatted_data.contains("'test-host'"));
        assert!(result.formatted_data.contains("'test-host.example.com'"));
        assert!(result.formatted_data.contains("'i-1234567890abcdef0'"));
        assert!(result.formatted_data.contains("'ssh-rsa"));
    }

    #[test]
    fn test_sql_injection_protection() {
        let dangerous_data = PhoneHomeData {
            instance_id: Some("'; DROP TABLE users; --".to_string()),
            hostname: Some("host'with'quotes".to_string()),
            fqdn: Some("host.com'; SELECT * FROM secrets; --".to_string()),
            pub_key_rsa: Some("ssh-rsa key'with'quotes".to_string()),
            pub_key_ecdsa: None,
            pub_key_ed25519: None,
        };

        let config = PhoneHomeConfig {
            output_type: "sql".to_string(),
            fields_to_extract: vec!["hostname".to_string(), "fqdn".to_string()],
            field_separator: "|".to_string(),
            include_timestamp: false,
            include_instance_id: true,
        };

        let result = dangerous_data.process(&config);

        // Should escape single quotes properly
        assert!(result.formatted_data.contains("host''with''quotes"));
        assert!(result.formatted_data.contains("''; DROP TABLE users; --"));
        assert!(result
            .formatted_data
            .contains("host.com''; SELECT * FROM secrets; --"));

        // Should still be a valid SQL statement structure
        assert!(result
            .formatted_data
            .starts_with("INSERT INTO phone_home_data"));
        assert!(result.formatted_data.ends_with(");"));
    }

    #[test]
    fn test_minimal_configuration_all_types() {
        let data = create_sample_data();

        let minimal_config = PhoneHomeConfig {
            fields_to_extract: vec!["hostname".to_string()],
            field_separator: ",".to_string(),
            include_timestamp: false,
            include_instance_id: false,
            output_type: "string".to_string(),
        };

        // Test string output
        let string_result = data.process(&minimal_config);
        assert_eq!(string_result.formatted_data, "test-host");
        assert_eq!(string_result.extracted_fields.len(), 1);

        // Test JSON output
        let json_config = PhoneHomeConfig {
            output_type: "json".to_string(),
            ..minimal_config.clone()
        };
        let json_result = data.process(&json_config);
        assert_eq!(json_result.formatted_data, r#"{"hostname":"test-host"}"#);

        // Test SQL output
        let sql_config = PhoneHomeConfig {
            output_type: "sql".to_string(),
            ..minimal_config.clone()
        };
        let sql_result = data.process(&sql_config);
        assert_eq!(
            sql_result.formatted_data,
            "INSERT INTO phone_home_data (hostname) VALUES ('test-host');"
        );
    }

    #[test]
    fn test_empty_data_handling() {
        let empty_data = PhoneHomeData::default();

        let config = PhoneHomeConfig {
            fields_to_extract: vec!["hostname".to_string(), "fqdn".to_string()],
            field_separator: "|".to_string(),
            include_timestamp: true,
            include_instance_id: true,
            output_type: "json".to_string(),
        };

        let result = empty_data.process(&config);

        // Should still process successfully
        assert_eq!(result.extracted_fields.len(), 4); // timestamp, instance_id, hostname, fqdn

        // JSON should be valid
        let json_value: serde_json::Value =
            serde_json::from_str(&result.formatted_data).expect("Should be valid JSON");

        // Should have empty strings for missing fields
        assert_eq!(json_value["hostname"], "");
        assert_eq!(json_value["fqdn"], "");
        assert_eq!(json_value["instance_id"], "unknown");
        assert!(json_value.get("timestamp").is_some());
    }

    #[test]
    fn test_all_supported_fields_json() {
        let data = create_sample_data();

        let config = PhoneHomeConfig {
            fields_to_extract: vec![
                "instance_id".to_string(),
                "hostname".to_string(),
                "fqdn".to_string(),
                "pub_key_rsa".to_string(),
                "pub_key_ecdsa".to_string(),
                "pub_key_ed25519".to_string(),
            ],
            field_separator: "|".to_string(),
            include_timestamp: false,
            include_instance_id: false,
            output_type: "json".to_string(),
        };

        let result = data.process(&config);
        let json_value: serde_json::Value =
            serde_json::from_str(&result.formatted_data).expect("Should be valid JSON");

        // Verify all SSH key types are included
        assert!(json_value["pub_key_rsa"]
            .as_str()
            .unwrap()
            .starts_with("ssh-rsa"));
        assert!(json_value["pub_key_ecdsa"]
            .as_str()
            .unwrap()
            .starts_with("ecdsa-sha2"));
        assert!(json_value["pub_key_ed25519"]
            .as_str()
            .unwrap()
            .starts_with("ssh-ed25519"));

        // Should have exactly 6 fields
        assert_eq!(json_value.as_object().unwrap().len(), 6);
    }

    #[test]
    fn test_field_separator_ignored_in_non_string_formats() {
        let data = create_sample_data();

        let config = PhoneHomeConfig {
            fields_to_extract: vec!["hostname".to_string(), "fqdn".to_string()],
            field_separator: "***CUSTOM_SEPARATOR***".to_string(),
            include_timestamp: false,
            include_instance_id: false,
            output_type: "json".to_string(),
        };

        let result = data.process(&config);

        // JSON shouldn't contain the custom separator
        assert!(!result.formatted_data.contains("***CUSTOM_SEPARATOR***"));

        // But should be valid JSON
        let json_value: serde_json::Value =
            serde_json::from_str(&result.formatted_data).expect("Should be valid JSON");
        assert_eq!(json_value["hostname"], "test-host");
        assert_eq!(json_value["fqdn"], "test-host.example.com");
    }

    #[test]
    fn test_case_insensitive_output_type() {
        let data = create_sample_data();
        let base_config = create_base_config();

        // Test uppercase
        let upper_config = PhoneHomeConfig {
            output_type: "JSON".to_string(),
            ..base_config.clone()
        };
        let upper_result = data.process(&upper_config);
        assert!(upper_result.formatted_data.starts_with("{"));

        // Test mixed case
        let mixed_config = PhoneHomeConfig {
            output_type: "Sql".to_string(),
            ..base_config.clone()
        };
        let mixed_result = data.process(&mixed_config);
        assert!(mixed_result.formatted_data.starts_with("INSERT INTO"));

        // Test invalid type defaults to string
        let invalid_config = PhoneHomeConfig {
            output_type: "invalid_type".to_string(),
            ..base_config.clone()
        };
        let invalid_result = data.process(&invalid_config);
        assert!(invalid_result.formatted_data.contains("|"));
    }
}
