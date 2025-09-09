use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Cloud Init phone home data structure
/// This represents the data that Cloud Init sends in its phone home request
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct PhoneHomeData {
    /// Instance ID from cloud metadata
    pub instance_id: Option<String>,

    /// Public SSH keys
    pub public_keys: Option<Vec<String>>,

    /// Hostname of the instance
    pub hostname: Option<String>,

    /// Fully qualified domain name
    pub fqdn: Option<String>,

    /// Instance metadata
    pub instance_data: Option<InstanceData>,

    /// Network configuration
    pub network: Option<NetworkData>,

    /// User data
    pub user_data: Option<String>,

    /// Vendor data
    pub vendor_data: Option<String>,

    /// Cloud name (e.g., "aws", "gce", "azure")
    pub cloud_name: Option<String>,

    /// Platform name
    pub platform: Option<String>,

    /// Region information
    pub region: Option<String>,

    /// Availability zone
    pub availability_zone: Option<String>,

    /// Instance type/size
    pub instance_type: Option<String>,

    /// Local hostname
    pub local_hostname: Option<String>,

    /// Additional arbitrary data
    #[serde(flatten)]
    pub additional_data: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InstanceData {
    /// Instance ID
    pub instance_id: Option<String>,

    /// Instance type
    pub instance_type: Option<String>,

    /// Launch time
    pub launch_time: Option<DateTime<Utc>>,

    /// Local IPv4 address
    pub local_ipv4: Option<String>,

    /// Public IPv4 address
    pub public_ipv4: Option<String>,

    /// Local IPv6 address
    pub local_ipv6: Option<String>,

    /// Public IPv6 address
    pub public_ipv6: Option<String>,

    /// MAC address
    pub mac: Option<String>,

    /// Security groups
    pub security_groups: Option<Vec<String>>,

    /// IAM instance profile (AWS specific)
    pub iam_instance_profile: Option<String>,

    /// Additional metadata
    #[serde(flatten)]
    pub metadata: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NetworkData {
    /// Network interfaces
    pub interfaces: Option<Vec<NetworkInterface>>,

    /// DNS configuration
    pub dns: Option<DnsConfig>,

    /// Routes
    pub routes: Option<Vec<Route>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NetworkInterface {
    /// Interface name
    pub name: Option<String>,

    /// MAC address
    pub mac_address: Option<String>,

    /// IPv4 addresses
    pub ipv4_addresses: Option<Vec<String>>,

    /// IPv6 addresses
    pub ipv6_addresses: Option<Vec<String>>,

    /// Interface type
    pub interface_type: Option<String>,

    /// MTU
    pub mtu: Option<u32>,

    /// Whether the interface is up
    pub is_up: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DnsConfig {
    /// Nameservers
    pub nameservers: Option<Vec<String>>,

    /// Search domains
    pub search: Option<Vec<String>>,

    /// Domain
    pub domain: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Route {
    /// Destination network
    pub destination: Option<String>,

    /// Gateway
    pub gateway: Option<String>,

    /// Interface
    pub interface: Option<String>,

    /// Metric
    pub metric: Option<u32>,
}

/// Processed data that will be passed to the external application
#[derive(Debug, Clone, Serialize)]
pub struct ProcessedPhoneHomeData {
    /// Timestamp when the request was received
    pub timestamp: DateTime<Utc>,

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
        match field_name {
            "instance_id" => self.instance_id.clone(),
            "hostname" => self.hostname.clone(),
            "fqdn" => self.fqdn.clone(),
            "cloud_name" => self.cloud_name.clone(),
            "platform" => self.platform.clone(),
            "region" => self.region.clone(),
            "availability_zone" => self.availability_zone.clone(),
            "instance_type" => self.instance_type.clone(),
            "local_hostname" => self.local_hostname.clone(),
            "public_keys" => self.public_keys.as_ref().map(|keys| keys.join(",")),
            "local_ipv4" => self
                .instance_data
                .as_ref()
                .and_then(|data| data.local_ipv4.clone()),
            "public_ipv4" => self
                .instance_data
                .as_ref()
                .and_then(|data| data.public_ipv4.clone()),
            "local_ipv6" => self
                .instance_data
                .as_ref()
                .and_then(|data| data.local_ipv6.clone()),
            "public_ipv6" => self
                .instance_data
                .as_ref()
                .and_then(|data| data.public_ipv6.clone()),
            "mac" => self
                .instance_data
                .as_ref()
                .and_then(|data| data.mac.clone()),
            "security_groups" => self
                .instance_data
                .as_ref()
                .and_then(|data| data.security_groups.as_ref())
                .map(|groups| groups.join(",")),
            _ => {
                // Try to extract from additional_data
                self.additional_data
                    .get(field_name)
                    .map(|value| match value {
                        serde_json::Value::String(s) => s.clone(),
                        serde_json::Value::Number(n) => n.to_string(),
                        serde_json::Value::Bool(b) => b.to_string(),
                        _ => value.to_string(),
                    })
            }
        }
    }

    /// Process the phone home data according to configuration
    pub fn process(&self, config: &crate::config::PhoneHomeConfig) -> ProcessedPhoneHomeData {
        let mut extracted_fields = Vec::new();

        // Add timestamp if configured
        if config.include_timestamp {
            extracted_fields.push(Utc::now().to_rfc3339());
        }

        // Add instance ID if configured and available
        if config.include_instance_id {
            if let Some(ref instance_id) = self.instance_id {
                extracted_fields.push(instance_id.clone());
            } else {
                extracted_fields.push("unknown".to_string());
            }
        }

        // Extract configured fields
        for field_name in &config.fields_to_extract {
            let value = self.extract_field_value(field_name).unwrap_or_default();
            extracted_fields.push(value);
        }

        // Format the data string
        let formatted_data = extracted_fields.join(&config.field_separator);

        ProcessedPhoneHomeData {
            timestamp: Utc::now(),
            instance_id: self.instance_id.clone(),
            extracted_fields,
            formatted_data,
            raw_data: self.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PhoneHomeConfig;

    #[test]
    fn test_field_extraction() {
        let mut phone_home_data = PhoneHomeData::default();
        phone_home_data.instance_id = Some("i-1234567890abcdef0".to_string());
        phone_home_data.hostname = Some("test-host".to_string());
        phone_home_data.public_keys = Some(vec![
            "ssh-rsa AAAAB3...".to_string(),
            "ssh-ed25519 AAAAC3...".to_string(),
        ]);

        assert_eq!(
            phone_home_data.extract_field_value("instance_id"),
            Some("i-1234567890abcdef0".to_string())
        );
        assert_eq!(
            phone_home_data.extract_field_value("hostname"),
            Some("test-host".to_string())
        );
        assert_eq!(
            phone_home_data.extract_field_value("public_keys"),
            Some("ssh-rsa AAAAB3...,ssh-ed25519 AAAAC3...".to_string())
        );
        assert_eq!(phone_home_data.extract_field_value("nonexistent"), None);
    }

    #[test]
    fn test_data_processing() {
        let mut phone_home_data = PhoneHomeData::default();
        phone_home_data.instance_id = Some("i-1234567890abcdef0".to_string());
        phone_home_data.hostname = Some("test-host".to_string());

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
        let mut phone_home_data = PhoneHomeData::default();
        phone_home_data.instance_id = Some("i-1234567890abcdef0".to_string());
        phone_home_data.hostname = Some("test-host".to_string());

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
}
