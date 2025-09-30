use phonehome::{config::PhoneHomeConfig, models::PhoneHomeData};

fn main() {
    println!("PhoneHome Output Types Demo");
    println!("===========================\n");

    // Create sample phone home data
    let phone_home_data = PhoneHomeData {
        instance_id: Some("i-1234567890abcdef0".to_string()),
        hostname: Some("web-server-01".to_string()),
        fqdn: Some("web-server-01.example.com".to_string()),
        pub_key_rsa: Some("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ...".to_string()),
        pub_key_ecdsa: Some("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTI...".to_string()),
        pub_key_ed25519: Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...".to_string()),
    };

    println!("Sample data:");
    println!("- Instance ID: {:?}", phone_home_data.instance_id);
    println!("- Hostname: {:?}", phone_home_data.hostname);
    println!("- FQDN: {:?}", phone_home_data.fqdn);
    println!("- Has RSA key: {}", phone_home_data.pub_key_rsa.is_some());
    println!(
        "- Has ECDSA key: {}",
        phone_home_data.pub_key_ecdsa.is_some()
    );
    println!(
        "- Has Ed25519 key: {}",
        phone_home_data.pub_key_ed25519.is_some()
    );
    println!();

    // Base configuration
    let base_config = PhoneHomeConfig {
        fields_to_extract: vec![
            "hostname".to_string(),
            "fqdn".to_string(),
            "pub_key_rsa".to_string(),
        ],
        field_separator: " | ".to_string(),
        include_timestamp: true,
        include_instance_id: true,
        output_type: "string".to_string(),
    };

    // Demonstrate STRING output type
    println!("1. STRING Output Type:");
    println!("---------------------");
    let string_config = PhoneHomeConfig {
        output_type: "string".to_string(),
        ..base_config.clone()
    };
    let string_result = phone_home_data.process(&string_config);
    println!("Formatted data: {}", string_result.formatted_data);
    println!("Fields extracted: {}", string_result.extracted_fields.len());
    println!();

    // Demonstrate JSON output type
    println!("2. JSON Output Type:");
    println!("-------------------");
    let json_config = PhoneHomeConfig {
        output_type: "json".to_string(),
        ..base_config.clone()
    };
    let json_result = phone_home_data.process(&json_config);
    println!("Formatted data: {}", json_result.formatted_data);
    println!("Fields extracted: {}", json_result.extracted_fields.len());
    println!();

    // Demonstrate SQL output type
    println!("3. SQL Output Type:");
    println!("------------------");
    let sql_config = PhoneHomeConfig {
        output_type: "sql".to_string(),
        ..base_config.clone()
    };
    let sql_result = phone_home_data.process(&sql_config);
    println!("Formatted data: {}", sql_result.formatted_data);
    println!("Fields extracted: {}", sql_result.extracted_fields.len());
    println!();

    // Demonstrate minimal configuration
    println!("4. Minimal Configuration (no timestamp/instance_id):");
    println!("---------------------------------------------------");
    let minimal_config = PhoneHomeConfig {
        fields_to_extract: vec!["hostname".to_string()],
        field_separator: ",".to_string(),
        include_timestamp: false,
        include_instance_id: false,
        output_type: "json".to_string(),
    };
    let minimal_result = phone_home_data.process(&minimal_config);
    println!("JSON (minimal): {}", minimal_result.formatted_data);
    println!();

    // Demonstrate SQL with minimal data
    println!("5. SQL with Minimal Data:");
    println!("------------------------");
    let sql_minimal_config = PhoneHomeConfig {
        fields_to_extract: vec!["hostname".to_string(), "instance_id".to_string()],
        field_separator: ",".to_string(),
        include_timestamp: false,
        include_instance_id: false,
        output_type: "sql".to_string(),
    };
    let sql_minimal_result = phone_home_data.process(&sql_minimal_config);
    println!("SQL (minimal): {}", sql_minimal_result.formatted_data);
    println!();

    println!("Demo completed successfully!");
}
