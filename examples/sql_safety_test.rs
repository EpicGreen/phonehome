use phonehome::{config::PhoneHomeConfig, models::PhoneHomeData};

fn main() {
    println!("PhoneHome SQL Safety Test");
    println!("=========================\n");

    // Create phone home data with potentially dangerous SQL characters
    let dangerous_data = PhoneHomeData {
        instance_id: Some("i-123'; DROP TABLE users; --".to_string()),
        hostname: Some("host'with'quotes".to_string()),
        fqdn: Some("host.example.com'; SELECT * FROM secrets; --".to_string()),
        pub_key_rsa: Some("ssh-rsa AAAAB3'injection'attempt...".to_string()),
        pub_key_ecdsa: None,
        pub_key_ed25519: None,
    };

    println!("Testing with potentially dangerous data:");
    println!("- Instance ID: {:?}", dangerous_data.instance_id);
    println!("- Hostname: {:?}", dangerous_data.hostname);
    println!("- FQDN: {:?}", dangerous_data.fqdn);
    println!("- RSA Key: {:?}", dangerous_data.pub_key_rsa);
    println!();

    // Test SQL output with dangerous characters
    let sql_config = PhoneHomeConfig {
        fields_to_extract: vec![
            "hostname".to_string(),
            "fqdn".to_string(),
            "pub_key_rsa".to_string(),
        ],
        field_separator: "|".to_string(),
        include_timestamp: true,
        include_instance_id: true,
        output_type: "sql".to_string(),
    };

    let sql_result = dangerous_data.process(&sql_config);
    println!("SQL Output (with escaping):");
    println!("{}", sql_result.formatted_data);
    println!();

    // Verify that single quotes are properly escaped
    let escaped_output = &sql_result.formatted_data;

    println!("Safety Analysis:");
    println!(
        "- Contains escaped quotes (''): {}",
        escaped_output.contains("''")
    );
    println!(
        "- Contains dangerous DROP: {}",
        escaped_output.contains("DROP TABLE")
    );
    println!(
        "- Contains dangerous SELECT: {}",
        escaped_output.contains("SELECT *")
    );
    println!(
        "- Contains SQL comment (--): {}",
        escaped_output.contains("--")
    );

    if escaped_output.contains("''") {
        println!("✓ Single quotes are properly escaped");
    } else {
        println!("⚠ Warning: Single quotes may not be escaped");
    }

    if escaped_output.contains("DROP TABLE") || escaped_output.contains("SELECT *") {
        println!("⚠ Warning: Dangerous SQL keywords found in output");
    } else {
        println!("✓ Dangerous SQL keywords are contained within escaped strings");
    }

    println!();

    // Test JSON output for comparison (JSON should handle special characters safely)
    let json_config = PhoneHomeConfig {
        output_type: "json".to_string(),
        ..sql_config.clone()
    };

    let json_result = dangerous_data.process(&json_config);
    println!("JSON Output (for comparison):");
    println!("{}", json_result.formatted_data);
    println!();

    // Test string output for comparison
    let string_config = PhoneHomeConfig {
        output_type: "string".to_string(),
        field_separator: " | ".to_string(),
        ..sql_config.clone()
    };

    let string_result = dangerous_data.process(&string_config);
    println!("String Output (for comparison):");
    println!("{}", string_result.formatted_data);
    println!();

    println!("SQL Safety Test completed!");
    println!("Note: The SQL escaping converts single quotes (') to double quotes ('')");
    println!("This prevents SQL injection but the external application should still");
    println!("use parameterized queries for maximum security.");
}
