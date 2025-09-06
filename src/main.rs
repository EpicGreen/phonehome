use std::path::PathBuf;


use axum::{
    routing::{get, post},
    Router,
};
use clap::Parser;
use tracing::{info, warn};
use tracing_subscriber;

use phonehome::{config::Config, handlers::phone_home_handler, health_check, tls, AppState};

#[derive(Parser)]
#[command(name = "phonehome")]
#[command(about = "A secure HTTPS server for Cloud Init phone home requests")]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,

    /// Port to listen on
    #[arg(short, long)]
    port: Option<u16>,

    /// Enable debug logging
    #[arg(short, long)]
    debug: bool,

    /// Enable development mode with self-signed certificate for localhost only
    /// WARNING: This should NEVER be used in production!
    #[arg(long)]
    dev_mode: bool,
}



#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize tracing
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(if cli.debug {
            tracing::Level::DEBUG
        } else {
            tracing::Level::INFO
        })
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set tracing subscriber");

    info!("Starting phonehome");

    // Load configuration
    let mut config = Config::load(&cli.config).await?;
    info!("Configuration loaded from {:?}", cli.config);

    // Handle development mode flag (only allow if running under cargo)
    let is_under_cargo = phonehome::config::Config::is_running_under_cargo();

    if cli.dev_mode && !is_under_cargo {
        anyhow::bail!("Development mode is only available when running under cargo (cargo run, cargo test, etc.)");
    }

    let dev_mode_enabled = cli.x && is_under_cargo;

    if dev_mode_enabled {
        warn!("Development mode enabled via CLI flag - this should NEVER be used in production!");
        warn!("Development mode is restricted to cargo-based execution only");

        // Override configuration for development mode
        config.server.host = "127.0.0.1".to_string();

        info!("Development mode: Server will bind to localhost only");
        info!("Development mode: Self-signed certificate will be generated");
    }

    // Override port if provided via CLI
    let port = cli.port.unwrap_or(config.server.port);
    let bind_addr = format!("{}:{}", config.server.host, port);

    info!("Server will bind to: {}", bind_addr);

    // Handle development mode self-signed certificate generation
    if dev_mode_enabled {
        let (cert_path, key_path) = phonehome::config::Config::get_dev_cert_paths();
        info!("Development mode: Generating self-signed certificate for localhost");
        tls::generate_self_signed_cert("localhost", &cert_path, &key_path).await?;
        info!("Development mode: Self-signed certificate generated successfully");
    }

    // Validate TLS configuration if provided and not in development mode
    if let Some(ref tls_config) = config.tls {
        if !dev_mode_enabled {
            info!("TLS configuration found - validating certificates");
            if let Err(err) = tls::validate_tls_config(tls_config).await {
                warn!("TLS validation failed: {}. Running without HTTPS.", err);
            }
        }
    } else if !dev_mode_enabled {
        warn!("No TLS configuration found - server will run without HTTPS");
    }

    // Create application state
    let state = AppState {
        config: std::sync::Arc::new(config),
    };

    // Build the router
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/:token", post(phone_home_handler))
        .with_state(state.clone());

    // Start server with appropriate protocol
    if dev_mode_enabled {
        info!("Starting HTTPS server with self-signed certificate on {}", bind_addr);
        start_https_server_with_dev_cert(app, &bind_addr).await?;
    } else if let Some(ref tls_config) = state.config.tls {
        info!("Starting HTTPS server on {}", bind_addr);
        start_https_server(app, &bind_addr, tls_config).await?;
    } else {
        info!("Starting HTTP server on {}", bind_addr);
        let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
        axum::serve(listener, app).await?;
    }

    Ok(())
}

async fn start_https_server_with_dev_cert(
    app: Router,
    bind_addr: &str,
) -> anyhow::Result<()> {
    use axum_server::tls_rustls::RustlsConfig;

    let (cert_path, key_path) = phonehome::config::Config::get_dev_cert_paths();
    let tls_config = RustlsConfig::from_pem_file(cert_path, key_path).await?;
    axum_server::bind_rustls(bind_addr.parse()?, tls_config)
        .serve(app.into_make_service())
        .await?;
    Ok(())
}

async fn start_https_server(
    app: Router,
    bind_addr: &str,
    tls_config: &phonehome::config::TlsConfig,
) -> anyhow::Result<()> {
    use axum_server::tls_rustls::RustlsConfig;

    let rustls_config = RustlsConfig::from_pem_file(&tls_config.cert_path, &tls_config.key_path).await?;
    axum_server::bind_rustls(bind_addr.parse()?, rustls_config)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}
