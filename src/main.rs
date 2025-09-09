use std::{path::PathBuf, process::exit};

use axum::{
    routing::{get, post},
    Router,
};
use clap::Parser;
use tracing::{info, warn};

use phonehome::{config::Config, handlers::phone_home_handler, health_check, tls, AppState};

#[derive(Parser)]
#[command(name = "phonehome")]
#[command(about = "A secure HTTPS server for Cloud Init phone home requests")]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, default_value = "/etc/phonehome/config.toml")]
    config: PathBuf,

    /// Port to listen on
    #[arg(short, long)]
    port: Option<u16>,

    /// Enable debug logging
    #[arg(short, long)]
    debug: bool,
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

    tracing::subscriber::set_global_default(subscriber).expect("Failed to set tracing subscriber");

    info!("Starting phonehome");

    // Load configuration
    let config = Config::load(&cli.config).await?;
    info!("Configuration loaded from {:?}", cli.config);

    // Override port if provided via CLI
    let port = cli.port.unwrap_or(config.server.port);
    let bind_addr = format!("{}:{}", config.server.host, port);

    info!("Server will bind to: {}", bind_addr);

    // Setup TLS configuration if provided
    if let Some(ref tls_config) = config.tls {
        info!("TLS configuration found - setting up certificates");
        if let Err(err) = tls::setup_tls_config(tls_config).await {
            warn!("TLS setup failed: {}.", err);
            exit(1);
        }
    } else {
        warn!("No TLS configuration found - server will run in HTTP mode");
        warn!("HTTPS is strongly recommended for production use");
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
    if let Some(ref tls_config) = state.config.tls {
        info!("Starting HTTPS server on {}", bind_addr);
        start_https_server(app, &bind_addr, tls_config).await?;
    } else {
        info!("Starting HTTP server on {}", bind_addr);
        let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
        axum::serve(listener, app).await?;
    }

    Ok(())
}

async fn start_https_server(
    app: Router,
    bind_addr: &str,
    tls_config: &phonehome::config::TlsConfig,
) -> anyhow::Result<()> {
    use axum_server::tls_rustls::RustlsConfig;

    let rustls_config =
        RustlsConfig::from_pem_file(&tls_config.cert_path, &tls_config.key_path).await?;
    axum_server::bind_rustls(bind_addr.parse()?, rustls_config)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}
