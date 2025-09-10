use std::{path::PathBuf, process::exit};

use axum::response::Response;
use axum::{
    routing::{get, MethodRouter},
    Router,
};
use clap::Parser;
use std::net::SocketAddr;
use tracing::{debug, error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};

use phonehome::{
    config::Config,
    handlers::{phone_home_handler, RateLimiter},
    health_check, tls, web, AppState,
};

#[derive(Debug, Parser)]
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

    // Load configuration first to get logging settings
    let config = Config::load(&cli.config).await?;

    // Initialize logging based on configuration
    setup_logging(&config, cli.debug).await?;

    info!("Starting phonehome server");
    info!("Configuration loaded successfully from: {:?}", cli.config);
    debug!("Command line arguments: {:#?}", cli);
    debug!("Loaded configuration: {:#?}", config);

    // Override port if provided via CLI
    let port = cli.port.unwrap_or(config.server.port);
    if cli.port.is_some() {
        info!(
            "Port overridden via CLI: {} -> {}",
            config.server.port, port
        );
    }
    let bind_addr = format!("{}:{}", config.server.host, port);

    info!("Server will bind to: {}", bind_addr);
    debug!("Host: {}, Port: {}", config.server.host, port);

    // Require TLS configuration
    let tls_config = match &config.tls {
        Some(tls_config) => {
            info!("TLS configuration found - setting up certificates");
            debug!(
                "TLS config: cert={:?}, key={:?}",
                tls_config.cert_path, tls_config.key_path
            );
            if let Err(err) = tls::setup_tls_config(tls_config).await {
                error!("TLS setup failed: {}", err);
                error!("Server cannot start without valid TLS configuration");
                exit(1);
            }
            info!("TLS setup completed successfully");
            tls_config.clone()
        }
        None => {
            error!("No TLS configuration found - HTTPS is required");
            error!("Please provide TLS configuration in config file");
            exit(1);
        }
    };

    // Create application state with rate limiter
    debug!("Creating application state");
    let rate_limiter = RateLimiter::new(100, 300); // 100 requests per 5 minutes
    info!("Rate limiter initialized: 100 requests per 300 seconds");

    let state = AppState {
        config: std::sync::Arc::new(config),
        rate_limiter,
    };
    info!("Application state created successfully");

    // Build the router
    debug!("Building application router");
    let app = Router::new()
        .route("/", get(web::landing_page))
        .route("/health", get(health_check))
        .route(
            "/phone-home/:token",
            MethodRouter::new()
                .get(phone_home_get_handler)
                .post(phone_home_handler),
        )
        .fallback(web::not_found)
        .with_state(state.clone());

    info!("Application router configured with routes:");
    info!("  GET  / - Landing page");
    info!("  GET  /health - Health check endpoint");
    info!("  POST /phone-home/:token - Phone home data endpoint");
    info!("  Fallback: Custom 404 error page");
    debug!("Router built successfully with shared state");

    // Start HTTPS server
    info!("Starting HTTPS server on {}", bind_addr);
    info!("Phone home URL: {}", state.config.get_phone_home_url());
    debug!(
        "Using TLS certificates: cert={:?}, key={:?}",
        tls_config.cert_path, tls_config.key_path
    );
    start_https_server(app, &bind_addr, &tls_config).await?;

    info!("Server shutdown completed");
    Ok(())
}

async fn phone_home_get_handler() -> Response {
    web::forbidden().await
}

async fn start_https_server(
    app: Router,
    bind_addr: &str,
    tls_config: &phonehome::config::TlsConfig,
) -> anyhow::Result<()> {
    use axum_server::tls_rustls::RustlsConfig;

    debug!("Loading TLS configuration for HTTPS server");
    debug!("Certificate file: {:?}", tls_config.cert_path);
    debug!("Private key file: {:?}", tls_config.key_path);

    let rustls_config =
        RustlsConfig::from_pem_file(&tls_config.cert_path, &tls_config.key_path).await?;
    info!("TLS configuration loaded successfully for HTTPS server");

    debug!("Parsing bind address: {}", bind_addr);
    let socket_addr = bind_addr.parse()?;
    debug!("Bind address parsed successfully: {:?}", socket_addr);

    info!("HTTPS server listening successfully, ready to accept connections");
    axum_server::bind_rustls(socket_addr, rustls_config)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;

    debug!("HTTPS server shutdown completed");
    Ok(())
}

/// Setup logging based on configuration
async fn setup_logging(config: &Config, debug_override: bool) -> anyhow::Result<()> {
    use tracing_appender::rolling::RollingFileAppender;
    use tracing_subscriber::fmt;

    // Determine log level - CLI debug flag overrides config
    let log_level = if debug_override {
        tracing::Level::DEBUG
    } else {
        match config.logging.log_level.to_lowercase().as_str() {
            "trace" => tracing::Level::TRACE,
            "debug" => tracing::Level::DEBUG,
            "info" => tracing::Level::INFO,
            "warn" => tracing::Level::WARN,
            "error" => tracing::Level::ERROR,
            _ => tracing::Level::INFO,
        }
    };

    // Create a temporary console logger for initial setup messages
    let temp_subscriber = tracing_subscriber::fmt().with_max_level(log_level).finish();
    let _guard = tracing::subscriber::set_default(temp_subscriber);

    eprintln!("Setting up logging with level: {:?}", log_level);
    eprintln!(
        "Logging configuration: enable_console={}, enable_file={}, log_file={:?}",
        config.logging.enable_console, config.logging.enable_file, config.logging.log_file
    );

    let mut layers = Vec::new();

    // Console logging layer
    if config.logging.enable_console {
        let console_layer = fmt::layer()
            .with_target(false)
            .with_thread_ids(false)
            .with_file(false)
            .with_line_number(false)
            .with_ansi(true)
            .with_filter(tracing_subscriber::filter::LevelFilter::from_level(
                log_level,
            ));

        layers.push(console_layer.boxed());
        eprintln!("Console logging enabled");
    } else {
        eprintln!("Console logging disabled");
    }

    // File logging layer
    if config.logging.enable_file {
        // Ensure log directory exists
        if let Some(log_dir) = config.logging.log_file.parent() {
            tokio::fs::create_dir_all(log_dir).await.map_err(|e| {
                anyhow::anyhow!("Failed to create log directory {:?}: {}", log_dir, e)
            })?;
            eprintln!("Log directory ensured: {:?}", log_dir);
        }

        // Setup rolling file appender
        let file_name = config
            .logging
            .log_file
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("phonehome.log");

        let log_dir = config
            .logging
            .log_file
            .parent()
            .unwrap_or_else(|| std::path::Path::new("/var/log/phonehome"));

        eprintln!(
            "Setting up file logging: directory={:?}, filename={}",
            log_dir, file_name
        );

        // Use daily rotation to work well with logrotate
        let file_appender = RollingFileAppender::builder()
            .rotation(tracing_appender::rolling::Rotation::DAILY)
            .filename_prefix(file_name)
            .build(log_dir)
            .map_err(|e| anyhow::anyhow!("Failed to create file appender: {}", e))?;

        let file_layer = fmt::layer()
            .with_writer(file_appender)
            .with_target(false)
            .with_thread_ids(false)
            .with_file(false)
            .with_line_number(false)
            .with_ansi(false) // No ANSI colors in log files
            .with_filter(tracing_subscriber::filter::LevelFilter::from_level(
                log_level,
            ));

        layers.push(file_layer.boxed());
        eprintln!("File logging enabled: {:?}", config.logging.log_file);
        eprintln!("Log rotation: daily, logrotate compatible");
    } else {
        eprintln!("File logging disabled");
    }

    // Drop the temporary guard to allow new subscriber
    drop(_guard);

    // Initialize the subscriber with all layers
    tracing_subscriber::registry().with(layers).init();

    info!("Logging system initialized successfully");
    info!("Log level: {:?}", log_level);
    info!("Console logging: {}", config.logging.enable_console);
    info!("File logging: {}", config.logging.enable_file);

    if config.logging.enable_file {
        info!("Log file: {:?}", config.logging.log_file);
    }

    Ok(())
}
