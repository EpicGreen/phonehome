use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
use tracing::{debug, warn};

/// Landing page handler for the root path
pub async fn landing_page() -> Html<&'static str> {
    debug!("Landing page accessed");

    Html(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PhoneHome Server</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 800px;
            margin: 2rem auto;
            padding: 2rem;
            line-height: 1.6;
            background: #f8f9fa;
            color: #333;
        }
        .container {
            background: white;
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 0.5rem;
        }
        .status {
            background: #d4edda;
            border: 1px solid #c3e6cb;
            border-radius: 4px;
            padding: 1rem;
            margin: 1rem 0;
        }
        .endpoint {
            background: #f8f9fa;
            border-left: 4px solid #007bff;
            padding: 1rem;
            margin: 1rem 0;
            font-family: monospace;
        }
        .warning {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 4px;
            padding: 1rem;
            margin: 1rem 0;
        }
        .footer {
            margin-top: 2rem;
            padding-top: 1rem;
            border-top: 1px solid #dee2e6;
            color: #6c757d;
            text-align: center;
        }
        code {
            background: #f1f3f4;
            padding: 0.2rem 0.4rem;
            border-radius: 3px;
            font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>PhoneHome Server</h1>

        <div class="status">
            <strong>✅ Service Status:</strong> Running and ready to accept Cloud Init phone home requests
        </div>

        <h2>Service Information</h2>
        <p>This is a secure HTTPS server designed to handle Cloud Init phone home requests. The server processes incoming data, extracts configured fields, and executes external applications with the processed information.</p>

        <h2>Available Endpoints</h2>

        <div class="endpoint">
            <strong>GET /health</strong><br>
            Health check endpoint for monitoring and load balancers
        </div>

        <div class="endpoint">
            <strong>POST /{token}</strong><br>
            Cloud Init phone home data submission endpoint<br>
            <em>Requires valid authentication token and JSON payload</em>
        </div>

        <h2>Usage</h2>
        <p>To configure Cloud Init to use this phone home server, add the following to your cloud-config:</p>

        <pre><code>#cloud-config
phone_home:
  url: "https://your-server.com:8443/phone-home/your-token"
  post: all
  tries: 10
        </code></pre>
        <div class="footer">
            <p>PhoneHome Server - Cloud Init Phone Home Handler</p>
        </div>
    </div>
</body>
</html>"#,
    )
}

/// Handle 404 Not Found errors
pub async fn not_found() -> Response {
    warn!("404 Not Found: Invalid endpoint accessed");

    let html = Html(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>404 - Page Not Found | PhoneHome Server</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 600px;
            margin: 4rem auto;
            padding: 2rem;
            text-align: center;
            background: #f8f9fa;
            color: #333;
        }
        .container {
            background: white;
            padding: 3rem 2rem;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #e74c3c;
            font-size: 4rem;
            margin: 0;
        }
        h2 {
            color: #2c3e50;
            margin: 1rem 0;
        }
        p {
            line-height: 1.6;
            margin: 1rem 0;
        }
        .btn {
            display: inline-block;
            background: #3498db;
            color: white;
            padding: 0.75rem 1.5rem;
            text-decoration: none;
            border-radius: 4px;
            margin: 1rem 0.5rem;
            transition: background 0.3s;
        }
        .btn:hover {
            background: #2980b9;
        }
        .endpoints {
            background: #f8f9fa;
            padding: 1rem;
            border-radius: 4px;
            margin: 1.5rem 0;
            text-align: left;
        }
        code {
            background: #f1f3f4;
            padding: 0.2rem 0.4rem;
            border-radius: 3px;
            font-family: monospace;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>404</h1>
        <h2>Page Not Found</h2>
        <p>The requested endpoint does not exist on this PhoneHome server.</p>

        <div class="endpoints">
            <strong>Available endpoints:</strong><br>
            <code>GET /</code> - Server information<br>
            <code>GET /health</code> - Health check<br>
            <code>POST /phone-home/{token}</code> - Phone home data submission
        </div>

        <a href="/" class="btn">🏠 Home</a>
        <a href="/health" class="btn">❤️ Health Check</a>

        <p style="margin-top: 2rem; color: #6c757d; font-size: 0.9rem;">
            If you believe this is an error, please check your URL and try again.
        </p>
    </div>
</body>
</html>"#,
    );

    (StatusCode::NOT_FOUND, html).into_response()
}

/// Handle 400 Bad Request errors
pub async fn bad_request() -> Response {
    warn!("400 Bad Request: Malformed request received");

    let html = Html(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>400 - Bad Request | PhoneHome Server</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 600px;
            margin: 4rem auto;
            padding: 2rem;
            text-align: center;
            background: #f8f9fa;
            color: #333;
        }
        .container {
            background: white;
            padding: 3rem 2rem;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #f39c12;
            font-size: 4rem;
            margin: 0;
        }
        h2 {
            color: #2c3e50;
            margin: 1rem 0;
        }
        p {
            line-height: 1.6;
            margin: 1rem 0;
        }
        .requirements {
            background: #f8f9fa;
            padding: 1rem;
            border-radius: 4px;
            margin: 1.5rem 0;
            text-align: left;
        }
        .btn {
            display: inline-block;
            background: #3498db;
            color: white;
            padding: 0.75rem 1.5rem;
            text-decoration: none;
            border-radius: 4px;
            margin: 1rem 0.5rem;
            transition: background 0.3s;
        }
        .btn:hover {
            background: #2980b9;
        }
        code {
            background: #f1f3f4;
            padding: 0.2rem 0.4rem;
            border-radius: 3px;
            font-family: monospace;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>400</h1>
        <h2>Bad Request</h2>
        <p>The request could not be processed due to malformed syntax or invalid data.</p>

        <div class="requirements">
            <strong>Phone home requests must include:</strong><br>
            • Valid authentication token in URL<br>
            • Content-Type: application/json header<br>
            • Valid JSON payload in request body<br>
            • POST method to <code>/phone-home/{token}</code>
        </div>

        <a href="/" class="btn">🏠 Home</a>
        <a href="/health" class="btn">❤️ Health Check</a>

        <p style="margin-top: 2rem; color: #6c757d; font-size: 0.9rem;">
            Please check your request format and try again.
        </p>
    </div>
</body>
</html>"#,
    );

    (StatusCode::BAD_REQUEST, html).into_response()
}

/// Handle 401 Unauthorized errors
pub async fn unauthorized() -> Response {
    warn!("401 Unauthorized: Invalid authentication token");

    let html = Html(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>401 - Unauthorized | PhoneHome Server</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 600px;
            margin: 4rem auto;
            padding: 2rem;
            text-align: center;
            background: #f8f9fa;
            color: #333;
        }
        .container {
            background: white;
            padding: 3rem 2rem;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #e74c3c;
            font-size: 4rem;
            margin: 0;
        }
        h2 {
            color: #2c3e50;
            margin: 1rem 0;
        }
        p {
            line-height: 1.6;
            margin: 1rem 0;
        }
        .security-info {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            padding: 1rem;
            border-radius: 4px;
            margin: 1.5rem 0;
        }
        .btn {
            display: inline-block;
            background: #3498db;
            color: white;
            padding: 0.75rem 1.5rem;
            text-decoration: none;
            border-radius: 4px;
            margin: 1rem 0.5rem;
            transition: background 0.3s;
        }
        .btn:hover {
            background: #2980b9;
        }
        code {
            background: #f1f3f4;
            padding: 0.2rem 0.4rem;
            border-radius: 3px;
            font-family: monospace;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>401</h1>
        <h2>Unauthorized</h2>
        <p>Access denied. The provided authentication token is invalid or missing.</p>

        <div class="security-info">
            <strong>🔒 Security Notice:</strong><br>
            This access attempt has been logged. Valid authentication tokens are required for all phone home requests.
        </div>

        <p>Valid phone home URLs follow this format:</p>
        <code>POST /phone-home/{valid-token}</code>

        <a href="/" class="btn">🏠 Home</a>
        <a href="/health" class="btn">❤️ Health Check</a>

        <p style="margin-top: 2rem; color: #6c757d; font-size: 0.9rem;">
            Contact your system administrator if you need access credentials.
        </p>
    </div>
</body>
</html>"#,
    );

    (StatusCode::UNAUTHORIZED, html).into_response()
}

pub async fn forbidden() -> Response {
    warn!("403 Forbidden: Access denied to protected resource");

    let html = Html(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>403 - Forbidden | PhoneHome Server</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 600px;
            margin: 4rem auto;
            padding: 2rem;
            text-align: center;
            background: #f8f9fa;
            color: #333;
        }
        .container {
            background: white;
            padding: 3rem 2rem;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #e74c3c;
            font-size: 4rem;
            margin: 0;
        }
        h2 {
            color: #2c3e50;
            margin: 1rem 0;
        }
        p {
            line-height: 1.6;
            margin: 1rem 0;
        }
        .security-info {
            background: #ffe6e6;
            border: 1px solid #ff9999;
            padding: 1rem;
            border-radius: 4px;
            margin: 1.5rem 0;
        }
        .btn {
            display: inline-block;
            background: #3498db;
            color: white;
            padding: 0.75rem 1.5rem;
            text-decoration: none;
            border-radius: 4px;
            margin: 1rem 0.5rem;
            transition: background 0.3s;
        }
        .btn:hover {
            background: #2980b9;
        }
        code {
            background: #f1f3f4;
            padding: 0.2rem 0.4rem;
            border-radius: 3px;
            font-family: monospace;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>403</h1>
        <h2>Forbidden</h2>
        <p>You don't have permission to access this resource using this method.</p>

        <div class="security-info">
            <strong>🚫 Access Denied:</strong><br>
            The phone home endpoint only accepts POST requests with valid authentication tokens.
        </div>

        <div>
            <p>Valid phone home requests must use:</p>
            <code>POST /phone-home/{valid-token}</code>
        </div>

        <a href="/" class="btn">🏠 Home</a>
        <a href="/health" class="btn">❤️ Health Check</a>

        <p style="margin-top: 2rem; color: #6c757d; font-size: 0.9rem;">
            This access attempt has been logged for security monitoring.
        </p>
    </div>
</body>
</html>"#,
    );

    (StatusCode::FORBIDDEN, html).into_response()
}

pub async fn internal_server_error() -> Response {
    warn!("500 Internal Server Error: Server encountered an error");

    let html = Html(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>500 - Internal Server Error | PhoneHome Server</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 600px;
            margin: 4rem auto;
            padding: 2rem;
            text-align: center;
            background: #f8f9fa;
            color: #333;
        }
        .container {
            background: white;
            padding: 3rem 2rem;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #e74c3c;
            font-size: 4rem;
            margin: 0;
        }
        h2 {
            color: #2c3e50;
            margin: 1rem 0;
        }
        p {
            line-height: 1.6;
            margin: 1rem 0;
        }
        .error-info {
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            padding: 1rem;
            border-radius: 4px;
            margin: 1.5rem 0;
        }
        .btn {
            display: inline-block;
            background: #3498db;
            color: white;
            padding: 0.75rem 1.5rem;
            text-decoration: none;
            border-radius: 4px;
            margin: 1rem 0.5rem;
            transition: background 0.3s;
        }
        .btn:hover {
            background: #2980b9;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>500</h1>
        <h2>Internal Server Error</h2>
        <p>The server encountered an unexpected error while processing your request.</p>

        <div class="error-info">
            <strong>🔧 Technical Information:</strong><br>
            The error has been logged for investigation. Please try again in a few moments.
        </div>

        <a href="/" class="btn">🏠 Home</a>
        <a href="/health" class="btn">❤️ Health Check</a>

        <p style="margin-top: 2rem; color: #6c757d; font-size: 0.9rem;">
            If the problem persists, please contact the system administrator.
        </p>
    </div>
</body>
</html>"#,
    );

    (StatusCode::INTERNAL_SERVER_ERROR, html).into_response()
}

/// Handle method not allowed errors (405)
pub async fn method_not_allowed() -> Response {
    warn!("405 Method Not Allowed: Invalid HTTP method used");

    let html = Html(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>405 - Method Not Allowed | PhoneHome Server</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 600px;
            margin: 4rem auto;
            padding: 2rem;
            text-align: center;
            background: #f8f9fa;
            color: #333;
        }
        .container {
            background: white;
            padding: 3rem 2rem;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #f39c12;
            font-size: 4rem;
            margin: 0;
        }
        h2 {
            color: #2c3e50;
            margin: 1rem 0;
        }
        p {
            line-height: 1.6;
            margin: 1rem 0;
        }
        .methods {
            background: #f8f9fa;
            padding: 1rem;
            border-radius: 4px;
            margin: 1.5rem 0;
            text-align: left;
        }
        .btn {
            display: inline-block;
            background: #3498db;
            color: white;
            padding: 0.75rem 1.5rem;
            text-decoration: none;
            border-radius: 4px;
            margin: 1rem 0.5rem;
            transition: background 0.3s;
        }
        .btn:hover {
            background: #2980b9;
        }
        code {
            background: #f1f3f4;
            padding: 0.2rem 0.4rem;
            border-radius: 3px;
            font-family: monospace;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>405</h1>
        <h2>Method Not Allowed</h2>
        <p>The HTTP method used is not allowed for this endpoint.</p>

        <div class="methods">
            <strong>Allowed methods by endpoint:</strong><br>
            <code>GET /</code> - Server information<br>
            <code>GET /health</code> - Health check<br>
            <code>POST /phone-home/{token}</code> - Phone home data submission
        </div>

        <a href="/" class="btn">🏠 Home</a>
        <a href="/health" class="btn">❤️ Health Check</a>

        <p style="margin-top: 2rem; color: #6c757d; font-size: 0.9rem;">
            Please use the correct HTTP method for your request.
        </p>
    </div>
</body>
</html>"#,
    );

    (StatusCode::METHOD_NOT_ALLOWED, html).into_response()
}

/// Generic error handler that returns appropriate error pages based on status code
pub async fn handle_error(status_code: StatusCode) -> Response {
    match status_code {
        StatusCode::BAD_REQUEST => bad_request().await,
        StatusCode::UNAUTHORIZED => unauthorized().await,
        StatusCode::NOT_FOUND => not_found().await,
        StatusCode::METHOD_NOT_ALLOWED => method_not_allowed().await,
        StatusCode::INTERNAL_SERVER_ERROR => internal_server_error().await,
        _ => {
            warn!("Unhandled error status code: {}", status_code);
            internal_server_error().await
        }
    }
}
