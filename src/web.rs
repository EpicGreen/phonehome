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
        <p>This is a server designed to handle Cloud Init phone home requests. The server processes incoming data, extracts configured fields, and executes external applications with the processed information.</p>

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
  url: "http://your-server.com:8080/phone-home/your-token"
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

/// Not found handler for 404 errors
pub async fn not_found() -> Response {
    debug!("404 Not Found handler invoked");

    let html = Html(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>404 - Not Found</title>
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
            margin-top: 1rem;
        }
        p {
            color: #6c757d;
            line-height: 1.6;
        }
        a {
            color: #3498db;
            text-decoration: none;
            font-weight: 500;
        }
        a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>404</h1>
        <h2>Page Not Found</h2>
        <p>The page you're looking for doesn't exist or has been moved.</p>
        <p><a href="/">Return to Home</a></p>
    </div>
</body>
</html>"#,
    );

    (StatusCode::NOT_FOUND, html).into_response()
}

/// Bad request handler for 400 errors
pub async fn bad_request() -> Response {
    debug!("400 Bad Request handler invoked");

    let html = Html(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>400 - Bad Request</title>
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
            margin-top: 1rem;
        }
        p {
            color: #6c757d;
            line-height: 1.6;
        }
        a {
            color: #3498db;
            text-decoration: none;
            font-weight: 500;
        }
        a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>400</h1>
        <h2>Bad Request</h2>
        <p>The request could not be understood by the server.</p>
        <p><a href="/">Return to Home</a></p>
    </div>
</body>
</html>"#,
    );

    (StatusCode::BAD_REQUEST, html).into_response()
}

/// Unauthorized handler for 401 errors
pub async fn unauthorized() -> Response {
    debug!("401 Unauthorized handler invoked");

    let html = Html(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>401 - Unauthorized</title>
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
            margin-top: 1rem;
        }
        p {
            color: #6c757d;
            line-height: 1.6;
        }
        a {
            color: #3498db;
            text-decoration: none;
            font-weight: 500;
        }
        a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>401</h1>
        <h2>Unauthorized</h2>
        <p>Authentication is required to access this resource.</p>
        <p><a href="/">Return to Home</a></p>
    </div>
</body>
</html>"#,
    );

    (StatusCode::UNAUTHORIZED, html).into_response()
}

/// Forbidden handler for 403 errors
pub async fn forbidden() -> Response {
    warn!("403 Forbidden response generated - GET method not allowed for phone home endpoint");

    let html = Html(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>403 - Forbidden</title>
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
            margin-top: 1rem;
        }
        p {
            color: #6c757d;
            line-height: 1.6;
        }
        .info {
            background: #e3f2fd;
            border-left: 4px solid #2196f3;
            padding: 1rem;
            margin: 1.5rem 0;
            text-align: left;
        }
        a {
            color: #3498db;
            text-decoration: none;
            font-weight: 500;
        }
        a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>403</h1>
        <h2>Forbidden</h2>
        <p>You don't have permission to access this resource.</p>
        <div class="info">
            <strong>Note:</strong> Phone home endpoints only accept POST requests.
        </div>
        <p><a href="/">Return to Home</a></p>
    </div>
</body>
</html>"#,
    );

    (StatusCode::FORBIDDEN, html).into_response()
}

/// Internal server error handler for 500 errors
pub async fn internal_server_error() -> Response {
    debug!("500 Internal Server Error handler invoked");

    let html = Html(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>500 - Internal Server Error</title>
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
            margin-top: 1rem;
        }
        p {
            color: #6c757d;
            line-height: 1.6;
        }
        a {
            color: #3498db;
            text-decoration: none;
            font-weight: 500;
        }
        a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>500</h1>
        <h2>Internal Server Error</h2>
        <p>Something went wrong on our end. Please try again later.</p>
        <p><a href="/">Return to Home</a></p>
    </div>
</body>
</html>"#,
    );

    (StatusCode::INTERNAL_SERVER_ERROR, html).into_response()
}

/// Method not allowed handler for 405 errors
pub async fn method_not_allowed() -> Response {
    debug!("405 Method Not Allowed handler invoked");

    let html = Html(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>405 - Method Not Allowed</title>
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
            margin-top: 1rem;
        }
        p {
            color: #6c757d;
            line-height: 1.6;
        }
        a {
            color: #3498db;
            text-decoration: none;
            font-weight: 500;
        }
        a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>405</h1>
        <h2>Method Not Allowed</h2>
        <p>The request method is not supported for this resource.</p>
        <p><a href="/">Return to Home</a></p>
    </div>
</body>
</html>"#,
    );

    (StatusCode::METHOD_NOT_ALLOWED, html).into_response()
}

/// Generic error handler
pub async fn handle_error(status_code: StatusCode) -> Response {
    match status_code {
        StatusCode::NOT_FOUND => not_found().await,
        StatusCode::BAD_REQUEST => bad_request().await,
        StatusCode::UNAUTHORIZED => unauthorized().await,
        StatusCode::FORBIDDEN => forbidden().await,
        StatusCode::INTERNAL_SERVER_ERROR => internal_server_error().await,
        StatusCode::METHOD_NOT_ALLOWED => method_not_allowed().await,
        _ => not_found().await,
    }
}
