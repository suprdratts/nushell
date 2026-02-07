//! The `seksh-http` command - secure HTTP client with internal secret injection
//!
//! This command makes HTTP requests with secrets injected internally.
//! The shell NEVER sees the actual secret values - they go directly from
//! the broker into the HTTP request.

use nu_engine::command_prelude::*;
use nu_seks::{BrokerClient, register_named_secret, scrub_output};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

#[derive(Clone)]
pub struct SekshHttp;

impl Command for SekshHttp {
    fn name(&self) -> &str {
        "seksh-http"
    }

    fn description(&self) -> &str {
        "Make HTTP requests with secrets injected internally (never exposed to shell)."
    }

    fn signature(&self) -> Signature {
        Signature::build("seksh-http")
            .input_output_types(vec![(Type::Nothing, Type::String)])
            .required("method", SyntaxShape::String, "HTTP method (GET, POST, PUT, DELETE, etc.)")
            .required("url", SyntaxShape::String, "URL to request")
            .named(
                "auth-bearer",
                SyntaxShape::String,
                "Secret name to use as Bearer token",
                Some('a'),
            )
            .named(
                "auth-basic-user",
                SyntaxShape::String,
                "Secret name for basic auth username",
                None,
            )
            .named(
                "auth-basic-pass",
                SyntaxShape::String,
                "Secret name for basic auth password",
                None,
            )
            .named(
                "header-secret",
                SyntaxShape::List(Box::new(SyntaxShape::String)),
                "Header with secret value: 'Header-Name:secret_name'",
                Some('H'),
            )
            .named(
                "header",
                SyntaxShape::List(Box::new(SyntaxShape::String)),
                "Plain header (no secrets): 'Header-Name: value'",
                Some('e'),
            )
            .named(
                "data",
                SyntaxShape::String,
                "Request body data",
                Some('d'),
            )
            .named(
                "timeout",
                SyntaxShape::Int,
                "Timeout in seconds (default: 30)",
                Some('t'),
            )
            .switch("insecure", "Allow insecure TLS connections", Some('k'))
            .category(Category::Network)
    }

    fn extra_description(&self) -> &str {
        r#"Makes HTTP requests with secrets injected securely. Unlike using getseks with
curl, the actual secret values NEVER enter the shell's memory space.

The secret is fetched directly from the broker and injected into the HTTP
request headers. The shell only sees the secret NAME, not the VALUE.

SECURITY MODEL:
- Secret values go: Broker → seksh-http → HTTP request
- Shell sees: Command args (secret names) + Response (scrubbed)
- Shell NEVER sees: Actual secret values

COMPARISON:
  # UNSAFE - secret enters shell memory, can be exfiltrated
  ^curl -H $"Authorization: Bearer (getseks github_token)" $url

  # SAFE - secret never enters shell memory
  seksh-http get $url --auth-bearer github_token

ENVIRONMENT VARIABLES:
  SEKS_BROKER_URL    - Broker URL (default: http://localhost:8787)
  SEKS_AGENT_TOKEN   - Agent bearer token (required)

The response body is still scrubbed as defense-in-depth (in case an API
echoes tokens back), but the primary security is that secrets never enter
the shell at all."#
    }

    fn run(
        &self,
        engine_state: &EngineState,
        stack: &mut Stack,
        call: &Call,
        _input: PipelineData,
    ) -> Result<PipelineData, ShellError> {
        let span = call.head;
        
        // Parse arguments
        let method: String = call.req(engine_state, stack, 0)?;
        let url: String = call.req(engine_state, stack, 1)?;
        
        let auth_bearer: Option<String> = call.get_flag(engine_state, stack, "auth-bearer")?;
        let auth_basic_user: Option<String> = call.get_flag(engine_state, stack, "auth-basic-user")?;
        let auth_basic_pass: Option<String> = call.get_flag(engine_state, stack, "auth-basic-pass")?;
        let header_secrets: Option<Vec<String>> = call.get_flag(engine_state, stack, "header-secret")?;
        let plain_headers: Option<Vec<String>> = call.get_flag(engine_state, stack, "header")?;
        let data: Option<String> = call.get_flag(engine_state, stack, "data")?;
        let timeout: Option<i64> = call.get_flag(engine_state, stack, "timeout")?;
        let insecure: bool = call.has_flag(engine_state, stack, "insecure")?;

        // Build the request
        let mut headers: HashMap<String, String> = HashMap::new();
        let broker = BrokerClient::new();

        // Handle Bearer auth
        if let Some(secret_name) = auth_bearer {
            let secret = fetch_secret(&broker, &secret_name, span)?;
            register_named_secret(&secret_name, &secret);
            headers.insert("Authorization".to_string(), format!("Bearer {}", secret));
        }

        // Handle Basic auth
        if let Some(user_secret) = auth_basic_user {
            let pass_secret = auth_basic_pass.ok_or_else(|| ShellError::GenericError {
                error: "Basic auth requires both user and password".into(),
                msg: "--auth-basic-user requires --auth-basic-pass".into(),
                span: Some(span),
                help: None,
                inner: vec![],
            })?;

            let username = fetch_secret(&broker, &user_secret, span)?;
            let password = fetch_secret(&broker, &pass_secret, span)?;
            
            register_named_secret(&user_secret, &username);
            register_named_secret(&pass_secret, &password);

            let credentials = format!("{}:{}", username, password);
            let encoded = base64_encode(credentials.as_bytes());
            headers.insert("Authorization".to_string(), format!("Basic {}", encoded));
        }

        // Handle secret headers
        if let Some(secret_headers) = header_secrets {
            for header_spec in secret_headers {
                let parts: Vec<&str> = header_spec.splitn(2, ':').collect();
                if parts.len() != 2 {
                    return Err(ShellError::GenericError {
                        error: "Invalid header-secret format".into(),
                        msg: format!("Expected 'Header-Name:secret_name', got: {}", header_spec),
                        span: Some(span),
                        help: Some("Use format: --header-secret 'X-Api-Key:my_api_key'".into()),
                        inner: vec![],
                    });
                }
                let header_name = parts[0].trim().to_string();
                let secret_name = parts[1].trim();
                let secret = fetch_secret(&broker, secret_name, span)?;
                register_named_secret(secret_name, &secret);
                headers.insert(header_name, secret);
            }
        }

        // Handle plain headers
        if let Some(plain) = plain_headers {
            for header_spec in plain {
                let parts: Vec<&str> = header_spec.splitn(2, ':').collect();
                if parts.len() != 2 {
                    return Err(ShellError::GenericError {
                        error: "Invalid header format".into(),
                        msg: format!("Expected 'Header-Name: value', got: {}", header_spec),
                        span: Some(span),
                        help: None,
                        inner: vec![],
                    });
                }
                headers.insert(parts[0].trim().to_string(), parts[1].trim().to_string());
            }
        }

        // Make the HTTP request
        let timeout_secs = timeout.unwrap_or(30) as u64;
        let response = make_http_request(
            &method.to_uppercase(),
            &url,
            &headers,
            data.as_deref(),
            timeout_secs,
            insecure,
        ).map_err(|e| ShellError::GenericError {
            error: "HTTP request failed".into(),
            msg: e,
            span: Some(span),
            help: None,
            inner: vec![],
        })?;

        // Scrub the response (defense-in-depth)
        let scrubbed = scrub_output(&response);

        Ok(Value::string(scrubbed, span).into_pipeline_data())
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![
            Example {
                description: "GET request with Bearer token auth",
                example: "seksh-http get https://api.github.com/user --auth-bearer github_token",
                result: None,
            },
            Example {
                description: "POST request with API key header",
                example: "seksh-http post https://api.example.com/data --header-secret 'X-Api-Key:api_key' --data '{\"foo\": \"bar\"}'",
                result: None,
            },
            Example {
                description: "Request with basic auth",
                example: "seksh-http get https://api.example.com --auth-basic-user db_user --auth-basic-pass db_pass",
                result: None,
            },
            Example {
                description: "Multiple secret headers",
                example: "seksh-http get $url --header-secret 'Authorization:token' --header-secret 'X-Api-Key:key'",
                result: None,
            },
        ]
    }
}

fn fetch_secret(broker: &BrokerClient, name: &str, span: Span) -> Result<String, ShellError> {
    broker.get_secret(name).map_err(|e| ShellError::GenericError {
        error: format!("Failed to get secret '{}'", name),
        msg: e.to_string(),
        span: Some(span),
        help: Some("Make sure the SEKS broker is running and the secret exists".into()),
        inner: vec![],
    })
}

/// Simple base64 encoding without external dependencies
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    let mut result = String::new();
    let mut i = 0;
    
    while i < input.len() {
        let b0 = input[i] as usize;
        let b1 = if i + 1 < input.len() { input[i + 1] as usize } else { 0 };
        let b2 = if i + 2 < input.len() { input[i + 2] as usize } else { 0 };
        
        result.push(ALPHABET[b0 >> 2] as char);
        result.push(ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)] as char);
        
        if i + 1 < input.len() {
            result.push(ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)] as char);
        } else {
            result.push('=');
        }
        
        if i + 2 < input.len() {
            result.push(ALPHABET[b2 & 0x3f] as char);
        } else {
            result.push('=');
        }
        
        i += 3;
    }
    
    result
}

/// Make an HTTP request (simple implementation without external HTTP client)
/// For production, this should use a proper HTTP client like reqwest
fn make_http_request(
    method: &str,
    url: &str,
    headers: &HashMap<String, String>,
    body: Option<&str>,
    timeout_secs: u64,
    _insecure: bool,
) -> Result<String, String> {
    // Parse URL
    let url = url.trim();
    
    // For HTTPS, we need TLS support - use native-tls or rustls
    // For now, this is a minimal implementation that handles HTTP
    // In production, integrate with nu-command's HTTP client or use reqwest
    
    let (scheme, rest) = if url.starts_with("https://") {
        ("https", &url[8..])
    } else if url.starts_with("http://") {
        ("http", &url[7..])
    } else {
        return Err("URL must start with http:// or https://".to_string());
    };

    let (host_port, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };

    let (host, port) = match host_port.find(':') {
        Some(idx) => (&host_port[..idx], host_port[idx + 1..].parse::<u16>().unwrap_or(if scheme == "https" { 443 } else { 80 })),
        None => (host_port, if scheme == "https" { 443 } else { 80 }),
    };

    if scheme == "https" {
        // For HTTPS, we need to use the system's HTTP client or a TLS library
        // This is a limitation of the minimal implementation
        // Fall back to using curl as a subprocess (ironic but practical)
        return make_https_request_via_curl(method, url, headers, body, timeout_secs);
    }

    // HTTP implementation
    let addr = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect(&addr)
        .map_err(|e| format!("Failed to connect to {}: {}", addr, e))?;
    
    stream.set_read_timeout(Some(Duration::from_secs(timeout_secs))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(timeout_secs))).ok();

    // Build request
    let mut request = format!("{} {} HTTP/1.1\r\n", method, path);
    request.push_str(&format!("Host: {}\r\n", host));
    request.push_str("Connection: close\r\n");
    
    for (name, value) in headers {
        request.push_str(&format!("{}: {}\r\n", name, value));
    }
    
    if let Some(body_data) = body {
        request.push_str(&format!("Content-Length: {}\r\n", body_data.len()));
        if !headers.contains_key("Content-Type") {
            request.push_str("Content-Type: application/json\r\n");
        }
    }
    
    request.push_str("\r\n");
    
    if let Some(body_data) = body {
        request.push_str(body_data);
    }

    stream.write_all(request.as_bytes())
        .map_err(|e| format!("Failed to send request: {}", e))?;
    stream.flush()
        .map_err(|e| format!("Failed to flush: {}", e))?;

    // Read response
    let mut response = Vec::new();
    stream.read_to_end(&mut response)
        .map_err(|e| format!("Failed to read response: {}", e))?;

    String::from_utf8(response)
        .map_err(|e| format!("Invalid UTF-8 in response: {}", e))
}

/// For HTTPS, use curl subprocess (practical fallback)
/// The key security property is maintained: secrets go directly from broker to curl args,
/// never through nushell's shell expansion
fn make_https_request_via_curl(
    method: &str,
    url: &str,
    headers: &HashMap<String, String>,
    body: Option<&str>,
    timeout_secs: u64,
) -> Result<String, String> {
    use std::process::{Command, Stdio};
    
    let mut cmd = Command::new("curl");
    cmd.arg("-s") // silent
       .arg("-S") // show errors
       .arg("-X").arg(method)
       .arg("--max-time").arg(timeout_secs.to_string());
    
    for (name, value) in headers {
        cmd.arg("-H").arg(format!("{}: {}", name, value));
    }
    
    if let Some(body_data) = body {
        cmd.arg("-d").arg(body_data);
    }
    
    cmd.arg(url);
    
    cmd.stdout(Stdio::piped())
       .stderr(Stdio::piped());
    
    let output = cmd.output()
        .map_err(|e| format!("Failed to execute curl: {}", e))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("curl failed: {}", stderr));
    }
    
    String::from_utf8(output.stdout)
        .map_err(|e| format!("Invalid UTF-8 in response: {}", e))
}
