//! SEKS Broker - Secret Management Daemon
//!
//! A simple daemon that:
//! - Reads secrets from ~/.seksh/secrets.json
//! - Listens on Unix socket ~/.seksh/broker.sock
//! - Responds to get/list requests over JSON protocol

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::Arc;

/// Request from client
#[derive(Debug, Deserialize)]
struct Request {
    cmd: String,
    #[serde(default)]
    name: String,
}

/// Response to client
#[derive(Debug, Serialize)]
#[serde(untagged)]
enum Response {
    Value { value: String },
    Names { names: Vec<String> },
    Error { error: String },
}

fn get_seksh_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".seksh")
}

fn load_secrets(path: &PathBuf) -> HashMap<String, String> {
    match fs::read_to_string(path) {
        Ok(content) => match serde_json::from_str(&content) {
            Ok(secrets) => secrets,
            Err(e) => {
                eprintln!("Failed to parse secrets.json: {}", e);
                HashMap::new()
            }
        },
        Err(e) => {
            eprintln!("Failed to read secrets.json: {}", e);
            eprintln!("Create ~/.seksh/secrets.json with your secrets");
            HashMap::new()
        }
    }
}

fn handle_client(mut stream: UnixStream, secrets: &HashMap<String, String>) {
    let peer = stream
        .peer_addr()
        .map(|a| format!("{:?}", a))
        .unwrap_or_else(|_| "unknown".to_string());
    eprintln!("Client connected: {}", peer);

    let reader = BufReader::new(stream.try_clone().expect("Failed to clone stream"));

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Failed to read from client: {}", e);
                break;
            }
        };

        if line.is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<Request>(&line) {
            Ok(req) => handle_request(&req, secrets),
            Err(e) => Response::Error {
                error: format!("Invalid request: {}", e),
            },
        };

        let response_json = serde_json::to_string(&response).unwrap_or_else(|_| {
            r#"{"error":"Failed to serialize response"}"#.to_string()
        });

        if let Err(e) = writeln!(stream, "{}", response_json) {
            eprintln!("Failed to write response: {}", e);
            break;
        }

        if let Err(e) = stream.flush() {
            eprintln!("Failed to flush: {}", e);
            break;
        }
    }

    eprintln!("Client disconnected: {}", peer);
}

fn handle_request(req: &Request, secrets: &HashMap<String, String>) -> Response {
    match req.cmd.as_str() {
        "get" => {
            if req.name.is_empty() {
                return Response::Error {
                    error: "Missing 'name' field".to_string(),
                };
            }

            match secrets.get(&req.name) {
                Some(value) => Response::Value {
                    value: value.clone(),
                },
                None => Response::Error {
                    error: format!("Secret '{}' not found", req.name),
                },
            }
        }
        "list" => {
            let names: Vec<String> = secrets.keys().cloned().collect();
            Response::Names { names }
        }
        _ => Response::Error {
            error: format!("Unknown command: {}", req.cmd),
        },
    }
}

fn main() {
    let seksh_dir = get_seksh_dir();
    let secrets_path = seksh_dir.join("secrets.json");
    let socket_path = seksh_dir.join("broker.sock");

    // Ensure directory exists
    if let Err(e) = fs::create_dir_all(&seksh_dir) {
        eprintln!("Failed to create ~/.seksh directory: {}", e);
        std::process::exit(1);
    }

    // Load secrets
    eprintln!("Loading secrets from: {}", secrets_path.display());
    let secrets = Arc::new(load_secrets(&secrets_path));
    eprintln!("Loaded {} secrets", secrets.len());

    // Remove old socket if it exists
    if socket_path.exists() {
        if let Err(e) = fs::remove_file(&socket_path) {
            eprintln!("Failed to remove old socket: {}", e);
            std::process::exit(1);
        }
    }

    // Create the socket
    let listener = match UnixListener::bind(&socket_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to bind socket: {}", e);
            std::process::exit(1);
        }
    };

    // Set socket permissions (owner only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600)) {
            eprintln!("Warning: Failed to set socket permissions: {}", e);
        }
    }

    eprintln!("SEKS Broker listening on: {}", socket_path.display());
    eprintln!("Press Ctrl+C to stop");

    // Handle incoming connections
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let secrets = Arc::clone(&secrets);
                std::thread::spawn(move || {
                    handle_client(stream, &secrets);
                });
            }
            Err(e) => {
                eprintln!("Failed to accept connection: {}", e);
            }
        }
    }
}
