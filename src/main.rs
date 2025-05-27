use chrono::{Duration, Local};
use log::{LevelFilter, error, info};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use simplelog::{ColorChoice, CombinedLogger, Config, TermLogger, TerminalMode, WriteLogger};
use std::collections::HashMap;
use std::fs::File;
use std::process::Command;
use std::sync::{Arc, Mutex};
use warp::Filter;

#[derive(Deserialize)]
struct SendRequest {
    address: String,
}

#[derive(Serialize)]
struct Response {
    message: String,
}

struct RateLimiter {
    last_sent: HashMap<String, chrono::DateTime<Local>>,
}

fn is_valid_address(address: &str) -> bool {
    if address.is_empty()
        || address.contains(' ')
        || !address.starts_with("grin1")
        || !address.chars().all(|c| c.is_alphanumeric())
        || address.len() < 62
    {
        return false;
    }
    true
}

// Function to hash the IP address
fn hash_ip(ip: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(ip);
    let result = hasher.finalize();
    hex::encode(result) // Convert the hash to a hexadecimal string
}

#[tokio::main]
async fn main() {
    // Initialize logging
    let log_file = File::create("app.log").unwrap();
    CombinedLogger::init(vec![
        TermLogger::new(
            LevelFilter::Info,
            Config::default(),
            TerminalMode::Mixed,
            ColorChoice::Always,
        ),
        WriteLogger::new(LevelFilter::Info, Config::default(), log_file),
    ])
    .unwrap();

    let rate_limiter = Arc::new(Mutex::new(RateLimiter {
        last_sent: HashMap::new(),
    }));

    let rate_limiter_filter = warp::any().map(move || rate_limiter.clone());

    let send_faucet = warp::post()
        .and(warp::path("send"))
        .and(warp::body::json())
        .and(rate_limiter_filter.clone())
        .and(warp::addr::remote()) // Get the remote address
        .map(
            |request: SendRequest,
             rate_limiter: Arc<Mutex<RateLimiter>>,
             remote_addr: Option<std::net::SocketAddr>| {
                let address = request.address;

                // Validate the address
                if !is_valid_address(&address) {
                    return warp::reply::json(&Response {
                        message:
                            "Invalid: Must start with 'grin1' and be a valid 62 character address"
                                .to_string(),
                    });
                }

                let mut rate_limiter = rate_limiter.lock().unwrap();
                let now = Local::now();

                // Hash the IP address
                let ip_hash = match remote_addr {
                    Some(addr) => hash_ip(&addr.ip().to_string()),
                    None => {
                        return warp::reply::json(&Response {
                            message: "Could not retrieve IP address".to_string(),
                        });
                    }
                };

                info!("IP Hash: {}", ip_hash);

                // Check if the address has been sent funds in the last 24 hours
                if let Some(last_sent) = rate_limiter.last_sent.get(&ip_hash) {
                    if now - *last_sent < Duration::hours(24) {
                        info!("Criminal {} requested funds too often.", ip_hash);
                        return warp::reply::json(&Response {
                            message: "You can only request 1ツ every 24 hours".to_string(),
                        });
                    }
                }

                // Execute the command
                let output = Command::new("bash")
                    .arg("-c")
                    .arg(format!(
                        "echo '<PASSWORD>' | <DIR>/grin-wallet send -d {} 1",
                        address
                    ))
                    .output()
                    .expect("Failed to execute command");

                // Update the last sent time
                rate_limiter.last_sent.insert(ip_hash.clone(), now);

                // Handle command output
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);

                if stderr.is_empty() {
                    if let Some(slatepack_message) = extract_slatepack_message(&stdout) {
                        info!(" {}", slatepack_message);
                        return warp::reply::json(&Response {
                            message: slatepack_message,
                        });
                    } else {
                        info!("Grin sent successfully to address: {}", address);
                        return warp::reply::json(&Response {
                            message: "Grin sent via TOR ツ".to_string(),
                        });
                    }
                } else {
                    error!("Error sending funds to address {}: {}", address, stderr);
                    return warp::reply::json(&Response {
                        message: format!("Error: {}", stderr),
                    });
                }
            },
        );

    // Load SSL keys and certs
    let cert_path = "<PATHTOCERT>";
    let key_path = "<PATHTOPRIVKEY>";

    // Enable CORS only from this site
    let cors = warp::cors()
        .allow_origin("https://<URL>")
        .allow_methods(vec!["POST"]) // Allow POST requests
        .allow_headers(vec!["Content-Type"]); // Allow Content-Type header

    // Start the warp server with CORS & TLS
    warp::serve(send_faucet.with(cors))
        .tls()
        .cert_path(cert_path)
        .key_path(key_path)
        .run(([0, 0, 0, 0], 3031)) // Listen on all interfaces
        .await;
}

// Function to extract the slatepack message from the output
fn extract_slatepack_message(stdout: &str) -> Option<String> {
    let start_marker = "BEGINSLATEPACK.";
    let end_marker = "ENDSLATEPACK.";

    if let Some(start) = stdout.find(start_marker) {
        if let Some(end) = stdout.find(end_marker) {
            let slatepack_message = &stdout[start..end + end_marker.len()];

            let trimmed_message = if slatepack_message.starts_with(' ') {
                &slatepack_message[1..] // Remove the first character (space)
            } else {
                slatepack_message // Return the original message if no leading space
            };

            return Some(trimmed_message.to_string());
        }
    }
    None
}
