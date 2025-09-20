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
    last_sent_ip: HashMap<String, chrono::DateTime<Local>>,
    last_sent_address: HashMap<String, chrono::DateTime<Local>>,
}

fn is_valid_address(address: &str) -> bool {
    if address.is_empty()
        || address.contains(' ')
        || (!address.starts_with("grin1"))
        || !address.chars().all(|c| c.is_alphanumeric())
        || address.len() < 62
    {
        return false;
    }
    true
}

// hash the IP address
fn hash_ip(ip: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(ip);
    let result = hasher.finalize();
    hex::encode(result) // hash to hex
}

#[tokio::main]
async fn main() {
    // logging
    let log_file = File::create("faucet.log").unwrap();
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
        last_sent_ip: HashMap::new(),
        last_sent_address: HashMap::new(),
    }));

    let rate_limiter_filter = warp::any().map(move || rate_limiter.clone());

    let send_faucet = warp::post()
        .and(warp::path("send"))
        .and(warp::body::json())
        .and(rate_limiter_filter.clone())
        .and(warp::addr::remote()) 
        .map(
            |request: SendRequest,
             rate_limiter: Arc<Mutex<RateLimiter>>,
             remote_addr: Option<std::net::SocketAddr>| {
                let address = request.address;

                // wallet address validator
                if !is_valid_address(&address) {
                    return warp::reply::json(&Response {
                        message:
                            "Invalid: Must start with 'grin1' and be a valid address"
                                .to_string(),
                    });
                }

                let mut rate_limiter = rate_limiter.lock().unwrap();
                let now = Local::now();

                // hash the IP address
                let ip_hash = match remote_addr {
                    Some(addr) => hash_ip(&addr.ip().to_string()),
                    None => {
                        return warp::reply::json(&Response {
                            message: "Could not retrieve IP address".to_string(),
                        });
                    }
                };

                // check IP for sends in the last 24 hours
                if let Some(last_sent) = rate_limiter.last_sent_ip.get(&ip_hash) {
                    if now - *last_sent < Duration::hours(24) {
                        return warp::reply::json(&Response {
                            message: "You can only request 1ツ every 24 hours".to_string(),
                        });
                    }
                }

                // check address for sends in the last 24 hours
                if let Some(last_sent) = rate_limiter.last_sent_address.get(&address) {
                    if now - *last_sent < Duration::hours(24) {
                        return warp::reply::json(&Response {
                            message: "This wallet address can only request 1ツ every 24 hours".to_string(),
                        });
                    }
                }

                // grin-wallet send
                let output = Command::new("bash")
                    .arg("-c")
                    .arg(format!(
                        "echo '<PASSWORD>' | /usr/local/bin/grin-wallet send -d {} 1",
                        address
                    ))
                    .output()
                    .expect("Failed to execute command");

                // Handle grin-wallet output
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);

                // Not enough funds error
                let combined_output = format!("{}{}", stdout, stderr);
                if combined_output.contains("Not enough funds") || 
                   combined_output.contains("LibWallet Error: Not enough funds") ||
                   combined_output.contains("Wallet command failed: Not enough funds") {
                    error!("Faucet is empty ¯\\_(ツ)_/¯");
                    return warp::reply::json(&Response {
                        message: "Faucet is empty ¯\\_(ツ)_/¯".to_string(),
                    });
                }

                // Offline wallet slatepack response
                if let Some(slatepack_message) = extract_slatepack_message(&stdout) {
                    rate_limiter.last_sent_ip.insert(ip_hash.clone(), now);
                    rate_limiter.last_sent_address.insert(address.clone(), now);

                    info!("IP: {}, Wallet: {}, Slatepack issued", ip_hash, address);
                    return warp::reply::json(&Response {
                        message: slatepack_message,
                    });
                }

                // Tor sending success
                if stdout.contains("WARN grin_wallet_api::owner - Attempting to send transaction via TOR")
                    && stdout.contains("Tx sent successfully")
                    && stdout.contains("Command 'send' completed successfully")
                {
                    rate_limiter.last_sent_ip.insert(ip_hash.clone(), now);
                    rate_limiter.last_sent_address.insert(address.clone(), now);

                    info!("Grin sent via Tor to Wallet: {} (IP: {})", address, ip_hash);
                    return warp::reply::json(&Response {
                        message: "Grin sent via Tor ツ".to_string(),
                    });
                }

                // sending errors (log but don’t rate limit)
                error!("Error sending funds to Wallet {} (IP: {}): {}", address, ip_hash, stderr);
                warp::reply::json(&Response {
                    message: "Error: Transaction did not complete successfully.".to_string(),
                })
            } 
        ); 

    // Load TLS keys
    let cert_path = "/etc/ssl/cert.pem";
    let key_path = "/etc/ssl/privkey.pem";

    // Enable CORS 
    let cors = warp::cors()
        .allow_origin("https://spigot.grinminer.net")
        .allow_methods(vec!["POST"]) 
        .allow_headers(vec!["Content-Type"]); 

    // Start the warp server
    warp::serve(send_faucet.with(cors))
        .tls()
        .cert_path(cert_path)
        .key_path(key_path)
        .run(([0, 0, 0, 0], 3031)) 
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
                &slatepack_message[1..] // Remove the whitespace at beginning
            } else {
                slatepack_message // Return original message if no space
            };

            return Some(trimmed_message.to_string());
        }
    }
    None
}
