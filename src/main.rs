mod crypto;
mod network;
mod structs;

use std::env;
use network::server::DHServer;
use network::client::DHClient;

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() > 1 && args[1] == "client" {
        // Run as client
        let server_addr = if args.len() > 2 {
            &args[2]
        } else {
            "127.0.0.1:8080"
        };

        println!("=== Diffie-Hellman Key Exchange Client ===\n");
        let mut client = DHClient::new(server_addr)?;
        let shared_secret = client.perform_key_exchange()?;

        println!("\n[CLIENT] Connection established with shared secret");
        println!("[CLIENT] You can now send messages to the server");
        
        // Keep connection alive for communication
        let mut buffer = [0; 1024];
        loop {
            match client.receive_message(&mut buffer) {
                Ok(0) => {
                    println!("[CLIENT] Server closed connection");
                    break;
                }
                Ok(n) => {
                    println!("[CLIENT] Received: {:?}", String::from_utf8_lossy(&buffer[..n]));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                Err(e) => {
                    eprintln!("[CLIENT] Connection error: {}", e);
                    break;
                }
            }
        }

        Ok(())
    } else {
        // Run as server
        println!("=== Diffie-Hellman Key Exchange Server ===\n");
        println!("Usage: cargo run [client [server_addr]]\n");
        
        // Create server on localhost:8080 with 512-bit primes (fast for testing, use 2048+ for production)
        let server = DHServer::new("127.0.0.1:8080", 512)?;
        
        // Run the server (blocks indefinitely, handling incoming connections)
        server.run()?;
        
        Ok(())
    }
}

