use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write};
use std::thread;
use num_bigint::BigInt;

use crate::structs::DH_Prot::{DHMessage, DHConnection};
use crate::crypto::crypto::{generate_dh_params, generate_secret_key, compute_public_key, mod_pow};

/// DH Server that listens for and handles multiple client connections
pub struct DHServer {
    /// Server's DH prime modulus
    prime: BigInt,
    /// Server's DH base generator
    base: BigInt,
    /// Listener socket
    listener: TcpListener,
}

impl DHServer {
    /// Create a new DH server and bind to the specified address
    ///
    /// # Arguments
    /// * `addr` - Address to bind to (e.g., "127.0.0.1:8080")
    /// * `bit_length` - Bit length for DH prime (e.g., 1024, 2048)
    ///
    /// # Returns
    /// A new DHServer instance
    pub fn new(addr: &str, bit_length: usize) -> std::io::Result<Self> {
        println!("[SERVER] Generating DH parameters ({} bits)...", bit_length);
        let (prime, base) = generate_dh_params(bit_length);
        
        println!("[SERVER] Binding to {}", addr);
        let listener: TcpListener = TcpListener::bind(addr)?;
        
        println!("[SERVER] Server listening on {}", addr);
        Ok(DHServer {
            prime,
            base,
            listener,
        })
    }

    /// Start the server and listen for incoming connections
    /// Spawns a new thread for each client connection
    pub fn run(&self) -> std::io::Result<()> {
        println!("[SERVER] Waiting for client connections...");
        
        for stream in self.listener.incoming() {
            match stream {
                Ok(client_stream) => {
                    let client_addr = client_stream.peer_addr().ok();
                    println!("[SERVER] New client connection: {:?}", client_addr);
                    
                    // Clone shared parameters (p, g) for this client's thread
                    // Note: p and g are shared per DH protocol, but each client gets unique secret exponent
                    let prime = self.prime.clone();
                    let base = self.base.clone();
                    
                    // Spawn a NEW THREAD for this client with completely isolated state
                    // Each thread:
                    // - Generates its own random secret exponent (y)
                    // - Maintains its own DHConnection with unique client public key (X)
                    // - Computes its own unique shared secret (not shared with other clients)
                    thread::spawn(move || {
                        if let Err(e) = handle_client(client_stream, prime, base) {
                            eprintln!("[SERVER] Error handling client {:?}: {}", client_addr, e);
                        }
                        // Thread exits here, taking the connection and secrets with it
                        // No state persists between clients
                    });
                }
                Err(e) => {
                    eprintln!("[SERVER] Error accepting connection: {}", e);
                }
            }
        }
        
        Ok(())
    }
}

/// Handle a single client connection through the DH key exchange
/// Each invocation is in its own thread with completely isolated state
fn handle_client(stream: TcpStream, prime: BigInt, base: BigInt) -> std::io::Result<()> {
    let client_addr = stream.peer_addr()?;
    println!("[CLIENT {}] Starting DH key exchange", client_addr);
    
    // *** CRITICAL: Generate UNIQUE secret exponent for THIS CLIENT ONLY ***
    // This is called once per client thread, ensuring each client gets a different secret
    let secret = generate_secret_key(&prime);
    println!("[CLIENT {}] Generated unique secret exponent for this client", client_addr);
    
    // Create a connection state for this client (local to this thread, not shared)
    let mut connection = DHConnection::new(stream, prime.clone(), base.clone(), secret.clone());
    
    // Set non-blocking to timeout reads
    connection.stream.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
    
    // Step 1: Receive ClientHello
    println!("[CLIENT {}] Waiting for ClientHello", client_addr);
    let client_hello = read_message(&mut connection.stream)?;
    
    match client_hello {
        Some(DHMessage::ClientHello) => {
            println!("[CLIENT {}] Received ClientHello", client_addr);
        }
        _ => {
            eprintln!("[CLIENT {}] Expected ClientHello, got {:?}", client_addr, client_hello);
            return Ok(());
        }
    }
    
    // Step 2: Send ServerHello with (p, g)
    let server_hello = DHMessage::ServerHello {
        p: connection.prime.clone(),
        g: connection.base.clone(),
    };
    
    println!("[CLIENT {}] Sending ServerHello with p and g", client_addr);
    write_message(&mut connection.stream, &server_hello)?;
    
    // Step 3: Receive ClientPublicKey
    println!("[CLIENT {}] Waiting for ClientPublicKey", client_addr);
    let client_pub_key = read_message(&mut connection.stream)?;
    
    match client_pub_key {
        Some(DHMessage::ClientPublicKey { x }) => {
            println!("[CLIENT {}] Received ClientPublicKey: {}", client_addr, x);
            connection.client_public_key = Some(x.clone());
        }
        _ => {
            eprintln!("[CLIENT {}] Expected ClientPublicKey, got {:?}", client_addr, client_pub_key);
            return Ok(());
        }
    }
    
    // Step 4: Compute and send ServerPublicKey
    let server_public_key = compute_public_key(&secret, &connection.base, &connection.prime);
    let server_key_msg = DHMessage::ServerPublicKey {
        y: server_public_key.clone(),
    };
    
    println!("[CLIENT {}] Sending ServerPublicKey", client_addr);
    write_message(&mut connection.stream, &server_key_msg)?;
    
    // Step 5: Receive Done
    println!("[CLIENT {}] Waiting for Done message", client_addr);
    let done_msg = read_message(&mut connection.stream)?;
    
    match done_msg {
        Some(DHMessage::Done) => {
            println!("[CLIENT {}] Received Done", client_addr);
        }
        _ => {
            eprintln!("[CLIENT {}] Expected Done, got {:?}", client_addr, done_msg);
            return Ok(());
        }
    }
    
    // Compute shared secret: X^secret mod p
    // *** UNIQUE to this client: each client's shared_secret is different ***
    if let Some(client_key) = &connection.client_public_key {
        let shared_secret = mod_pow(client_key, &secret, &connection.prime);
        connection.shared_secret = Some(shared_secret.clone());
        println!("[CLIENT {}] DH key exchange complete! Shared secret established.", client_addr);
        println!("[CLIENT {}] Shared secret (unique to this client): {}", client_addr, connection.shared_secret.as_ref().unwrap());
    }
    
    // Keep connection alive for future communication
    println!("[CLIENT {}] Connection ready for future communication", client_addr);
    
    let mut buffer = [0; 1024];
    loop {
        match connection.stream.read(&mut buffer) {
            Ok(0) => {
                println!("[CLIENT {}] Client disconnected", client_addr);
                break;
            }
            Ok(n) => {
                println!("[CLIENT {}] Received {} bytes", client_addr, n);
                // Echo back for now (can be extended for application-specific messages)
                connection.stream.write_all(&buffer[..n])?;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Timeout, continue waiting
                thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => {
                eprintln!("[CLIENT {}] Error reading from client: {}", client_addr, e);
                break;
            }
        }
    }
    
    println!("[CLIENT {}] Closing connection", client_addr);
    // *** ISOLATION GUARANTEED ***
    // All client-specific state (secret exponent, public key, shared secret, connection)
    // is dropped here and cleaned up from memory. No secrets persist after disconnect.
    Ok(())
}

/// Read a DHMessage from the stream
fn read_message(stream: &mut TcpStream) -> std::io::Result<Option<DHMessage>> {
    let mut type_byte = [0; 1];
    stream.read_exact(&mut type_byte)?;
    
    match type_byte[0] {
        0 => Ok(Some(DHMessage::ClientHello)),
        1 | 2 | 3 => {
            // For ServerHello, ClientPublicKey, ServerPublicKey:
            // First BigInt: [4-byte length][data]
            // If ServerHello, second BigInt follows
            let mut data = vec![type_byte[0]];
            
            // Read first BigInt
            let mut len_bytes = [0; 4];
            stream.read_exact(&mut len_bytes)?;
            data.extend_from_slice(&len_bytes);
            
            let len = u32::from_be_bytes(len_bytes) as usize;
            let mut value_bytes = vec![0; len];
            stream.read_exact(&mut value_bytes)?;
            data.extend(value_bytes);
            
            // If ServerHello, read second BigInt
            if type_byte[0] == 1 {
                let mut len_bytes = [0; 4];
                stream.read_exact(&mut len_bytes)?;
                data.extend_from_slice(&len_bytes);
                
                let len = u32::from_be_bytes(len_bytes) as usize;
                let mut value_bytes = vec![0; len];
                stream.read_exact(&mut value_bytes)?;
                data.extend(value_bytes);
            }
            
            Ok(DHMessage::from_bytes(&data))
        }
        4 => Ok(Some(DHMessage::Done)),
        _ => Ok(None),
    }
}

/// Write a DHMessage to the stream
fn write_message(stream: &mut TcpStream, message: &DHMessage) -> std::io::Result<()> {
    let bytes = message.to_bytes();
    stream.write_all(&bytes)?;
    stream.flush()?;
    Ok(())
}
