use std::net::TcpStream;
use std::io::{Read, Write};
use num_bigint::BigInt;

use crate::structs::DH_Prot::{DHMessage, DHConnection};
use crate::crypto::crypto::{generate_secret_key, compute_public_key, mod_pow};

/// DH Client that connects to a server and performs key exchange
pub struct DHClient {
    stream: TcpStream,
    server_addr: String,
}

impl DHClient {
    /// Create a new DH client and connect to the server
    ///
    /// # Arguments
    /// * `server_addr` - Server address (e.g., "127.0.0.1:8080")
    ///
    /// # Returns
    /// A new connected DHClient instance
    pub fn new(server_addr: &str) -> std::io::Result<Self> {
        println!("[CLIENT] Connecting to server at {}", server_addr);
        let stream = TcpStream::connect(server_addr)?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
        
        println!("[CLIENT] Connected to server at {}", server_addr);
        Ok(DHClient {
            stream,
            server_addr: server_addr.to_string(),
        })
    }

    /// Perform the Diffie-Hellman key exchange with the server
    pub fn perform_key_exchange(&mut self) -> std::io::Result<BigInt> {
        println!("[CLIENT] Starting DH key exchange with {}", self.server_addr);

        // Step 1: Send ClientHello
        println!("[CLIENT] Sending ClientHello");
        let client_hello = DHMessage::ClientHello;
        write_message(&mut self.stream, &client_hello)?;

        // Step 2: Receive ServerHello with (p, g)
        println!("[CLIENT] Waiting for ServerHello");
        let server_hello = read_message(&mut self.stream)?;

        let (prime, base) = match server_hello {
            Some(DHMessage::ServerHello { p, g }) => {
                println!("[CLIENT] Received ServerHello with p and g");
                (p, g)
            }
            _ => {
                eprintln!("[CLIENT] Expected ServerHello, got {:?}", server_hello);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid response from server",
                ));
            }
        };

        // Step 3: Generate client's secret exponent and compute public key
        println!("[CLIENT] Generating client secret exponent");
        let client_secret = generate_secret_key(&prime);
        let client_public_key = compute_public_key(&client_secret, &base, &prime);

        println!("[CLIENT] Sending ClientPublicKey");
        let client_key_msg = DHMessage::ClientPublicKey {
            x: client_public_key.clone(),
        };
        write_message(&mut self.stream, &client_key_msg)?;

        // Step 4: Receive ServerPublicKey
        println!("[CLIENT] Waiting for ServerPublicKey");
        let server_key_msg = read_message(&mut self.stream)?;

        let server_public_key = match server_key_msg {
            Some(DHMessage::ServerPublicKey { y }) => {
                println!("[CLIENT] Received ServerPublicKey");
                y
            }
            _ => {
                eprintln!("[CLIENT] Expected ServerPublicKey, got {:?}", server_key_msg);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid response from server",
                ));
            }
        };

        // Step 5: Send Done
        println!("[CLIENT] Sending Done");
        let done_msg = DHMessage::Done;
        write_message(&mut self.stream, &done_msg)?;

        // Step 6: Compute shared secret: Y^secret mod p
        println!("[CLIENT] Computing shared secret");
        let shared_secret = mod_pow(&server_public_key, &client_secret, &prime);

        println!("[CLIENT] DH key exchange complete!");
        println!("[CLIENT] Shared secret established: {}", shared_secret);

        Ok(shared_secret)
    }

    /// Send a message to the server (after key exchange)
    pub fn send_message(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.stream.write_all(data)?;
        self.stream.flush()?;
        Ok(())
    }

    /// Receive a message from the server (after key exchange)
    pub fn receive_message(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.stream.read(buffer)
    }

    /// Get the server address
    pub fn server_addr(&self) -> &str {
        &self.server_addr
    }
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
