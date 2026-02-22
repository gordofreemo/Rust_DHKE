use num_bigint::BigInt;

/// Protocol messages for Diffie-Hellman Key Exchange
#[derive(Debug, Clone)]
pub enum DHMessage {
    /// Client initiates the key exchange
    ClientHello,

    /// Server responds with agreed prime modulus (p) and base (g)
    ServerHello {
        p: BigInt,
        g: BigInt,
    },

    /// Client sends its public key: X = (g^x mod p)
    ClientPublicKey {
        x: BigInt,
    },

    /// Server sends its public key: Y = (g^y mod p)
    ServerPublicKey {
        y: BigInt,
    },

    /// Signals completion of the key exchange
    Done,
}

impl DHMessage {
    /// Serialize message to bytes for transmission
    /// Format: [type_byte] [data...]
    /// For BigInt values: [length:u32] [bytes...]
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            DHMessage::ClientHello => {
                vec![0]
            }
            DHMessage::ServerHello { p, g } => {
                let mut bytes = vec![1];
                serialize_bigint(&mut bytes, p);
                serialize_bigint(&mut bytes, g);
                bytes
            }
            DHMessage::ClientPublicKey { x } => {
                let mut bytes = vec![2];
                serialize_bigint(&mut bytes, x);
                bytes
            }
            DHMessage::ServerPublicKey { y } => {
                let mut bytes = vec![3];
                serialize_bigint(&mut bytes, y);
                bytes
            }
            DHMessage::Done => {
                vec![4]
            }
        }
    }

    /// Deserialize message from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() {
            return None;
        }

        let mut cursor = 1;

        match bytes[0] {
            0 => Some(DHMessage::ClientHello),
            1 => {
                let (p, new_cursor) = deserialize_bigint(&bytes, cursor)?;
                let (g, _) = deserialize_bigint(&bytes, new_cursor)?;
                Some(DHMessage::ServerHello { p, g })
            }
            2 => {
                let (x, _) = deserialize_bigint(&bytes, cursor)?;
                Some(DHMessage::ClientPublicKey { x })
            }
            3 => {
                let (y, _) = deserialize_bigint(&bytes, cursor)?;
                Some(DHMessage::ServerPublicKey { y })
            }
            4 => Some(DHMessage::Done),
            _ => None,
        }
    }
}

/// Serialize a BigInt to bytes with length prefix
fn serialize_bigint(bytes: &mut Vec<u8>, value: &BigInt) {
    let value_bytes = value.to_bytes_be();
    let len = value_bytes.1.len() as u32;
    bytes.extend(len.to_be_bytes());
    bytes.extend(&value_bytes.1);
}

/// Deserialize a BigInt from bytes with length prefix
fn deserialize_bigint(bytes: &[u8], cursor: usize) -> Option<(BigInt, usize)> {
    if cursor + 4 > bytes.len() {
        return None;
    }

    let len = u32::from_be_bytes([
        bytes[cursor],
        bytes[cursor + 1],
        bytes[cursor + 2],
        bytes[cursor + 3],
    ]) as usize;

    if cursor + 4 + len > bytes.len() {
        return None;
    }

    let value_bytes = &bytes[cursor + 4..cursor + 4 + len];
    let value = BigInt::from_bytes_be(num_bigint::Sign::Plus, value_bytes);

    Some((value, cursor + 4 + len))
}

/// Manages a Diffie-Hellman key exchange connection with a client
#[derive(Debug)]
pub struct DHConnection {
    /// TCP stream to communicate with the client
    pub stream: std::net::TcpStream,

    /// Prime modulus (p) - agreed upon by both parties
    pub prime: BigInt,

    /// Base generator (g) - agreed upon by both parties
    pub base: BigInt,

    /// Server's secret exponent
    pub secret_exponent: BigInt,

    /// Client's public key (X = g^x mod p)
    pub client_public_key: Option<BigInt>,

    /// Computed shared secret (X^secret_exponent mod p)
    pub shared_secret: Option<BigInt>,
}

impl DHConnection {
    /// Create a new DH connection with a client
    pub fn new(
        stream: std::net::TcpStream,
        prime: BigInt,
        base: BigInt,
        secret_exponent: BigInt,
    ) -> Self {
        DHConnection {
            stream,
            prime,
            base,
            secret_exponent,
            client_public_key: None,
            shared_secret: None,
        }
    }

    /// Get the peer address of the connected client
    pub fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.stream.peer_addr()
    }
}
