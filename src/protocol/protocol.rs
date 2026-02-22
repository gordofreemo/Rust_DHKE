/// Protocol messages for Diffie-Hellman Key Exchange
#[derive(Debug, Clone)]
pub enum DHMessage {
    /// Client initiates the key exchange
    ClientHello,

    /// Server responds with agreed prime modulus (p) and base (g)
    ServerHello {
        p: u64,
        g: u64,
    },

    /// Client sends its public key: X = (g^x mod p)
    ClientPublicKey {
        x: u64,
    },

    /// Server sends its public key: Y = (g^y mod p)
    ServerPublicKey {
        y: u64,
    },

    /// Signals completion of the key exchange
    Done,
}

impl DHMessage {
    /// Serialize message to bytes for transmission
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            DHMessage::ClientHello => {
                vec![0]
            }
            DHMessage::ServerHello { p, g } => {
                let mut bytes = vec![1];
                bytes.extend(p.to_le_bytes());
                bytes.extend(g.to_le_bytes());
                bytes
            }
            DHMessage::ClientPublicKey { x } => {
                let mut bytes = vec![2];
                bytes.extend(x.to_le_bytes());
                bytes
            }
            DHMessage::ServerPublicKey { y } => {
                let mut bytes = vec![3];
                bytes.extend(y.to_le_bytes());
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

        match bytes[0] {
            0 => Some(DHMessage::ClientHello),
            1 => {
                if bytes.len() >= 17 {
                    let p = u64::from_le_bytes([
                        bytes[1], bytes[2], bytes[3], bytes[4],
                        bytes[5], bytes[6], bytes[7], bytes[8],
                    ]);
                    let g = u64::from_le_bytes([
                        bytes[9], bytes[10], bytes[11], bytes[12],
                        bytes[13], bytes[14], bytes[15], bytes[16],
                    ]);
                    Some(DHMessage::ServerHello { p, g })
                } else {
                    None
                }
            }
            2 => {
                if bytes.len() >= 9 {
                    let x = u64::from_le_bytes([
                        bytes[1], bytes[2], bytes[3], bytes[4],
                        bytes[5], bytes[6], bytes[7], bytes[8],
                    ]);
                    Some(DHMessage::ClientPublicKey { x })
                } else {
                    None
                }
            }
            3 => {
                if bytes.len() >= 9 {
                    let y = u64::from_le_bytes([
                        bytes[1], bytes[2], bytes[3], bytes[4],
                        bytes[5], bytes[6], bytes[7], bytes[8],
                    ]);
                    Some(DHMessage::ServerPublicKey { y })
                } else {
                    None
                }
            }
            4 => Some(DHMessage::Done),
            _ => None,
        }
    }
}
