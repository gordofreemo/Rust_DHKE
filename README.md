# Rust_DHKE

Implement a simple DHKE exchange in Rust - experiments in vibe coding.

## DHKE

Alice and Bob agree on a prime modulus p and and a base g. Alice chooses a secret exponent x and Bob chooses a secret exponent y.

Alice sends X=(g^x mod p) to Bob and Bob sends Y=(g^y mod p) to Alice.

Alice computes secret key with (Y^x mod p) and Bob computes with (X^y mod p).

Components necessary:
Network communication.
Cryptographic computation.

The program will take an IP address as input and perform DH key exchange with this IP address, we should have a DH server that sits and listens for incoming connections and a DH client that initializes these connections. Project Structure:
  src/ 
    crypto/
      crypto_computations.rs
      secure_communicate.rs
    network/
      client.rs
      server.rs
    protocol/
      protocol.rs // protocol enums and classes

Protocol Design:

Client --> Server
Client Hello

Server --> Client
Server Hello + (p,g)

Client --> Server
X=(g^x mod p)

Server --> Client
Y=(g^y mod p)

Client --> Server
Done

Server can have multiple connections at a time - handles DH key exchange for each client

protocol - Defines enums for the DH protocol
crypto - generates bases p and g, does mod computations and verification.
