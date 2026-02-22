use num_bigint::{BigInt, RandBigInt, BigUint, ToBigInt};
use num_traits::{One, Zero};
use rand::Rng;

/// Performs Miller-Rabin primality test on a number
fn is_prime(n: &BigInt, rounds: usize) -> bool {
    if n < &BigInt::from(2) {
        return false;
    }
    if n == &BigInt::from(2) || n == &BigInt::from(3) {
        return true;
    }
    if n % 2 == BigInt::zero() {
        return false;
    }

    // Write n-1 as d * 2^r
    let mut d = n - BigInt::one();
    let mut r = 0;
    while &d % 2 == &BigInt::zero() {
        d /= 2;
        r += 1;
    }

    let mut rng = rand::thread_rng();
    
    'witness_loop: for _ in 0..rounds {
        let a = rng.gen_bigint_range(&BigInt::from(2), &(n - BigInt::one()));
        let mut x = mod_pow(&a, &d, n);

        if x == BigInt::one() || x == n - BigInt::one() {
            continue 'witness_loop;
        }

        for _ in 0..r - 1 {
            x = mod_pow(&x, &BigInt::from(2), n);
            if x == n - BigInt::one() {
                continue 'witness_loop;
            }
        }

        return false;
    }

    true
}

/// Modular exponentiation: (base^exp) mod modulus
fn mod_pow(base: &BigInt, exp: &BigInt, modulus: &BigInt) -> BigInt {
    let mut result = BigInt::one();
    let mut base = base % modulus;
    let mut exp = exp.clone();

    while exp > BigInt::zero() {
        if &exp % 2 == BigInt::one() {
            result = (result * &base) % modulus;
        }
        exp >>= 1;
        base = (&base * &base) % modulus;
    }

    result
}

/// Generates a random prime of approximately bit_length bits
fn generate_random_prime(bit_length: usize) -> BigInt {
    let mut rng = rand::thread_rng();

    loop {
        let mut p = rng.gen_bigint(bit_length as u64);
        
        // Ensure it's odd
        if &p % 2 == BigInt::zero() {
            p += BigInt::one();
        }
        
        // Set MSB and LSB to ensure correct bit length
        p.set_bit((bit_length - 1) as u64, true);
        
        if is_prime(&p, 64) {
            return p;
        }
    }
}

/// Finds a generator g for the multiplicative group modulo p
/// g should satisfy: 1 < g < p and g^((p-1)/2) mod p != 1
fn find_generator(p: &BigInt) -> BigInt {
    let mut rng = rand::thread_rng();
    let exp = (p - BigInt::one()) / 2;

    loop {
        let g = rng.gen_bigint_range(&BigInt::from(2), &(p - BigInt::one()));
        
        // Check if g is a valid generator
        // For a safe prime, g should satisfy: g^((p-1)/2) mod p != 1
        let test = mod_pow(&g, &exp, p);
        if test != BigInt::one() {
            return g;
        }
    }
}

/// Generates DH parameters (p, g) for key exchange
/// 
/// # Arguments
/// * `bit_length` - The bit length of prime p (typically 1024, 2048, or 4096)
///
/// # Returns
/// A tuple (p, g) where:
/// - p is a large random prime
/// - g is a generator of the multiplicative group modulo p
pub fn generate_dh_params(bit_length: usize) -> (BigInt, BigInt) {
    println!("Generating {} bit prime p...", bit_length);
    let p = generate_random_prime(bit_length);
    
    println!("Prime p generated. Generating generator g...");
    let g = find_generator(&p);
    
    println!("DH parameters generated successfully!");
    (p, g)
}

/// Generates a random secret key for DH key exchange
///
/// # Arguments
/// * `p` - The prime modulus from DH parameters
///
/// # Returns
/// A random BigInt in the range (1, p-1) to be used as a secret key
pub fn generate_secret_key(p: &BigInt) -> BigInt {
    let mut rng = rand::thread_rng();
    rng.gen_bigint_range(&BigInt::from(2), &(p - BigInt::one()))
}

/// Computes the public key from a secret key using DH parameters
///
/// # Arguments
/// * `secret_key` - The private key
/// * `g` - The generator from DH parameters
/// * `p` - The prime modulus from DH parameters
///
/// # Returns
/// The public key: g^{secret_key} mod p
pub fn compute_public_key(secret_key: &BigInt, g: &BigInt, p: &BigInt) -> BigInt {
    mod_pow(g, secret_key, p)
}
