#pragma once
#include <string>
#include <openssl/dh.h>

// A small struct to hold ephemeral DH key objects
struct DHKeyPair {
    DH* dh;                // Our ephemeral DH object
    std::string public_key;  // Our public value (base64-encoded)
};

// Create DH parameters (p, g). In many real apps you might hard-code
// a known safe prime or load it from a file once.
DH* create_dh_params(unsigned int bits = 2048);

// Generate ephemeral keypair using the above parameters
DHKeyPair generate_dh_keypair(DH* dh_params);

// Compute the shared secret using our ephemeral key + peer’s public key
// Returns raw bytes of the shared secret.
std::string compute_dh_shared_secret(DH* my_dh, const std::string& peer_pub_b64);