#pragma once

#include <string>
#include <stdexcept>
#include "common.h"

class CryptoError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

struct EncryptedData {
    std::string iv;
    std::string ciphertext;
    std::string tag;
};

// AES-GCM encryption/decryption
EncryptedData aes_encrypt(const std::string& plaintext, const std::string& key);
std::string aes_decrypt(const EncryptedData& data, const std::string& key);

// Key generation
std::string generate_aes_key();
std::string generate_random_bytes(size_t length);

// Helper functions to encrypt and encode a message for sending
std::string prepare_secure_message(const std::string& message, const std::string& key);
std::string process_secure_message(const std::string& encoded_message, const std::string& key);