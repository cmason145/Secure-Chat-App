#include "../include/crypto.h"
#include <openssl/evp.h>
#include <openssl/rand.h>

EncryptedData aes_encrypt(const std::string &plaintext, const std::string &key)
{
    if (key.size() != 32)
        throw CryptoError("Invalid key size");

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        throw CryptoError("Failed to create context");

    EncryptedData result;
    result.iv = generate_random_bytes(12);

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(),
                                nullptr,
                                reinterpret_cast<const unsigned char *>(key.data()),
                                reinterpret_cast<const unsigned char *>(result.iv.data())))
    {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoError("Encryption init failed");
    }

    std::string ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH, '\0');
    int len;

    if (1 != EVP_EncryptUpdate(ctx,
                               reinterpret_cast<unsigned char *>(&ciphertext[0]),
                               &len,
                               reinterpret_cast<const unsigned char *>(plaintext.data()),
                               plaintext.size()))
    {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoError("Encryption update failed");
    }
    int ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx,
                                 reinterpret_cast<unsigned char *>(&ciphertext[0]) + len,
                                 &len))
    {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoError("Encryption final failed");
    }
    ciphertext_len += len;

    result.ciphertext = ciphertext.substr(0, ciphertext_len);
    result.tag.resize(16);

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16,
                                 reinterpret_cast<unsigned char *>(&result.tag[0])))
    {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoError("Failed to get tag");
    }

    EVP_CIPHER_CTX_free(ctx);
    return result;
}

std::string aes_decrypt(const EncryptedData &data, const std::string &key)
{
    if (key.size() != 32)
        throw CryptoError("Invalid key size");
    if (data.iv.size() != 12)
        throw CryptoError("Invalid IV size");
    if (data.tag.size() != 16)
        throw CryptoError("Invalid tag size");

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        throw CryptoError("Failed to create context");

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                                reinterpret_cast<const unsigned char *>(key.data()),
                                reinterpret_cast<const unsigned char *>(data.iv.data())))
    {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoError("Decryption init failed");
    }

    std::string plaintext(data.ciphertext.size(), '\0');
    int len;

    if (1 != EVP_DecryptUpdate(ctx,
                               reinterpret_cast<unsigned char *>(&plaintext[0]),
                               &len,
                               reinterpret_cast<const unsigned char *>(data.ciphertext.data()),
                               data.ciphertext.size()))
    {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoError("Decryption update failed");
    }
    int plaintext_len = len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                                 const_cast<unsigned char *>(
                                     reinterpret_cast<const unsigned char *>(data.tag.data()))))
    {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoError("Failed to set tag");
    }

    if (1 != EVP_DecryptFinal_ex(ctx,
                                 reinterpret_cast<unsigned char *>(&plaintext[0]) + len,
                                 &len))
    {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoError("Authentication failed");
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext.substr(0, plaintext_len);
}

std::string generate_aes_key()
{
    return generate_random_bytes(32);
}

std::string generate_random_bytes(size_t length)
{
    std::string bytes(length, '\0');
    if (RAND_bytes(reinterpret_cast<unsigned char *>(&bytes[0]), length) != 1)
    {
        throw CryptoError("Failed to generate random bytes");
    }
    return bytes;
}

std::string prepare_secure_message(const std::string &message, const std::string &key)
{
    try
    {
        // Encrypt the message
        EncryptedData encrypted = aes_encrypt(message, key);

        // Combine IV, ciphertext, and tag
        std::string combined = encrypted.iv + encrypted.ciphertext + encrypted.tag;

        // Base64 encode the result
        return base64_encode(combined) + "\r\n\r\n";
    }
    catch (const CryptoError &e)
    {
        throw CryptoError("Failed to prepare secure message: " + std::string(e.what()));
    }
}

std::string process_secure_message(const std::string &encoded_message, const std::string &key)
{
    try
    {
        // Remove trailing \r\n if present
        std::string message = trim(encoded_message);
        std::string decoded = base64_decode(message);

        if (decoded.size() < 12 + 16) {
            throw CryptoError("Invalid message format (too short)");
        }

        // Validate message structure
        if (decoded.size() < 12 + 16)
        { // IV(12) + tag(16)
            throw CryptoError("Invalid message format");
        }

        // Extract components
        EncryptedData encrypted;
        encrypted.iv = decoded.substr(0, 12);
        encrypted.ciphertext = decoded.substr(12, decoded.size() - 12 - 16);
        encrypted.tag = decoded.substr(decoded.size() - 16);

        // Decrypt and return
        return aes_decrypt(encrypted, key);
    }
    catch (const CryptoError &e)
    {
        throw CryptoError("Failed to process secure message: " + std::string(e.what()));
    }
}