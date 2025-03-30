#include "../include/dh_utils.h"
#include "../include/common.h" // For base64_* if you like
#include <openssl/bn.h>
#include <stdexcept>

DH *create_dh_params(unsigned int bits)
{
    // NID_ffdhe2048 is a standard finite-field group for 2048-bit DH.
    DH *dh = DH_new_by_nid(NID_ffdhe2048);
    if (!dh)
    {
        throw std::runtime_error("DH_new_by_nid(NID_ffdhe2048) failed");
    }
    return dh;

    return dh;
}

DHKeyPair generate_dh_keypair(DH *dh_params)
{
    if (!dh_params)
    {
        throw std::runtime_error("DH params not initialized");
    }

    // Create a new ephemeral DH object from the parameters
    DH *dh = DH_new();
    if (!dh)
        throw std::runtime_error("Failed to allocate DH for keypair");

    // Set p, g from shared dh_params
    // This copies the big integers p, g.
    if (!DH_set0_pqg(dh,
                     BN_dup(DH_get0_p(dh_params)),
                     nullptr,
                     BN_dup(DH_get0_g(dh_params))))
    {
        DH_free(dh);
        throw std::runtime_error("Failed to set p/g");
    }

    // Now generate a private/public key pair
    if (1 != DH_generate_key(dh))
    {
        DH_free(dh);
        throw std::runtime_error("DH_generate_key failed");
    }

    // Extract our public key
    const BIGNUM *pub_key_bn = nullptr;
    DH_get0_key(dh, &pub_key_bn, nullptr);

    // Convert public key BN -> binary -> base64
    int pub_len = BN_num_bytes(pub_key_bn);
    std::string pub_bytes(pub_len, '\0');
    BN_bn2bin(pub_key_bn, reinterpret_cast<unsigned char *>(&pub_bytes[0]));

    std::string pub_b64 = base64_encode(pub_bytes);

    DHKeyPair result;
    result.dh = dh;
    result.public_key = pub_b64;
    return result;
}

std::string compute_dh_shared_secret(DH *my_dh, const std::string &peer_pub_b64)
{
    if (!my_dh)
    {
        throw std::runtime_error("DH not initialized");
    }

    // Decode peer’s public from base64
    std::string peer_pub = base64_decode(peer_pub_b64);
    BIGNUM *peer_bn = BN_bin2bn(
        reinterpret_cast<const unsigned char *>(peer_pub.data()),
        peer_pub.size(), nullptr);
    if (!peer_bn)
    {
        throw std::runtime_error("Failed to convert peer_pub to BN");
    }

    // Compute shared secret
    int secret_size = DH_size(my_dh);
    std::string secret_buf(secret_size, '\0');

    int ret = DH_compute_key(
        reinterpret_cast<unsigned char *>(&secret_buf[0]),
        peer_bn, my_dh);
    BN_free(peer_bn);

    if (ret == -1)
    {
        throw std::runtime_error("DH_compute_key failed");
    }

    // 'ret' is actually the length of the secret in bytes
    secret_buf.resize(ret);

    // Typically you'd pass this through a KDF or hash, e.g. SHA256
    // For demo, we can do something simple:
    // e.g. take a SHA256 of the raw secret to get a 32-byte symmetric key
    // (assuming you want AES-256).
    // We'll do that with an OpenSSL EVP_Digest:

    unsigned char hash[32];
    unsigned int out_len = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, secret_buf.data(), secret_buf.size());
    EVP_DigestFinal_ex(ctx, hash, &out_len);
    EVP_MD_CTX_free(ctx);

    // Return 32-byte key
    return std::string(reinterpret_cast<char *>(hash), 32);
}
