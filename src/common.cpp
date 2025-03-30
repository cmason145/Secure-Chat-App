#include "../include/common.h"
#include <openssl/bio.h>
#include <openssl/evp.h>

std::unordered_map<std::string, std::string> parse_headers(const std::string &data)
{
    std::unordered_map<std::string, std::string> headers;
    std::vector<std::string> lines = split(data, '\n');

    for (const auto &line : lines)
    {
        std::string trimmed = trim(line);
        if (trimmed.empty())
            continue;

        size_t pos = trimmed.find(':');
        if (pos != std::string::npos)
        {
            std::string key = trim(trimmed.substr(0, pos));
            std::string value = trim(trimmed.substr(pos + 1));
            headers[key] = value;
        }
    }
    return headers;
}

std::vector<std::string> split(const std::string &s, char delimiter)
{
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(s);
    while (std::getline(tokenStream, token, delimiter))
    {
        if (!token.empty())
        { // Skip empty tokens
            tokens.push_back(trim(token));
        }
    }
    return tokens;
}

std::string trim(const std::string &str)
{
    size_t first = str.find_first_not_of(" \t\r\n");
    if (first == std::string::npos)
        return "";
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, (last - first + 1));
}

std::string base64_encode(const std::string &input)
{
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new(BIO_s_mem());
    BIO_push(b64, mem);

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, input.data(), input.size());
    BIO_flush(b64);

    char *output;
    long len = BIO_get_mem_data(mem, &output);
    std::string result(output, len);

    BIO_free_all(b64);
    return result;
}

std::string base64_decode(const std::string &input)
{
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new_mem_buf(input.data(), input.size());
    BIO_push(b64, mem);

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    std::string output(input.size(), '\0');
    int len = BIO_read(b64, &output[0], input.size());
    output.resize(len);

    BIO_free_all(b64);
    return output;
}
