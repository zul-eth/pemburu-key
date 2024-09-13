#include <iostream>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <string>
#include <vector>

std::string calculate_sha256_hash(const std::string& hex_data) {
    std::string data;
    for (size_t i = 0; i < hex_data.size(); i += 2) {
        std::string byte = hex_data.substr(i, 2);
        char chr = (char)std::strtol(byte.c_str(), nullptr, 16);
        data.push_back(chr);
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, data.c_str(), data.length());
    SHA256_Final(hash, &sha256_ctx);

    char hex_hash[SHA256_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        sprintf(hex_hash + i * 2, "%02x", hash[i]);
    }
    hex_hash[SHA256_DIGEST_LENGTH * 2] = '\0';
    
    return std::string(hex_hash);
}

std::string calculate_ripemd160_hash(const std::string& hex_data) {
    std::string data;
    for (size_t i = 0; i < hex_data.size(); i += 2) {
        std::string byte = hex_data.substr(i, 2);
        char chr = (char)std::strtol(byte.c_str(), nullptr, 16);
        data.push_back(chr);
    }

    unsigned char sha256_hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, data.c_str(), data.length());
    SHA256_Final(sha256_hash, &sha256_ctx);

    std::vector<unsigned char> sha256_vector(sha256_hash, sha256_hash + SHA256_DIGEST_LENGTH);

    unsigned char hash[RIPEMD160_DIGEST_LENGTH];
    RIPEMD160_CTX ripemd160_ctx;
    RIPEMD160_Init(&ripemd160_ctx);
    RIPEMD160_Update(&ripemd160_ctx, sha256_vector.data(), sha256_vector.size());
    RIPEMD160_Final(hash, &ripemd160_ctx);

    char hex_hash[RIPEMD160_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < RIPEMD160_DIGEST_LENGTH; ++i) {
        sprintf(hex_hash + i * 2, "%02x", hash[i]);
    }
    hex_hash[RIPEMD160_DIGEST_LENGTH * 2] = '\0';

    return std::string(hex_hash);
}

int main() {
    std::string hex_data = "48656c6c6f2c20776f726c6421"; // Contoh data heksadesimal "Hello, world!"

    std::string sha256_hash = calculate_sha256_hash(hex_data);
    std::cout << "SHA-256 hash: " << sha256_hash << std::endl;

    std::string ripemd160_hash = calculate_ripemd160_hash(hex_data);
    std::cout << "RIPEMD-160 hash: " << ripemd160_hash << std::endl;

    return 0;
}
