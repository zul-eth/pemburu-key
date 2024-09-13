
/*
IMPLEMENTASI ALGORITMA UNTUK BITCOIN SHA-256 by Zulfi
*/

#include <iostream>
#include <string>
#include "sha256.h"
#include <sstream>


// Fungsi untuk mengonversi string hexadecimal ke array byte
void hexStringToBytes(const std::string& hexString, unsigned char* output) {
    size_t len = hexString.length();
    if (len % 2 != 0) {
        throw std::invalid_argument("Panjang string hexadecimal harus genap");
    }
    for (size_t i = 0; i < len; i += 2) {
        std::istringstream byteStream(hexString.substr(i, 2));
        unsigned int byteValue;
        byteStream >> std::hex >> byteValue;
        output[i / 2] = static_cast<unsigned char>(byteValue);
    }
}


int main() {
     // g++ -o main_sha main_sha.cpp sha256.cpp
     
    // String hexadecimal yang ingin di-hash
    std::string hexString = "025a5b29f4fa85d36e42010e739bb0eba778ef50def78584059ae4f5f0849a53eb";

    // Konversi string hexadecimal ke array byte
    size_t data_length = hexString.length() / 2;
    unsigned char data[data_length];
    hexStringToBytes(hexString, data);

    // Transformasi untuk satu chunk data (hash SHA-256)
    uint8_t digest[32];
    sha256(data, data_length, digest);
    
    // Menampilkan hasil hash cara 1
    std::string hex_digest = sha256_hex(digest);
    std::cout << "Hash SHA-256: " <<  hex_digest << std::endl;
    
    /*
    // Menampilkan hasil hash cara 2
    std::cout << "Hash SHA-256 dari string hexadecimal: ";
    for (int i = 0; i < 32; ++i) {
        std::cout << std::hex << (int)digest[i];
    }
    std::cout << std::endl;
    */
    
    return 0;
}
