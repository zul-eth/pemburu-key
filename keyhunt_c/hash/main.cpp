#include "ripemd160.h"
#include <iostream>
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
    // Contoh input data
    std::string hexString = "10eff5e997f4a2fe2e43e879aa9576776266e1ccbc217b4489e037396c7d2ff0";
    
    size_t data_length = hexString.length() / 2;
    unsigned char data[data_length];
    hexStringToBytes(hexString, data);
    // Memanggil fungsi ripemd160
    unsigned char digest[20];
    ripemd160((unsigned char*)data, data_length, digest);
    
    // Menampilkan hasil hash dalam bentuk hexadesimal
    std::cout << "RIPEMD-160 Hash: " << ripemd160_hex(digest) << std::endl;
    
    return 0;
}
