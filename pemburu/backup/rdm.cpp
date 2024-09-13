#include <iostream>
#include <random>
#include <bitset>

int main() {
    std::random_device rd; // Menggunakan random_device untuk seed
    std::mt19937_64 eng(rd()); // Mersenne Twister 64 bit
    std::uniform_int_distribution<uint64_t> distr;

    uint64_t random_value = distr(eng); // Menghasilkan nilai random 64 bit

    std::bitset<64> bits(random_value); // Mengonversi ke bitset untuk memudahkan akses per-bit

    std::cout << "64-bit Random: " << bits << std::endl;

    // Memecah ke dalam 8 buffer 8-bit
    for(int i = 0; i < 64; i += 8) {
        auto byte = (random_value >> i) & 0xFF; // Memindahkan dan masking 8 bit
        std::bitset<8> byte_bits(byte); // Konversi ke bitset untuk kemudahan
        std::cout << "8-bit chunk: " << byte_bits << std::endl;
    }

    return 0;
}
