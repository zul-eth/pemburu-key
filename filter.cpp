#include <iostream>
#include <string>
#include <random>
#include <unordered_map>

// Fungsi untuk menghasilkan string hexa acak dengan panjang 8 karakter (32 bit)
std::string generateHex() {
    const std::string hexChars = "0123456789ABCDEF";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);

    std::string hexString;
    for (int i = 0; i < 8; ++i) {
        hexString += hexChars[dis(gen)];
    }
    return hexString;
}

// Fungsi untuk memeriksa apakah string hexa memiliki lebih dari 2 duplikat dari setiap karakter hexa
bool hasExcessiveDuplicates(const std::string& hexString) {
    std::unordered_map<char, int> charCount;
    for (char c : hexString) {
        charCount[c]++;
        if (charCount[c] > 2) {
            return true;
        }
    }
    return false;
}

int main(int argc, char* argv[]) {
    std::string start = "00000000";
    std::string end = "FFFFFFFF";

    std::cout << "Hasil: " << std::endl;
    for (int i = 0; i < 10; ++i) { // Ganti 10 dengan jumlah yang diinginkan
        std::string hexValue = generateHex();
        if (hexValue >= start && hexValue <= end && !hasExcessiveDuplicates(hexValue)) {
            std::cout << "3" << hexValue << "00000000" << std::endl;
            
        }
    }

    return 0;
}
