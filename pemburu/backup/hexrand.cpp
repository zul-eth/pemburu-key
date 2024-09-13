#include <iostream>
#include <iomanip>
#include <random>

int main() {
    // Menggunakan std::random_device untuk seed acak yang lebih andal
    std::random_device rd;
    std::mt19937 gen(rd());
    
    // Menggunakan distribusi uniform untuk menghasilkan angka acak
    std::uniform_int_distribution<long long> dis;
    
    // Menghasilkan angka acak
    long long randomNum = dis(gen);
    
    // Menampilkan angka acak dalam desimal dan hexadesimal
    std::cout << "Angka acak dalam desimal: " << randomNum << std::endl;
    std::cout << "Angka acak dalam hexadesimal: " << std::hex << randomNum << std::endl;
    
    return 0;
}
