#include <iostream>
#include <gmp.h>
#include "hash/sha256.h"
#include "hash/ripemd160.h"
#include <string>
#include <sstream>
#include <fstream>

using namespace std;

const char *Gx_str = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
const char *Gy_str = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
const char *p_str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";

void add_points(mpz_t x1, mpz_t y1, const mpz_t x2, const mpz_t y2, const mpz_t prime, mpz_t result_x, mpz_t result_y) {
    mpz_t lambda_val, x_result, y_result, x_diff, y_diff;
    mpz_inits(lambda_val, x_result, y_result, x_diff, y_diff, NULL);

    // Calculate numerator: (y2 - y1)
    mpz_sub(y_diff, y2, y1);

    // Calculate denominator: (x2 - x1)
    mpz_sub(x_diff, x2, x1);

    // Calculate modular inverse of denominator
    mpz_invert(lambda_val, x_diff, prime);

    // Calculate lambda: (numerator * inv)
    mpz_mul(lambda_val, y_diff, lambda_val);
    mpz_mod(lambda_val, lambda_val, prime);

    // Calculate x_result: (lambda_val^2 - x1 - x2)
    mpz_mul(x_result, lambda_val, lambda_val);
    mpz_sub(x_result, x_result, x1);
    mpz_sub(x_result, x_result, x2);
    mpz_mod(x_result, x_result, prime);

    // Calculate y_result: (lambda_val * (x1 - x_result) - y1)
    mpz_sub(y_result, x1, x_result);
    mpz_mul(y_result, lambda_val, y_result);
    mpz_sub(y_result, y_result, y1);
    mpz_mod(y_result, y_result, prime);

    mpz_set(result_x, x_result);
    mpz_set(result_y, y_result);

    mpz_clears(lambda_val, x_result, y_result, x_diff, y_diff, NULL);
}

void hexStringToBytes(const string& hexString, unsigned char* output) {
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

std::string mpzToHex(const mpz_t num) {
    char* hexChars = mpz_get_str(nullptr, 16, num); // Konversi ke string heksadesimal
    std::string hexString(hexChars);
    const size_t hexLength = hexString.length();
    const size_t targetLength = 64;
    if (hexLength < targetLength) {
        hexString = std::string(targetLength - hexLength, '0') + hexString; // Tambahkan nol di depan jika panjangnya kurang dari 64
    }
    free(hexChars); // Bebaskan memori yang dialokasikan oleh mpz_get_str
    return hexString;
}

string get_sha_hash(const string& hex_data) {
    size_t data_length = hex_data.length() / 2;
    unsigned char* data = new unsigned char[data_length]; 
    hexStringToBytes(hex_data, data);
    uint8_t digest[32];
    sha256(data, data_length, digest);
    delete[] data;
    return sha256_hex(digest);
}

string get_rmd_hash(const string& hex_data) {
    size_t data_length = hex_data.length() / 2;
    unsigned char* data = new unsigned char[data_length]; 
    hexStringToBytes(hex_data, data);
    unsigned char digest[20];
    ripemd160((unsigned char*)data, data_length, digest);
    delete[] data; 
    return ripemd160_hex(digest);
}

void check_and_save_private_key(const string& ripemd160_hash, const string& private_key) {
    ifstream file("66.rmd");
    string line;
    bool found = false;
    while (getline(file, line)) {
        if (line.find(ripemd160_hash) != string::npos) {
            found = true;
                break;
        }
    }
    file.close();

    if (found) {
        ofstream output_file("Hit_privatekey.txt", ios::app);
        output_file << private_key << endl;
        output_file.close();
    }
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        cout << "Usage: ./nama_program <n_x> <n_y>" << endl;
        return 1;
    }
    
    mpz_t Gx, Gy, x, y, prime, result_x, result_y;
    mpz_inits(Gx, Gy, x, y, prime, result_x, result_y, NULL);

    // Initialize Gx, Gy, x, y, and prime

    mpz_set_str(Gx, Gx_str, 16);
    mpz_set_str(Gy, Gy_str, 16);
    mpz_set_str(prime, p_str, 16);
    mpz_set_str(x, argv[1], 16);
    mpz_set_str(y, argv[2], 16);
    
    
    for (int i = 0; i < 50000000; ++i) {
        add_points(x, y, Gx, Gy, prime, result_x, result_y);
        string p2pkh_uncompressed = "04" + mpzToHex(result_x) + mpzToHex(result_y);
        string p2pkh_c = (mpz_tstbit(result_y, 0) == 0) ? "02" : "03";
        p2pkh_c += p2pkh_uncompressed.substr(2, 64);
      
        string sha256_hash = get_sha_hash(p2pkh_c);
        string rmd160_hash = get_rmd_hash(sha256_hash);
        check_and_save_private_key(rmd160_hash,p2pkh_uncompressed);
        //cout << rmd160_hash << endl;
        // Update x and y for next iteration
        mpz_set(x, result_x);
        mpz_set(y, result_y);
    }

    // Clear memory
    mpz_clears(Gx, Gy, x, y, prime, result_x, result_y, NULL);

    return 0;
}
