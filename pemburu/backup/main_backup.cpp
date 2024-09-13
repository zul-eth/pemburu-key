#include <iostream>
#include <gmp.h>
#include <gmpxx.h>
#include <string>
#include <ctime>
#include <vector>
#include <sstream>
#include <iomanip>
#include <fstream>
#include "sha256.h"
#include "ripemd160.h"
#include <cstdlib>
#include <thread> // untuk std::this_thread::sleep_for

using namespace std;

void check_and_save_private_key(const string& ripemd160_hash, const string& private_key);

const string Gx_str = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
const string Gy_str = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
mpz_class p("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);

void init_random_seed() {
    srand(time(NULL));
}

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

string mpzToHex(const mpz_class& num) {
    stringstream ss;
    ss << hex << setw(64) << setfill('0') << num;
    return ss.str();
}

pair<mpz_class, mpz_class> add_points(mpz_class x1, mpz_class y1, mpz_class x2, mpz_class y2) {
    mpz_class lambda_val, x_result, y_result;
    if (x1 == x2 && y1 == y2) {
        mpz_class numerator = (x1 * x1 * 3) % p;
        mpz_class denominator = (2 * y1) % p;
        mpz_class inv;
        mpz_invert(inv.get_mpz_t(), denominator.get_mpz_t(), p.get_mpz_t());
        lambda_val = (numerator * inv) % p;
    } else {
        mpz_class numerator = (y2 - y1) % p;
        mpz_class denominator = (x2 - x1) % p;
        mpz_class inv;
        mpz_invert(inv.get_mpz_t(), denominator.get_mpz_t(), p.get_mpz_t());
        lambda_val = (numerator * inv) % p;
    }
    x_result = (lambda_val * lambda_val - x1 - x2) % p;
    y_result = (lambda_val * (x1 - x_result) - y1) % p;
    if (y_result < 0) {
        y_result += p;
    }

    return make_pair(x_result, y_result);
}

string calculate_sha256_hash(const string& hex_data) {
    size_t data_length = hex_data.length() / 2;
    unsigned char data[data_length];
    hexStringToBytes(hex_data, data);

    // Transformasi untuk satu chunk data (hash SHA-256)
    uint8_t digest[32];
    sha256(data, data_length, digest);
    
    return sha256_hex(digest);
    
}

string calculate_ripemd160_hash(const string& hex_data) {
    size_t data_length = hex_data.length() / 2;
    unsigned char data[data_length];
    hexStringToBytes(hex_data, data);
    // Memanggil fungsi ripemd160
    unsigned char digest[20];
    ripemd160((unsigned char*)data, data_length, digest);

    return ripemd160_hex(digest);
}

string get_public_key(mpz_class x, mpz_class y) {
    string P2PKH_UNCOMPRESSED = "04" + mpzToHex(x) + mpzToHex(y);
    string P2PKH_COMPRESSED;
    if (y % 2 == 0) {
        P2PKH_COMPRESSED = "02";
    } else {
        P2PKH_COMPRESSED = "03";
    }
    P2PKH_COMPRESSED += P2PKH_UNCOMPRESSED.substr(2, 64);
    return P2PKH_COMPRESSED;
}
/*
void poin_matrix() {
    
    string initial_string = "1";
    string lengh_priv(159, '0');
    for (int i = 0; i < 159; ++i) {
        lengh_priv[i] = '0' + rand() % 2;
    }
    mpz_class Gx(Gx_str, 16);
    mpz_class Gy(Gy_str, 16);
    mpz_class add_x = Gx, add_y = Gy;
    
    for (int i = 1; i < 96; ++i) {
        if (i == 34 || i == 39 || i == 44 || i == 49 || i == 54 || i == 59 || i == 64 || i == 69 || i == 74 || i == 79 || i == 84 || i == 89) {
            continue;
        }
        string binary_priv = initial_string + lengh_priv.substr(i, 159 - i);
        mpz_class x = add_x, y = add_y;
        //int hash_checked = 0;
        for (char bit : binary_priv) {
            tie(x, y) = add_points(x, y, x, y);
            if (bit == '1') {
                tie(x, y) = add_points(x, y, add_x, add_y);
            }
            hash_checked++;
        }
        //cout << "BINARY: " << binary_priv << endl;
        //cout << "X: " << hex << x << endl;
       // cout << "Y: " << hex << y << endl;
        string P2PKH_COMPRESSED = get_public_key(x, y);
        string sha256_hash = calculate_sha256_hash(P2PKH_COMPRESSED);
        
        string ripemd160_hash = calculate_ripemd160_hash(sha256_hash);
        check_and_save_private_key(ripemd160_hash, binary_priv);
        
        //cout << "SHA-256 hash: " << sha256_hash << endl;
        //cout << "\r" << "RIPEMD_160 Hash: " << ripemd160_hash << "Total: " << hash_checked << flush;
       // this_thread::sleep_for(chrono::seconds(1));
        //cout << "\r" << "RIPEMD_160: " << "new_hash_value" << flush;
    }
}
*/

void generate_and_print_binary(int length) {
    const int MAX_LENGTH = 160;
    const int CACHE_LINE_SIZE = 64;
    
    // Inisialisasi bilangan biner dengan panjang maksimum
    char binary_string[MAX_LENGTH + 1];
    memset(binary_string, '0', MAX_LENGTH);
    binary_string[0] = '1';
    binary_string[length] = '\0';
    for (int i = 1; i < length; ++i) {
        binary_string[i] = '0' + rand() % 2;
    }
    mpz_class Gx(Gx_str, 16);
    mpz_class Gy(Gy_str, 16);
    mpz_class add_x = Gx, add_y = Gy;
    string priv_bin;
    
    for (int i = 0; i < 96; ++i) {
        priv_bin = binary_string + i;
        mpz_class x = add_x, y = add_y;
        for (char bit : priv_bin) {
          tie(x, y) = add_points(x, y, x, y);
          if (bit == '1') {
            tie(x, y) = add_points(x, y, add_x, add_y);
          }
        }
        //cout << "B: " << priv_bin << endl;
        
        string P2PKH_COMPRESSED = get_public_key(x, y);
        
        string sha256_hash = calculate_sha256_hash(P2PKH_COMPRESSED);
        
        string ripemd160_hash = calculate_ripemd160_hash(sha256_hash);
        
        cout << "RIPEMD_160 Hash: " << ripemd160_hash << endl;
        
        check_and_save_private_key(ripemd160_hash, priv_bin);
    }
}

void check_and_save_private_key(const string& ripemd160_hash, const string& private_key) {
    ifstream file("160.rmd");
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

int main() {
    init_random_seed();
    for (int i = 0; i < 1000; ++i) {
        generate_and_print_binary(160);
    }
    return 0;
}