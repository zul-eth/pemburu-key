#include <iostream>
#include <gmp.h>
#include <gmpxx.h>
#include <string>
#include <ctime>
#include <vector>
#include <sstream>
#include <fstream>
#include "sha256.h"
#include "ripemd160.h"
#include <cstdlib>
#include <random>

using namespace std;

vector<string> binary = {"10","100","1000","10000","100000","110","1100","11000","110000","1100000","1110","11100","111000","1110000","11100000","111110","1111100","11111000","111110000","1111100000","1111110","11111100","111111000","1111110000","11111100000"};

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
    string p2pkh_uncompressed = "04" + mpzToHex(x) + mpzToHex(y);
    string p2pkh_compressed;
    if (y % 2 == 0) {
        p2pkh_compressed = "02";
    } else {
        p2pkh_compressed = "03";
    }
    p2pkh_compressed += p2pkh_uncompressed.substr(2, 64);
    return p2pkh_compressed;
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

void check_pk(const string& binr) {
    mpz_class Gx(Gx_str, 16);
    mpz_class Gy(Gy_str, 16);
    mpz_class add_x = Gx, add_y = Gy;
    if (binr.length() % 5 == 0 || binr.length() % 5 == 1 || binr.length() % 5 == 2 || binr.length() % 5 == 3 || binr.length() % 5 == 4) {
        if (binr.length() >= 65 && binr.length() <= 74) {
          
            mpz_class x = add_x, y = add_y;
            for (char bit : binr) {
              tie(x, y) = add_points(x, y, x, y);
              if (bit == '1') {
                tie(x, y) = add_points(x, y, add_x, add_y);
              }
            }
            //cout << "Binary: " << binr << endl;
            string p2pkh_compressed = get_public_key(x, y);
            string sha256_hash = calculate_sha256_hash(p2pkh_compressed);
            string ripemd160_hash = calculate_ripemd160_hash(sha256_hash);
            cout << "RIPEMD_160 Hash: " << ripemd160_hash << endl;
            check_and_save_private_key(ripemd160_hash, binr);
        }
    }
}

int main() {
    init_random_seed();
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, binary.size() - 1);

    for (int i = 0; i < 10000000; ++i) {
        std::string binr;
        for (int j = 0; j < 18; ++j) {
            binr += binary[dis(gen)];
        }
        check_pk(binr);
    }
    return 0;
}