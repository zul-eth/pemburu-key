#include <iostream>
#include <gmp.h>
#include <gmpxx.h>
#include <string>
#include <ctime>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <vector>
#include <sstream>
#include <iomanip>
#include <fstream>

using namespace std;

clock_t start_time;
int hash_count = 0;

void check_and_save_private_key(const string& ripemd160_hash, const string& private_key);

const string Gx_str = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
const string Gy_str = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
mpz_class p("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);

void init_random_seed() {
    srand(time(NULL));
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
    vector<unsigned char> data;
    data.reserve(hex_data.size() / 2);
    for (size_t i = 0; i < hex_data.size(); i += 2) {
        string byte = hex_data.substr(i, 2);
        data.push_back(static_cast<unsigned char>(stoi(byte, nullptr, 16)));
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(data.data(), data.size(), hash);

    stringstream ss;
    ss << hex << setfill('0');
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << setw(2) << static_cast<int>(hash[i]);
    }

    return ss.str();
}

string calculate_ripemd160_hash(const string& hex_data) {
    vector<unsigned char> data;
    data.reserve(hex_data.size() / 2);
    for (size_t i = 0; i < hex_data.size(); i += 2) {
        string byte = hex_data.substr(i, 2);
        data.push_back(static_cast<unsigned char>(stoi(byte, nullptr, 16)));
    }

    unsigned char sha256_hash[SHA256_DIGEST_LENGTH];
    SHA256(data.data(), data.size(), sha256_hash);

    unsigned char hash[RIPEMD160_DIGEST_LENGTH];
    RIPEMD160(sha256_hash, SHA256_DIGEST_LENGTH, hash);

    stringstream ss;
    ss << hex << setfill('0');
    for (int i = 0; i < RIPEMD160_DIGEST_LENGTH; ++i) {
        ss << setw(2) << static_cast<int>(hash[i]);
    }

    return ss.str();
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

void poin_matrix() {
    string initial_string = "1";
    string lengh_priv(160, '0');
    for (int i = 0; i < 160; ++i) {
        lengh_priv[i] = '0' + rand() % 2;
    }
    mpz_class Gx(Gx_str, 16);
    mpz_class Gy(Gy_str, 16);
    mpz_class add_x = Gx, add_y = Gy;
    for (int i = 1; i < 95; ++i) {
        if (i % 5 == 4) {
            continue;
        } 
        string binary_priv = initial_string + lengh_priv.substr(i, 160 - i);
        mpz_class x = add_x, y = add_y;
        for (char bit : binary_priv) {
            tie(x, y) = add_points(x, y, x, y);
            if (bit == '1') {
                tie(x, y) = add_points(x, y, add_x, add_y);
            }
        }
        //cout << "BINARY: " << binary_priv << endl;
        //cout << "X: " << hex << x << endl;
       // cout << "Y: " << hex << y << endl;
        string P2PKH_COMPRESSED = get_public_key(x, y);
        string sha256_hash = calculate_sha256_hash(P2PKH_COMPRESSED);
        string ripemd160_hash = calculate_ripemd160_hash(P2PKH_COMPRESSED);
        check_and_save_private_key(ripemd160_hash, binary_priv);
        //cout << "SHA-256 hash: " << sha256_hash << endl;
        cout << "RIPEMD-160 hash: " << ripemd160_hash << endl;
        hash_count++;
    }
}

void check_and_save_private_key(const string& ripemd160_hash, const string& private_key) {
    ifstream file("all_puz.rmd");
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
    start_time = clock();
    for (int i = 0; i < 1000000; ++i) {
        poin_matrix();
    }
    clock_t end_time = clock(); // menyimpan waktu selesai eksekusi
    double execution_time = double(end_time - start_time) / CLOCKS_PER_SEC;
    cout << "Execution time: " << execution_time << " seconds" << endl;
    cout << "Total hashes checked: " << hash_count << endl;

    return 0;
}
