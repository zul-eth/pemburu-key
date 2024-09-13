#include <iostream>
#include <gmp.h>
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

int main() {
    
    mpz_t Gx, Gy, x, y, prime, result_x, result_y;
    mpz_inits(Gx, Gy, x, y, prime, result_x, result_y, NULL);

    // Initialize Gx, Gy, x, y, and prime

    mpz_set_str(Gx, Gx_str, 16);
    mpz_set_str(Gy, Gy_str, 16);
    mpz_set_str(prime, p_str, 16);
    //mpz_set_str(x, argv[1], 16);
    //mpz_set_str(y, argv[2], 16);
    // 200jt
    //mpz_set_str(x, "7638a19a3dac8980e6440bb8af41b1f9b0848eb043988fdfcf1b4fb4083854e7", 16);
    //mpz_set_str(y, "c6bb2f066b06b84091abae2ace6b5aeea0bde16f629a146564aca2c20a20f615", 16);
    /* puzzle 130 pub-u */
    mpz_set_str(x, "633cbe3ec02b9401c5effa144c5b4d22f87940259634858fc7e59b1c09937852", 16);
    mpz_set_str(y, "b078a17cc1558a9a4fa0b406f194c9a2b71d9a61424b533ceefe27408b3191e3", 16);
    
    ofstream outputFile("/data/data/com.termux/files/home/key/key_k/pub/5d.txt");
    
    string p2pkh_uncompressed;
    // 256 50000000
    for (int i = 0; i < 1048579; ++i) {
        add_points(x, y, Gx, Gy, prime, result_x, result_y);
        p2pkh_uncompressed = "04" + mpzToHex(result_x) + mpzToHex(result_y);
        string p2pkh_c = (mpz_tstbit(result_y, 0) == 0) ? "02" : "03";
        p2pkh_c += p2pkh_uncompressed.substr(2, 64);
        outputFile << p2pkh_c << endl;
        
        // Update x and y for next iteration
        mpz_set(x, result_x);
        mpz_set(y, result_y);
    }
    //string pub_x = p2pkh_uncompressed.substr(2, 64);
    //string pub_y = p2pkh_uncompressed.substr(66, 64);
    
    //cout << "Nilai akhir x: " << pub_x << endl;
    //cout << "Nilai akhir y: " << pub_y << endl;
    
    //outputFile.close();
    // Clear memory
    mpz_clears(Gx, Gy, x, y, prime, result_x, result_y, NULL);

    return 0;
}
