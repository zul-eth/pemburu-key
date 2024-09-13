#include <iostream>
#include <gmp.h>
#include <gmpxx.h>
#include <string>
#include <ctime>

// g++ -o main main.cpp -lgmpxx -lgmp -lssl -lcrypto
using namespace std;

void init_random_seed() {
    srand(time(NULL));
}

mpz_class p("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);

mpz_class modular_inverse(mpz_class base, mpz_class exponent, mpz_class modulus) {
    mpz_class result = 1;
    base = base % modulus;
    while (exponent > 0) {
        if (exponent % 2 == 1) {
            result = (result * base) % modulus;
        }
        exponent = exponent / 2;
        base = (base * base) % modulus;
    }
    return result;
}

std::pair<mpz_class, mpz_class> add_points(mpz_class x1, mpz_class y1, mpz_class x2, mpz_class y2) {
    mpz_class lambda_val, x_result, y_result;
    if (x1 == x2 && y1 == y2) {
        mpz_class numerator = (x1 * x1 * 3) % p;
        mpz_class denominator = modular_inverse(2 * y1, p - 2, p);
        lambda_val = (numerator * denominator) % p;
    } else {
        mpz_class numerator = (y2 - y1) % p;
        mpz_class denominator = modular_inverse(x2 - x1, p - 2, p);
        lambda_val = (numerator * denominator) % p;
    }
    x_result = (lambda_val * lambda_val - x1 - x2) % p;
    y_result = (lambda_val * (x1 - x_result) - y1) % p;
    if (y_result < 0) {
        y_result += p;
    }

    return std::make_pair(x_result, y_result);
}

void poin_add(std::string priv) {
    mpz_class Gx("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
    mpz_class Gy("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);
    mpz_class x = Gx, y = Gy;
    for (char bit : priv) {
        std::tie(x, y) = add_points(x, y, x, y);
        if (bit == '1') {
            std::tie(x, y) = add_points(x, y, Gx, Gy);
        }
    }
    cout << "b: " << priv << endl;
    cout << "x: " << hex << x << endl;
    cout << "y: " << hex << y << endl;
}

void poin_matrix() {
    string initial_string = "1";
    string bin_;
    string rand_b(160, '0'); // inisialisasi string biner dengan panjang 160
    for (int i = 0; i < 160; ++i) {
        rand_b[i] = '0' + rand() % 2; // isi string biner secara acak
    }

    mpz_class Gx("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
    mpz_class Gy("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);
    mpz_class x = Gx, y = Gy;

    for (int i = 1; i < 96; ++i) {
        if (i == 34 || i == 39 || i == 44 || i == 49 || i == 54 || i == 59 || i == 64 || i == 69 || i == 74 || i == 79 || i == 84 || i == 89) {
            continue;
        }
        bin_ = initial_string + rand_b.substr(i, 160 - i);
        poin_add(bin_);
    }
}

int main() {
    init_random_seed();
    for (int i = 0; i < 1; ++i) {
        poin_matrix();
    }
    return 0;
}
