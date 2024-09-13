#include "ecc.h"

const string Gx_str = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
const string Gy_str = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
mpz_t p;

void mpz_addmod(mpz_t result, const mpz_t op1, const mpz_t op2, const mpz_t mod) {
    mpz_add(result, op1, op2);
    mpz_mod(result, result, mod);
}

void mpz_submod(mpz_t result, const mpz_t op1, const mpz_t op2, const mpz_t mod) {
    mpz_sub(result, op1, op2);
    mpz_mod(result, result, mod);
}

void mpz_mulmod(mpz_t result, const mpz_t op1, const mpz_t op2, const mpz_t mod) {
    mpz_mul(result, op1, op2);
    mpz_mod(result, result, mod);
}

pair<string, string> add_points(const string& x1, const string& y1, const string& x2, const string& y2) {
    mpz_t lambda_val, x_result, y_result;
    mpz_inits(lambda_val, x_result, y_result, NULL);
    mpz_t X1, Y1, X2, Y2;
    mpz_init_set_str(X1, x1.c_str(), 16);
    mpz_init_set_str(Y1, y1.c_str(), 16);
    mpz_init_set_str(X2, x2.c_str(), 16);
    mpz_init_set_str(Y2, y2.c_str(), 16);
    
    if (mpz_cmp(X1, X2) == 0 && mpz_cmp(Y1, Y2) == 0) {
        mpz_t temp1, temp2;
        mpz_inits(temp1, temp2, NULL);

        mpz_mulmod(temp1, X1, X1, p);
        mpz_mul_ui(temp1, temp1, 3);
        mpz_mod(temp1, temp1, p);

        mpz_mul_ui(temp2, Y1, 2);
        mpz_mod(temp2, temp2, p);

        mpz_invert(lambda_val, temp2, p);

        mpz_mul(lambda_val, temp1, lambda_val);
        mpz_mod(lambda_val, lambda_val, p);
        
        mpz_clears(temp1, temp2, NULL);
    } else {
        mpz_t temp1, temp2;
        mpz_inits(temp1, temp2, NULL);

        mpz_submod(temp1, Y2, Y1, p);
        mpz_submod(temp2, X2, X1, p);

        mpz_invert(lambda_val, temp2, p);

        mpz_mul(lambda_val, temp1, lambda_val);
        mpz_mod(lambda_val, lambda_val, p);

        mpz_clears(temp1, temp2, NULL);
    }

    mpz_mul(x_result, lambda_val, lambda_val);
    mpz_sub(x_result, x_result, X1);
    mpz_sub(x_result, x_result, X2);
    mpz_mod(x_result, x_result, p);

    mpz_sub(y_result, X1, x_result);
    mpz_mul(y_result, lambda_val, y_result);
    mpz_sub(y_result, y_result, Y1);
    mpz_mod(y_result, y_result, p);

    if (mpz_sgn(y_result) < 0) {
        mpz_add(y_result, y_result, p);
    }

    char* x_str = mpz_get_str(NULL, 16, x_result);
    char* y_str = mpz_get_str(NULL, 16, y_result);

    pair<string, string> result = make_pair(string(x_str), string(y_str));

    mpz_clears(lambda_val, x_result, y_result, X1, Y1, X2, Y2, NULL);
    free(x_str);
    free(y_str);

    return result;
}

void generate_and_print_binary(const string& priv_key) {
    mpz_t Gx, Gy, add_x, add_y;
    mpz_inits(Gx, Gy, add_x, add_y, NULL);
    mpz_set_str(Gx, Gx_str.c_str(), 16);
    mpz_set_str(Gy, Gy_str.c_str(), 16);
    mpz_set(add_x, Gx);
    mpz_set(add_y, Gy);

    string x = mpz_get_str(NULL, 16, add_x);
    string y = mpz_get_str(NULL, 16, add_y);
    for (char bit : priv_key) {
        pair<string, string> result = add_points(x, y, x, y);
        x = result.first;
        y = result.second;
        if (bit == '1') {
            result = add_points(x, y, Gx_str, Gy_str);
            x = result.first;
            y = result.second;
        }
    }
    
    mpz_t X;
    mpz_init_set_str(X, x.c_str(), 16);
    
    string prefix = "02";
    if (mpz_odd_p(X)) {
        prefix = "03";
    }
    
    size_t byte_count = (mpz_sizeinbase(p, 2) + 7) / 8; // Number of bytes needed
    unsigned char *x_bytes = new unsigned char[byte_count];
    mpz_export(x_bytes, NULL, 1, 1, 1, 0, X);
    
    cout << prefix;
    for (size_t i = 0; i < byte_count; ++i) {
        printf("%02X", x_bytes[i]);
    }
    cout << endl;

    delete[] x_bytes;
    mpz_clears(Gx, Gy, add_x, add_y, X, NULL);
}

