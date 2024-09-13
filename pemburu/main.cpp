#include <iostream>
#include <gmp.h>
#include <string>
#include <ctime>
#include <vector>
#include "hash/sha256.h"
#include "hash/ripemd160.h"
#include <cstdlib>
#include <random>
#include <bitset>
#include <pthread.h>
#include <atomic>

using namespace std;

struct ThreadArgs {
    int start_index;
    int end_index;
};

atomic<int> num_checked(0);

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

    string x_str = mpz_get_str(NULL, 16, x_result);
    string y_str = mpz_get_str(NULL, 16, y_result);

    pair<string, string> result = make_pair(string(x_str), string(y_str));

    mpz_clears(lambda_val, x_result, y_result, X1, Y1, X2, Y2, NULL);
   
    return result;
}

void hexStringToBytes(const std::string& hexString, unsigned char* output) {
    size_t len = hexString.length();
    if (len % 2 != 0) {
        throw std::invalid_argument("Panjang string hexadecimal harus genap");
    }

    mpz_t byteValue;
    mpz_init(byteValue);

    for (size_t i = 0; i < len; i += 2) {
        const char byteStr[3] = {hexString[i], hexString[i + 1], '\0'};
        mpz_set_str(byteValue, byteStr, 16);
        output[i / 2] = static_cast<unsigned char>(mpz_get_ui(byteValue));
    }

    mpz_clear(byteValue);
}

string compress_public_key(const string& x, const string& y) {
    mpz_t y_mpz;
    mpz_init_set_str(y_mpz, y.c_str(), 16);
    string prefix = (mpz_odd_p(y_mpz) ? "03" : "02");
    mpz_clear(y_mpz);
    return prefix + x;
}

void get_hash(const string& hex_data, unsigned char** data, size_t* data_length) {
    string padded_hex_data = hex_data;
    if (hex_data.length() % 2 != 0) {
        padded_hex_data = "0" + hex_data;
    }
    *data_length = padded_hex_data.length() / 2;
    *data = new unsigned char[*data_length];
    hexStringToBytes(padded_hex_data, *data);
}


void* thread_proses(void* arg) {
    ThreadArgs* args = (ThreadArgs*) arg;
    mpz_t Gx, Gy, add_x, add_y;
    mpz_inits(Gx, Gy, add_x, add_y, NULL);
    mpz_set_str(Gx, Gx_str.c_str(), 16);
    mpz_set_str(Gy, Gy_str.c_str(), 16);
    mpz_set(add_x, Gx);
    mpz_set(add_y, Gy);
    
    unsigned char* data = nullptr;
    size_t data_length = 0;
        
    random_device rd;
    mt19937_64 eng(rd());
    uniform_int_distribution<uint64_t> distr(0, numeric_limits<uint64_t>::max());
    
    int start_index = args->start_index;
    int end_index = args->end_index;
    
    for(int i = start_index; i < end_index; i++) {
        
        uint64_t random_value = distr(eng);
        bitset<64> bits(random_value);
        string bits_string = bits.to_string();
        string priv_key = "1" + bits_string;
        
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
        string compressed_key = compress_public_key(x, y);
        
        
        get_hash(compressed_key, &data, &data_length);
        // Melakukan hashing SHA-256
        uint8_t sha256_digest[32];
        sha256(data, data_length, sha256_digest);
        string sha256_hash = sha256_hex(sha256_digest);
        
        
        get_hash(sha256_hash, &data, &data_length);
        unsigned char rmd160_digest[20];
        ripemd160(data, data_length, rmd160_digest);
        string rmd160_hash = ripemd160_hex(rmd160_digest);
        
        
        
        delete[] data;
        num_checked++;
        
        string rmd160_search = "20d45a6a762535700ce9e0b216e31994335db8a5";
        if (rmd160_hash == rmd160_search) {
            FILE *output_file = fopen("Hit_privatekey.txt", "a");
            if (output_file != NULL) {
              fprintf(output_file, "%s\n", priv_key.c_str());
              fclose(output_file);
              break;
            } else {
              fprintf(stderr, "Failed to open output file!\n");
            }
          }
        //printf(" * priv_key: %s\n * rmd160_hash: %s\n Keys\n", priv_key.c_str(), rmd160_hash.c_str());
        //printf(" * priv_key: %s\n", priv_key.c_str());
        //fflush(stdout);
        
    }
    pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        cout << "Usage: ./nama_program <n_length>" << endl;
        return 1;
    }
    int n_length = atoi(argv[1]);
    
    mpz_init_set_str(p, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
    
    const int num_threads = 1024; // Jumlah thread
    pthread_t threads[num_threads];
    ThreadArgs thread_args[num_threads];
    
    
    // Membuat dan menjalankan thread
    int chunk_size = n_length / num_threads;
    for (int i = 0; i < num_threads; ++i) {
        thread_args[i].start_index = i * chunk_size;
        thread_args[i].end_index = (i + 1) * chunk_size;
        if (i == num_threads - 1) {
            thread_args[i].end_index = n_length; // pastikan iterasi terakhir menangani sisa
        }
        pthread_create(&threads[i], NULL, thread_proses, (void*)&thread_args[i]);
    }
    
    // Gabungkan thread
    for (int i = 0; i < num_threads; ++i) {
        pthread_join(threads[i], NULL);
    } 
    mpz_clear(p);
    
    printf("Jumlah rmd160_hash yang telah diperiksa: %d\n", num_checked.load()); 
    //fflush(stdout);
    
    

    return 0;
}
