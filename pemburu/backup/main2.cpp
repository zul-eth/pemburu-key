#include <iostream>
#include <gmp.h>
#include <gmpxx.h>
#include <string>
#include <ctime>
#include <vector>
#include <sstream>
#include <fstream>
#include "hash/sha256.h"
#include "hash/ripemd160.h"
#include <cstdlib>
#include <random>
#include <pthread.h>
#include <atomic>

using namespace std;

struct ThreadArgs {
    int n_length;
};

atomic<int> num_checked(0);

/*
vector<string> binary = {"0101000001110","00101100010011","0101000001","0110110","010011010","0001100111"
};
*/
vector<string> binary = {"00000000","00000001","00000010","00000011","00000100","00000101","00000110","00000111","00001000","00001001","00001010","00001011","00001100","00001101","00001110","00001111","00010000","00010001","00010010","00010011","00010100","00010101","00010110","00010111","00011000","00011001","00011010","00011011","00011100","00011101","00011110","00011111","00100000","00100001","00100010","00100011","00100100","00100101","00100110","00100111","00101000","00101001","00101010","00101011","00101100","00101101","00101110","00101111","00110000","00110001","00110010","00110011","00110100","00110101","00110110","00110111","00111000","00111001","00111010","00111011","00111100","00111101","00111110","00111111","01000000","01000001","01000010","01000011","01000100","01000101","01000110","01000111","01001000","01001001","01001010","01001011","01001100","01001101","01001110","01001111","01010000","01010001","01010010","01010011","01010100","01010101","01010110","01010111","01011000","01011001","01011010","01011011","01011100","01011101","01011110","01011111","01100000","01100001","01100010","01100011","01100100","01100101","01100110","01100111","01101000","01101001","01101010","01101011","01101100","01101101","01101110","01101111","01110000","01110001","01110010","01110011","01110100","01110101","01110110","01110111","01111000","01111001","01111010","01111011","01111100","01111101","01111110","01111111","10000000","10000001","10000010","10000011","10000100","10000101","10000110","10000111","10001000","10001001","10001010","10001011","10001100","10001101","10001110","10001111","10010000","10010001","10010010","10010011","10010100","10010101","10010110","10010111","10011000","10011001","10011010","10011011","10011100","10011101","10011110","10011111","10100000","10100001","10100010","10100011","10100100","10100101","10100110","10100111","10101000","10101001","10101010","10101011","10101100","10101101","10101110","10101111","10110000","10110001","10110010","10110011","10110100","10110101","10110110","10110111","10111000","10111001","10111010","10111011","10111100","10111101","10111110","10111111","11000000","11000001","11000010","11000011","11000100","11000101","11000110","11000111","11001000","11001001","11001010","11001011","11001100","11001101","11001110","11001111","11010000","11010001","11010010","11010011","11010100","11010101","11010110","11010111","11011000","11011001","11011010","11011011","11011100","11011101","11011110","11011111","11100000","11100001","11100010","11100011","11100100","11100101","11100110","11100111","11101000","11101001","11101010","11101011","11101100","11101101","11101110","11101111","11110000","11110001","11110010","11110011","11110100","11110101","11110110","11110111","11111000","11111001","11111010","11111011","11111100","11111101","11111110","11111111"
};

const string Gx_str = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
const string Gy_str = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
mpz_class p("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);

void init_random_seed() {
    srand(time(NULL));
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

void* process_data(void* arg) {
  
    mpz_class Gx(Gx_str, 16);
    mpz_class Gy(Gy_str, 16);
    
    ThreadArgs* args = (ThreadArgs*) arg;
    int n_length = args->n_length;
    
    random_device rd;
    mt19937 gen(rd());
    
    string sha256_hash;
    string rmd160_hash;
    //52e763a7ddc1aa4fa811578c491c1bc7fd570137
    string rmd160_search = "20d45a6a762535700ce9e0b216e31994335db8a5";
    
    uniform_int_distribution<> dis(0, binary.size() - 1);
    for(int i = 0; i < 10000; i++){
      
      string binr;
      for (int j = 0; j < n_length; ++j) {
        binr += binary[dis(gen)];
      }
      
      for (int i = 0; i < 2; ++i) {
          string private_key = (i == 0) ? "1" + binr : "0" + binr;
          
          mpz_class add_x = Gx, add_y = Gy;
          mpz_class x = add_x, y = add_y;
          
          for (char bit : private_key) {
            tie(x, y) = add_points(x, y, x, y);
            if (bit == '1') {
              tie(x, y) = add_points(x, y, add_x, add_y);
            }
          }
          
          string p2pkh_uncompressed = "04" + mpzToHex(x) + mpzToHex(y);
          string p2pkh_c = (y % 2 == 0) ? "02" : "03";
          p2pkh_c += p2pkh_uncompressed.substr(2, 64);
          
          sha256_hash = get_sha_hash(p2pkh_c);
          rmd160_hash = get_rmd_hash(sha256_hash);
          
          num_checked++;
          
          if (rmd160_hash == rmd160_search) {
            FILE *output_file = fopen("Hit_privatekey.txt", "a");
            if (output_file != NULL) {
              fprintf(output_file, "%s\n", private_key.c_str());
              fclose(output_file);
            } else {
              cerr << "Failed to open output file!" << endl;
            }
          }
          //printf(" * priv_key: %s\n * rmd160_hash: %s\n Keys\n", private_key.c_str(), rmd160_hash.c_str());
          //fflush(stdout);
          }
    }
    pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        cout << "Usage: ./nama_program <n_length> <n_threads>" << endl;
        return 1;
    }
    int n_length = atoi(argv[1]);
    int n_threads = atoi(argv[2]);
    
    const int num_threads = n_threads; // Jumlah thread
    pthread_t threads[num_threads];
    ThreadArgs thread_args[num_threads];
    
    
    // Membuat dan menjalankan thread
    for (int i = 0; i < num_threads; ++i) {
        thread_args[i].n_length = n_length;
        pthread_create(&threads[i], NULL, process_data, (void*)&thread_args[i]);
    }
    
    // Gabungkan thread
    for (int i = 0; i < num_threads; ++i) {
        pthread_join(threads[i], NULL);
    } 
    
    printf("Jumlah rmd160_hash yang telah diperiksa: %d\n", num_checked.load()); 
    fflush(stdout);
   
    return 0;
}
