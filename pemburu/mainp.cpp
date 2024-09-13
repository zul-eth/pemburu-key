#include <iostream>
#include <gmp.h>
#include <gmpxx.h>
#include <string>
#include <ctime>
#include <vector>
#include <sstream>
#include <fstream>
#include <random>
#include <pthread.h>
#include <atomic>

using namespace std;

struct ThreadArgs {
    int n_length;
};

atomic<int> num_checked(0);

vector<string> binary = {"000000000","000000001","000000010","000000011","000000100","000000101","000000110","000000111","000001000","000001001","000001010","000001011","000001100","000001101","000001110","000001111","000010000","000010001","000010010","000010011","000010100","000010101","000010110","000010111","000011000","000011001","000011010","000011011","000011100","000011101","000011110","000011111","000100000","000100001","000100010","000100011","000100100","000100101","000100110","000100111","000101000","000101001","000101010","000101011","000101100","000101101","000101110","000101111","000110000","000110001","000110010","000110011","000110100","000110101","000110110","000110111","000111000","000111001","000111010","000111011","000111100","000111101","000111110","000111111","001000000","001000001","001000010","001000011","001000100","001000101","001000110","001000111","001001000","001001001","001001010","001001011","001001100","001001101","001001110","001001111","001010000","001010001","001010010","001010011","001010100","001010101","001010110","001010111","001011000","001011001","001011010","001011011","001011100","001011101","001011110","001011111","001100000","001100001","001100010","001100011","001100100","001100101","001100110","001100111","001101000","001101001","001101010","001101011","001101100","001101101","001101110","001101111","001110000","001110001","001110010","001110011","001110100","001110101","001110110","001110111","001111000","001111001","001111010","001111011","001111100","001111101","001111110","001111111","010000000","010000001","010000010","010000011","010000100","010000101","010000110","010000111","010001000","010001001","010001010","010001011","010001100","010001101","010001110","010001111","010010000","010010001","010010010","010010011","010010100","010010101","010010110","010010111","010011000","010011001","010011010","010011011","010011100","010011101","010011110","010011111","010100000","010100001","010100010","010100011","010100100","010100101","010100110","010100111","010101000","010101001","010101010","010101011","010101100","010101101","010101110","010101111","010110000","010110001","010110010","010110011","010110100","010110101","010110110","010110111","010111000","010111001","010111010","010111011","010111100","010111101","010111110","010111111","011000000","011000001","011000010","011000011","011000100","011000101","011000110","011000111","011001000","011001001","011001010","011001011","011001100","011001101","011001110","011001111","011010000","011010001","011010010","011010011","011010100","011010101","011010110","011010111","011011000","011011001","011011010","011011011","011011100","011011101","011011110","011011111","011100000","011100001","011100010","011100011","011100100","011100101","011100110","011100111","011101000","011101001","011101010","011101011","011101100","011101101","011101110","011101111","011110000","011110001","011110010","011110011","011110100","011110101","011110110","011110111","011111000","011111001","011111010","011111011","011111100","011111101","011111110","011111111","100000000","100000001","100000010","100000011","100000100","100000101","100000110","100000111","100001000","100001001","100001010","100001011","100001100","100001101","100001110","100001111","100010000","100010001","100010010","100010011","100010100","100010101","100010110","100010111","100011000","100011001","100011010","100011011","100011100","100011101","100011110","100011111","100100000","100100001","100100010","100100011","100100100","100100101","100100110","100100111","100101000","100101001","100101010","100101011","100101100","100101101","100101110","100101111","100110000","100110001","100110010","100110011","100110100","100110101","100110110","100110111","100111000","100111001","100111010","100111011","100111100","100111101","100111110","100111111","101000000","101000001","101000010","101000011","101000100","101000101","101000110","101000111","101001000","101001001","101001010","101001011","101001100","101001101","101001110","101001111","101010000","101010001","101010010","101010011","101010100","101010101","101010110","101010111","101011000","101011001","101011010","101011011","101011100","101011101","101011110","101011111","101100000","101100001","101100010","101100011","101100100","101100101","101100110","101100111","101101000","101101001","101101010","101101011","101101100","101101101","101101110","101101111","101110000","101110001","101110010","101110011","101110100","101110101","101110110","101110111","101111000","101111001","101111010","101111011","101111100","101111101","101111110","101111111","110000000","110000001","110000010","110000011","110000100","110000101","110000110","110000111","110001000","110001001","110001010","110001011","110001100","110001101","110001110","110001111","110010000","110010001","110010010","110010011","110010100","110010101","110010110","110010111","110011000","110011001","110011010","110011011","110011100","110011101","110011110","110011111","110100000","110100001","110100010","110100011","110100100","110100101","110100110","110100111","110101000","110101001","110101010","110101011","110101100","110101101","110101110","110101111","110110000","110110001","110110010","110110011","110110100","110110101","110110110","110110111","110111000","110111001","110111010","110111011","110111100","110111101","110111110","110111111","111000000","111000001","111000010","111000011","111000100","111000101","111000110","111000111","111001000","111001001","111001010","111001011","111001100","111001101","111001110","111001111","111010000","111010001","111010010","111010011","111010100","111010101","111010110","111010111","111011000","111011001","111011010","111011011","111011100","111011101","111011110","111011111","111100000","111100001","111100010","111100011","111100100","111100101","111100110","111100111","111101000","111101001","111101010","111101011","111101100","111101101","111101110","111101111","111110000","111110001","111110010","111110011","111110100","111110101","111110110","111110111","111111000","111111001","111111010","111111011","111111100","111111101","111111110","111111111"
};


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

void check_and_save_private_key(const string& ripemd160_hash, const string& private_key) {
    ifstream file("pub130.txt");
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

void* process_data(void* arg) {
  
    mpz_class Gx(Gx_str, 16);
    mpz_class Gy(Gy_str, 16);
    
    ThreadArgs* args = (ThreadArgs*) arg;
    int n_length = args->n_length;
    
    random_device rd;
    mt19937 gen(rd());
    
    uniform_int_distribution<> dis(0, binary.size() - 1);
    
    string binr;
    for (int j = 0; j < n_length; ++j) {
      binr += binary[dis(gen)];
    }
    for (int i = 0; i < 8; ++i) {
        string private_key;
        switch (i) {
          case 0:
            private_key = "000" + binr;
            break;
          case 1:
            private_key = "001" + binr;
            break;
          case 2:
            private_key = "010" + binr;
            break;
          case 3:
            private_key = "011" + binr;
            break;
          case 4:
            private_key = "100" + binr;
            break;
          case 5:
            private_key = "101" + binr;
            break;
          case 6:
            private_key = "110" + binr;
            break;
          case 7:
            private_key = "111" + binr;
            break;
          default:
            // Handle case when i is out of range
            break;
        }

        
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
      
        check_and_save_private_key(p2pkh_c,private_key);
        num_checked++;
        
        
        //printf(" * priv_key: %s\n", private_key.c_str());
        //printf(" * p2pkh_c: %s\n", p2pkh_c.c_str());
        //cout << private_key.length() << endl;
        //fflush(stdout);
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
