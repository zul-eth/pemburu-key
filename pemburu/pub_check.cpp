#include <pthread.h>
#include <iostream>
#include <gmp.h>
#include <ctime>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string>
#include <vector>
#include <sstream>
#include "hash/sha256.h"
#include "hash/ripemd160.h"

using namespace std;

gmp_randstate_t state;

struct ThreadArgs {
    int threadId;
    int numThreads;
};

void initRandomizer() {
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));
}

bool checkPubKeyInFile(const string& pubkeyhex) {
    int fd = open("all.rmd", O_RDONLY);
    if (fd == -1) {
        cerr << "Error: Gagal membuka file pub.txt" << endl;
        return false;
    }

    struct stat fileInfo;
    if (fstat(fd, &fileInfo) == -1) {
        cerr << "Error: Gagal mendapatkan informasi file" << endl;
        close(fd);
        return false;
    }

    char* fileData = (char*)mmap(NULL, fileInfo.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (fileData == MAP_FAILED) {
        cerr << "Error: Gagal memetakan file ke memori" << endl;
        return false;
    }

    char* ptr = fileData;
    char* end = fileData + fileInfo.st_size;
    while (ptr < end) {
        if (strncmp(ptr, pubkeyhex.c_str(), pubkeyhex.length()) == 0) {
            if (munmap(fileData, fileInfo.st_size) == -1) {
                cerr << "Error: Gagal membebaskan memori" << endl;
            }
            return true;
        }
        ptr = (char*)memchr(ptr, '\n', end - ptr);
        if (!ptr) break;
        ptr++;
    }

    if (munmap(fileData, fileInfo.st_size) == -1) {
        cerr << "Error: Gagal membebaskan memori" << endl;
    }

    return false;
}

void savePrivKeyToFile(const string& privkeyhex) {
    int fd = open("HIT_PUBKEY.txt", O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        cerr << "Error: Gagal membuka file HIT_PUBKEY.txt" << endl;
        return;
    }

    if (write(fd, privkeyhex.c_str(), privkeyhex.length()) == -1) {
        cerr << "Error: Gagal menulis ke file HIT_PUBKEY.txt" << endl;
    }

    close(fd);
}

void processKeys(const string& pubkeyhex, const string& privkeyhex) {
    if (checkPubKeyInFile(pubkeyhex)) {
        savePrivKeyToFile(privkeyhex + "\n");
        cout << " HIT_PUB.txt." << endl;
    }
}

string getRandomHex() {
    static bool initialized = false;
    mpz_t randomNumber;

    if (!initialized) {
        gmp_randinit_default(state);
        gmp_randseed_ui(state, time(NULL));
        initialized = true;
    }

    mpz_init(randomNumber);
    mpz_urandomb(randomNumber, state, 256);
    char* hex_cstr = mpz_get_str(NULL, 16, randomNumber);
    string hex_str = hex_cstr;
    free(hex_cstr);
    if (hex_str.length() % 2 != 0) {
        hex_str = "0" + hex_str; 
    }
    string pub_key = (mpz_tstbit(randomNumber, 0) == 0) ? "02" + hex_str : "03" + hex_str;

    mpz_clear(randomNumber);
    return pub_key;
}

void hexStringToBytes(const string& hexString, unsigned char* output) {
    size_t len = hexString.length();
    if (len % 2 != 0) {
        throw std::invalid_argument("harus genap");
    }
    for (size_t i = 0; i < len; i += 2) {
        std::istringstream byteStream(hexString.substr(i, 2));
        unsigned int byteValue;
        byteStream >> std::hex >> byteValue;
        output[i / 2] = static_cast<unsigned char>(byteValue);
    }
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

void* threadFunction(void* arg) {
    ThreadArgs* threadArgs = reinterpret_cast<ThreadArgs*>(arg);
    int threadId = threadArgs->threadId;
    int numThreads = threadArgs->numThreads;

    for (int i = threadId; i < 1000000; i += numThreads) {
        string pubkeyhex = getRandomHex();
        
        string sha256 = get_sha_hash(pubkeyhex);
        string rmd160 = get_rmd_hash(sha256);

        //cout << "pubkeyhex: " << pubkeyhex << endl;
        //cout << "sha256: " << sha256 << endl;
        //cout << "rmd160: " << rmd160 << endl;
        
        processKeys(rmd160, pubkeyhex);
    }

    pthread_exit(NULL);
}

int main() {
    initRandomizer();

    const int numThreads = 8;
    pthread_t threads[numThreads];
    ThreadArgs args[numThreads];

    for (int i = 0; i < numThreads; ++i) {
        args[i].threadId = i;
        args[i].numThreads = numThreads;
        pthread_create(&threads[i], NULL, threadFunction, &args[i]);
    }

    for (int i = 0; i < numThreads; ++i) {
        pthread_join(threads[i], NULL);
    }

    return 0;
}

