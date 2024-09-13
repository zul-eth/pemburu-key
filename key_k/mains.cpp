#include <pthread.h>
#include <iostream>
#include <gmp.h>
#include <ctime>
#include "gmp256k1/GMP256K1.h"
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string>
#include <vector>

using namespace std;

gmp_randstate_t state;

struct ThreadArgs {
    Secp256K1* secp256k1;
    int threadId;
    int numThreads;
};

void initRandomizer() {
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));
}

// Fungsi untuk memeriksa nilai pubkeyhex dalam file pub.txt
bool checkPubKeyInFile(const string& pubkeyhex) {
    int fd = open("pub/17m.txt", O_RDONLY);
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

    // Lakukan pencarian langsung pada fileData menggunakan pointer
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
        if (!ptr) break; // Jika tidak ada newline lagi, hentikan pencarian
        ptr++; // Lewati karakter newline
    }

    if (munmap(fileData, fileInfo.st_size) == -1) {
        cerr << "Error: Gagal membebaskan memori" << endl;
    }

    return false;
}

// Fungsi untuk menyimpan privkeyhex dalam file HIT_PRIVKEY.txt
void savePrivKeyToFile(const string& privkeyhex) {
    int fd = open("HIT_PRIVKEY.txt", O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        cerr << "Error: Gagal membuka file HIT_PRIVKEY.txt" << endl;
        return;
    }

    if (write(fd, privkeyhex.c_str(), privkeyhex.length()) == -1) {
        cerr << "Error: Gagal menulis ke file HIT_PRIVKEY.txt" << endl;
    }

    close(fd);
}

void processKeys(const string& pubkeyhex, const string& privkeyhex) {
    if (checkPubKeyInFile(pubkeyhex)) {
        savePrivKeyToFile(privkeyhex + "\n"); // Tambahkan newline untuk setiap privkey
        cout << " HIT_PRIVKEY.txt." << endl;
    }
}

void getRandomHex(mpz_t randomNumber, int iteration) {
    static mpz_t currentRandomNumber;
    static bool initialized = false;
    if (!initialized) {
        mpz_init_set_str(currentRandomNumber, "311ffffffffffffffffffffffffffffff", 16);
        initialized = true;
    } else {
        mpz_t increment;
        mpz_init_set_str(increment, "36C831A180DC77F348B5C71C71C7", 16); // Nilai 999999 dalam heksadesimal
        mpz_add(currentRandomNumber, currentRandomNumber, increment);
        mpz_clear(increment);
    }
    mpz_set(randomNumber, currentRandomNumber);
}


void* threadFunction(void* arg) {
    ThreadArgs* threadArgs = reinterpret_cast<ThreadArgs*>(arg);
    Secp256K1* secp256k1 = threadArgs->secp256k1;
    int threadId = threadArgs->threadId;
    int numThreads = threadArgs->numThreads;

    for (int i = threadId; i < 10000; i += numThreads) {
        Int privateKey;
        getRandomHex(privateKey.num, i);

        Point publicKey = secp256k1->ComputePublicKey(&privateKey);

        char* privkeyhex = (char*)malloc(33 * sizeof(char));
        gmp_sprintf(privkeyhex, "%ZX", privateKey.num);

        string pubkeyhex = secp256k1->GetPublicKeyHex(true, publicKey); 

        cout << privkeyhex << endl;
        //cout << pubkeyhex << endl;
        processKeys(pubkeyhex, privkeyhex);

        free(privkeyhex);
    }

    pthread_exit(NULL);
}

int main() {
    initRandomizer();
    Secp256K1* secp256k1 = new Secp256K1();
    secp256k1->Init();

    const int numThreads = 64;
    pthread_t threads[numThreads];
    ThreadArgs args[numThreads];

    for (int i = 0; i < numThreads; ++i) {
        args[i] = {secp256k1, i, numThreads};
        pthread_create(&threads[i], NULL, threadFunction, &args[i]);
    }

    for (int i = 0; i < numThreads; ++i) {
        pthread_join(threads[i], NULL);
    }

    delete secp256k1;

    return 0;
}
