legacy:
	g++ -march=native -mtune=native -Wall -Wextra -Ofast -ftree-vectorize -flto -c oldbloom/bloom.cpp -o oldbloom.o
	g++ -march=native -mtune=native -Wall -Wextra -Ofast -ftree-vectorize -flto -c bloom/bloom.cpp -o bloom.o
	gcc -march=native -mtune=native -Wno-unused-result -Ofast -ftree-vectorize -c base58/base58.c -o base58.o
	gcc -march=native -mtune=native -Wall -Wextra -Ofast -ftree-vectorize -c xxhash/xxhash.c -o xxhash.o
	g++ -march=native -mtune=native -Wall -Wextra -Ofast -ftree-vectorize -c util.c -o util.o
	g++ -march=native -mtune=native -Wall -Wextra -Ofast -ftree-vectorize -c sha3/sha3.c -o sha3.o
	g++ -march=native -mtune=native -Wall -Wextra -Ofast -ftree-vectorize -c sha3/keccak.c -o keccak.o
	g++ -march=native -mtune=native -Wall -Wextra -Ofast -ftree-vectorize -c hashing.c -o hashing.o
	g++ -march=native -mtune=native -Wall -Wextra -Ofast -ftree-vectorize -c gmp256k1/Int.cpp -o Int.o
	g++ -march=native -mtune=native -Wall -Wextra -Ofast -ftree-vectorize -c gmp256k1/Point.cpp -o Point.o
	g++ -march=native -mtune=native -Wall -Wextra -Ofast -ftree-vectorize -c gmp256k1/IntMod.cpp -o IntMod.o
	g++ -march=native -mtune=native -Wall -Wextra -Ofast -ftree-vectorize -flto -c gmp256k1/Random.cpp -o Random.o
	g++ -march=native -mtune=native -Wall -Wextra -Ofast -ftree-vectorize -flto -c gmp256k1/IntGroup.cpp -o IntGroup.o
	g++ -march=native -mtune=native -Wall -Wextra -Ofast -ftree-vectorize -o testing testing.cpp base58.o bloom.o oldbloom.o xxhash.o util.o Int.o  Point.o  IntMod.o  IntGroup.o Random.o hashing.o sha3.o keccak.o -lm -lpthread -lcrypto -lgmp	
	rm -r *.o