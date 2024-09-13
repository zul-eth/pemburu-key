default:
	g++ -march=native -mtune=native -Wall -Wextra -Ofast -ftree-vectorize -flto -c hash/sha256.cpp -o sha256.o -I.
	g++ -march=native -mtune=native -Wall -Wextra -Ofast -ftree-vectorize -flto -c hash/ripemd160.cpp -o ripemd160.o -I.
	g++ -march=native -mtune=native -Wall -Wextra -Ofast -ftree-vectorize -o pemburu8B main2.cpp ripemd160.o sha256.o -lm -lpthread -lgmp -lgmpxx
	rm -r *.o
legacy:
	g++ -march=native -mtune=native -Wall -Wextra -Ofast -ftree-vectorize -flto -c hash/sha256.cpp -o sha256.o -I.
	g++ -march=native -mtune=native -Wall -Wextra -Ofast -ftree-vectorize -flto -c hash/ripemd160.cpp -o ripemd160.o -I.
	g++ -march=native -mtune=native -Wall -Wextra -Ofast -ftree-vectorize -o pemburu main.cpp ripemd160.o sha256.o -lm -lpthread -lgmp   
	rm -r *.o
puz66:
	g++ -march=native -mtune=native -Wall -Wextra -Ofast -ftree-vectorize -flto -c hash/sha256.cpp -o sha256.o -I.
	g++ -march=native -mtune=native -Wall -Wextra -Ofast -ftree-vectorize -flto -c hash/ripemd160.cpp -o ripemd160.o -I.
	g++ -march=native -mtune=native -Wall -Wextra -Ofast -ftree-vectorize -o pemburu66 main3.cpp ripemd160.o sha256.o -lm -lpthread -lgmp -lgmpxx
	rm -r *.o
	
oneop:
	g++ -march=native -mtune=native -Wall -Wextra -Ofast -ftree-vectorize -flto -c hash/sha256.cpp -o sha256.o -I.
	g++ -march=native -mtune=native -Wall -Wextra -Ofast -ftree-vectorize -flto -c hash/ripemd160.cpp -o ripemd160.o -I.
	g++ -march=native -mtune=native -Wall -Wextra -Ofast -ftree-vectorize -o pemburu1op main4.cpp ripemd160.o sha256.o -lm -lpthread -lgmp
	rm -r *.o
	
pubs:
	g++ -march=native -mtune=native -Wall -Wextra -Ofast -ftree-vectorize -o pemburus mainp.cpp -lm -lpthread -lgmp -lgmpxx

pubc:
	g++ -march=native -mtune=native -Wall -Wextra -Ofast -ftree-vectorize -flto -c hash/sha256.cpp -o sha256.o -I.
	g++ -march=native -mtune=native -Wall -Wextra -Ofast -ftree-vectorize -flto -c hash/ripemd160.cpp -o ripemd160.o -I.
	g++ -march=native -mtune=native -Wall -Wextra -Ofast -ftree-vectorize -o pub_check pub_check.cpp ripemd160.o sha256.o -lm -lpthread -lgmp
	rm -r *.o