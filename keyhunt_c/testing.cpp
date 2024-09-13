#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "gmp256k1/Point.h"
#include "gmp256k1/Int.h"
#include "gmp256k1/IntGroup.h"
#include "gmp256k1/Random.h"
#include "util.h"
#include "hashing.h"

class Secp256K1 {
private:
    Point G; // Generator point
    Int P; // Prime for the finite field
    Int order; // Order of the generator point
    Point GTable[256 * 32]; // Generator table for fast point multiplication

    // Helper functions for point operations
    Point Add2(Point &p1, Point &p2);
    Point Double(Point &p);
    Point AddDirect(Point &p1, Point &p2);
    
public:
    Secp256K1();
    ~Secp256K1();
    void Init();
    Point ComputePublicKey(Int *privKey);
    Point DoubleDirect(Point &p);
    void GetHash160_fromX(int type,unsigned char prefix,
	Int *k0,Int *k1,Int *k2,Int *k3,
	uint8_t *h0,uint8_t *h1,uint8_t *h2,uint8_t *h3);
};

Point Secp256K1::DoubleDirect(Point &p) {
	Int _s;
	Int _p;
	Int a;
	Point r;
	r.z.SetInt32(1);
	_s.ModMulK1(&p.x,&p.x);
	_p.ModAdd(&_s,&_s);
	_p.ModAdd(&_s);

	a.ModAdd(&p.y,&p.y);
	a.ModInv();
	_s.ModMulK1(&_p,&a);     // s = (3*pow2(p.x))*inverse(2*p.y);

	_p.ModMulK1(&_s,&_s);
	a.ModAdd(&p.x,&p.x);
	a.ModNeg();
	r.x.ModAdd(&a,&_p);    // rx = pow2(s) + neg(2*p.x);

	a.ModSub(&r.x,&p.x);

	_p.ModMulK1(&a,&_s);
	r.y.ModAdd(&_p,&p.y);
	r.y.ModNeg();           // ry = neg(p.y + s*(ret.x+neg(p.x)));
	return r;
}

Point Secp256K1::AddDirect(Point &p1, Point &p2) {
    Int dy;
    Int dx;
    Int _s;
    Int _p;
    Point r;
    r.z.SetInt32(1);

    dy.ModSub(&p2.y, &p1.y);
    dx.ModSub(&p2.x, &p1.x);
    dx.ModInv();
    _s.ModMulK1(&dy, &dx);  // s = (p2.y - p1.y) * inverse(p2.x - p1.x);

    _p.ModSquareK1(&_s);   // _p = pow2(s)

    r.x.ModSub(&_p, &p1.x);
    r.x.ModSub(&p2.x);      // rx = pow2(s) - p1.x - p2.x;

    r.y.ModSub(&p2.x, &r.x);
    r.y.ModMulK1(&_s);
    r.y.ModSub(&p2.y);      // ry = - p2.y - s*(ret.x-p2.x);

    return r;
}

Point Secp256K1::Add2(Point &p1, Point &p2) {
  // P2.z = 1
  Int u;
  Int v;
  Int u1;
  Int v1;
  Int vs2;
  Int vs3;
  Int us2;
  Int a;
  Int us2w;
  Int vs2v2;
  Int vs3u2;
  Int _2vs2v2;
  Point r;
  u1.ModMulK1(&p2.y, &p1.z);
  v1.ModMulK1(&p2.x, &p1.z);
  u.ModSub(&u1, &p1.y);
  v.ModSub(&v1, &p1.x);
  us2.ModSquareK1(&u);
  vs2.ModSquareK1(&v);
  vs3.ModMulK1(&vs2, &v);
  us2w.ModMulK1(&us2, &p1.z);
  vs2v2.ModMulK1(&vs2, &p1.x);
  _2vs2v2.ModAdd(&vs2v2, &vs2v2);
  a.ModSub(&us2w, &vs3);
  a.ModSub(&_2vs2v2);

  r.x.ModMulK1(&v, &a);

  vs3u2.ModMulK1(&vs3, &p1.y);
  r.y.ModSub(&vs2v2, &a);
  r.y.ModMulK1(&r.y, &u);
  r.y.ModSub(&vs3u2);

  r.z.ModMulK1(&vs3, &p1.z);
  return r;
}

Secp256K1::Secp256K1() {
}
Secp256K1::~Secp256K1() {
}

void Secp256K1::Init() {
	// Prime for the finite field
	P.SetBase16("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");

	// Set up field
	Int::SetupField(&P);

	// Generator point and order
	G.x.SetBase16("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
	G.y.SetBase16("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
	G.z.SetInt32(1);
	order.SetBase16("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");

	Int::InitK1(&order);
	// Compute Generator table
	Point N(G);
	for(int i = 0; i < 32; i++) {
		GTable[i * 256] = N;
		N = DoubleDirect(N);
		for (int j = 1; j < 255; j++) {
			GTable[i * 256 + j] = N;
			N = AddDirect(N, GTable[i * 256]);
		}
		GTable[i * 256 + 255] = N; // Dummy point for check function
	}
}

Point Secp256K1::ComputePublicKey(Int *privKey)	{
	//char *hextemp;
	uint8_t buffer[32];
	int i = 0;
	uint8_t b;
	Point Q;

	Q.Clear();
	privKey->Get32Bytes(buffer);
	for (i = 0; i < 32; i++) {
		b = buffer[i];
		
		if(b)
		  break;
	}

	if(i == 32)
		return Q;
	Q = GTable[256 * (31 - i) + (b-1)];
	i++;
	for(; i < 32; i++) {
		b = buffer[i];
		if(b)
			Q = Add2(Q, GTable[256 * (31 - i) + (b-1)]);
	}
	Q.Reduce();
	return Q;
}


int main() {
    Secp256K1 secp256k1;
    secp256k1.Init();

    // Contoh penggunaan
    Int privKey;
    Point publicKey;
    privKey.SetBase16("ffffffffffffffffffffffffffffffffffffffff");
    publicKey = secp256k1.ComputePublicKey(&privKey);
    printf("Public Key (x, y):\n");
    printf("x: %s\n", publicKey.x.GetBase16());
    printf("y: %s\n", publicKey.y.GetBase16());
    
    uint8_t hash160[20]; // Buffer untuk menyimpan hasil hash160
    int addressType = P2PKH; // Anda dapat memilih tipe alamat yang sesuai
    unsigned char prefix = 0x00; // Sesuaikan dengan prefix yang sesuai
    Int k0, k1, k2, k3; // Parameter tambahan jika diperlukan
    secp256k1.GetHash160_fromX(addressType, prefix, &k0, &k1, &k2, &k3, hash160);
    
    printf("Hash160 ripe MD dari kunci publik:\n");
    for (int i = 0; i < 20; ++i) {
    printf("%02x", hash160[i]);
    }
    printf("\n");
    
    unsigned char my_buffer[8]; // buffer dengan panjang 8 byte
    int num_bytes = 8; // jumlah byte yang ingin dihasilkan
    random_bytes(my_buffer, num_bytes);
    printf("Nilai acak dalam buffer: ");
    for (int i = 0; i < num_bytes; i++) {
        printf("%02x", my_buffer[i]);
    }
    printf("\n");

    return 0;
}


