#ifndef SECP256K1H
#define SECP256K1H

#include "Point.h"
#include <vector>

class Secp256K1 {

public:

  Secp256K1();
  ~Secp256K1();
  void  Init();
  Point ComputePublicKey(Int *privKey);
  Point Add(Point &p1, Point &p2);
  Point Add2(Point &p1, Point &p2);

	char* GetPublicKeyHex(bool compressed, Point &p);
	
	Point DoubleDirect(Point &p);
	Point AddDirect(Point &p1, Point &p2);
	Point G;                 // Generator
	Int P;                   // Prime for the finite field
	Int   order;             // Curve order

private:
	Point GTable[256*32];       // Generator table

};

#endif // SECP256K1H
