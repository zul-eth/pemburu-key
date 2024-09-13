#include <iostream>
#include <vector>
#include <iomanip>
#include <cmath>
#include <gmpxx.h>

using namespace std;

// Struktur untuk menyimpan titik pada kurva eliptik
struct Point {
  mpz_class x, y;
};

// Tabel penjumlahan
vector<vector<Point>> table_addition(256, vector<Point>(256));

// Tabel penggandaan
vector<Point> table_doubling(256);

// Tabel untuk menyimpan titik-titik pada kurva
vector<Point> table;

// Fungsi untuk menghitung perkalian skalar dengan pre-computation
Point scalar_multiplication_precomputed(const Point& P, mpz_class k) {
  Point Q = {0, 0};
  for (int i = 0; i < 64; i++) {
    if (k.tstbit(i)) {
      Q = table_addition[Q.x.get_ui()][table_doubling[P.x.get_ui()].x.get_ui()];
    } else {
      Q = table_addition[Q.x.get_ui()][table[P.x.get_ui()].x.get_ui()];
    }
  }
  return Q;
}

// Fungsi untuk menghitung penjumlahan dua titik
Point point_addition(const Point& P, const Point& Q) {
  // Menghitung lambda
  mpz_class lambda;
  if (P.x == Q.x) {
    // Kasus khusus untuk penjumlahan titik dengan x yang sama
    if (P.y == Q.y) {
      // Penjumlahan dua titik yang sama (penggandaan)
      lambda = ((3 * P.x * P.x) + 7) / (2 * P.y);
    } else {
      // Titik-titik tersebut berlawanan
      return {0, 0};
    }
  } else {
    lambda = (Q.y - P.y) / (Q.x - P.x);
  }

  // Menghitung x dan y untuk titik baru
  mpz_class x_new = lambda * lambda - P.x - Q.x;
  mpz_class y_new = lambda * (P.x - x_new) - P.y;

  return {x_new, y_new};
}

// Fungsi untuk menghitung penggandaan titik
Point double_point(const Point& P) {
  // Menghitung lambda
  mpz_class lambda;
  if (P.y == 0) {
    // Kasus khusus untuk titik di infinity
    return {0, 0};
  } else {
    lambda = ((3 * P.x * P.x) + 7) / (2 * P.y);
  }

  // Menghitung x dan y untuk titik baru
  mpz_class x_new = lambda * lambda - 2 * P.x;
  mpz_class y_new = lambda * (P.x - x_new) - P.y;

  return {x_new, y_new};
}

// Fungsi untuk melakukan pre-computation
void precompute() {
  // Menghitung semua titik pada kurva y^2 = x^3 + 7
  for (unsigned long x = 0; x < 256; x++) {
    mpz_class y_squared = (x * x * x) + 7;
    mpz_class y;
    mpz_sqrt(y.get_mpz_t(), y_squared.get_mpz_t());
    table.push_back({x, y});
  }

  // Menghitung tabel penjumlahan
  for (int i = 0; i < 256; i++) {
    for (int j = 0; j < 256; j++) {
      table_addition[i][j] = point_addition(table[i], table[j]);
    }
  }

  // Menghitung tabel penggandaan
  for (int i = 0; i < 256; i++) {
    table_doubling[i] = double_point(table[i]);
  }
}

// Fungsi untuk mengonversi titik pada kurva eliptik ke format DER
vector<unsigned char> point_to_der(const Point& P) {
  vector<unsigned char> bytes;
  // Menambahkan byte untuk menandakan koordinat y positif
  if (P.y < 0) {
    bytes.push_back(0x81);
  } else {
    mpz_class y_abs = abs(P.y);
    bytes.push_back(y_abs.get_str().size());
  }
  bytes.insert(bytes.end(), P.y.get_str().begin(), P.y.get_str().end());

  return bytes;
}

int main() {
  // Parameter kurva eliptik Bitcoin
  mpz_class a = 0, b = 7;

  // Titik awal (generator)
  Point G = {mpz_class("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16),
             mpz_class("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)};

  // Melakukan pre-computation
  precompute();

  // Menghitung public key
  mpz_class d("12345"); // misalnya
  Point Q = scalar_multiplication_precomputed(G, d);

  // Mengubah public key ke format DER
  vector<unsigned char> public_key_der = point_to_der(Q);

  // Menampilkan hasil
  cout << "Public Key (DER): ";
  for (unsigned char byte : public_key_der) {
    cout << hex << setw(2) << setfill('0') << (int)byte;
  }
  cout << endl;

  return 0;
}
