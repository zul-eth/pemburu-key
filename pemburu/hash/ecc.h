#ifndef CURVE_OPERATIONS_H
#define CURVE_OPERATIONS_H

#include <string>
#include <utility>

extern const std::string Gx_str;
extern const std::string Gy_str;
extern mpz_t p;

void mpz_addmod(mpz_t result, const mpz_t op1, const mpz_t op2, const mpz_t mod);
void mpz_submod(mpz_t result, const mpz_t op1, const mpz_t op2, const mpz_t mod);
void mpz_mulmod(mpz_t result, const mpz_t op1, const mpz_t op2, const mpz_t mod);
std::pair<std::string, std::string> add_points(const std::string& x1, const std::string& y1, const std::string& x2, const std::string& y2);
std::pair<std::string, std::string> get_prefix(std::string priv_key);

#endif // CURVE_OPERATIONS_H
