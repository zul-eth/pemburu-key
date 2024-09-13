#include <iostream>
#include <string>
#include <gmp.h>

using namespace std;

int main() {
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(0));

    mpz_t lower_limit, upper_limit;
    mpz_init_set_str(lower_limit, "680564733841876926926749214863536422912", 10);
    mpz_init_set_str(upper_limit, "1361129467683753853853498429727072845823", 10);

    mpz_t range;
    mpz_init(range);
    mpz_sub(range, upper_limit, lower_limit);
    unsigned long bit_range = mpz_sizeinbase(range, 2);
    mpz_clear(range);
    
    string hex_result;
    
    for (int i = 1; i <= 10; ++i) {
        mpz_t random_value;
        mpz_init(random_value);

        mpz_urandomb(random_value, state, bit_range);
        mpz_add(random_value, random_value, lower_limit);
        mpz_add_ui(random_value, random_value, 999999);

        char* hex_str = mpz_get_str(NULL, 16, random_value);
        
        hex_result += hex_str;
        hex_result += "\n";

        mpz_clear(random_value);
        free(hex_str);
    }
    
    mpz_clear(lower_limit);
    mpz_clear(upper_limit);
    gmp_randclear(state);

    return 0;
}
