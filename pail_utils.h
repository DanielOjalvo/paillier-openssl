#ifndef PAIL_UTILS_H
#define PAIL_UTILS_H

#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>
#include "pail_key.h"
#include "cJSON.h"

#define MOD "modulus"
#define GEN "generator"
#define MOD2 "modulus_square"
#define LAMB "lambda"

void bn_printout(BIGNUM *bn);
int subtract_one(BIGNUM **output);
int add_one(BIGNUM **output);
char* bn_getstring(const BIGNUM* a);

int print_pubkey_to_file(const char* filename, const pail_pubkey* pubkey);
int print_privkey_to_file(const char* filename, const pail_privkey* privkey);

int load_pubkey_from_file(const char* filename, const pail_pubkey** pubkey);
int load_privkey_from_file(const char* filename, const pail_privkey** privkey);

#define PRINT_ERR() printf(ERR_error_string(ERR_get_error(), NULL)); printf("\n")

#endif //PAIL_UTILS_H
