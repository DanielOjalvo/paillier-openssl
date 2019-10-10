#ifndef PAIL_KEYGEN_H
#define PAIL_KEYGEN_H
/*
  Functions to automate loading public and/or private keys.
 */
#include "pail_key.h"

int load_pubkey(pail_pubkey** p, const char* filename);

int load_privkey(pail_privkey**, const char* filename);

int print_privkey_to_file(const char* filename, const pail_privkey* privkey);

int print_pubkey_to_file(const char* filename, const pail_pubkey* pubkey);

int print_privkey(const pail_privkey* privkey);

int print_pubkey(const pail_pubkey* pubkey);

#endif
