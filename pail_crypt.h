#ifndef PAIL_CRYPT_H
#define PAIL_CRYPT_H

#include "pail_key.h"

typedef BIGNUM ctext;
typedef BIGNUM ptext;

int blind_direct(ctext **result, ctext *c, BIGNUM *blinder, pail_pubkey *pubkey);
int blind_indirect(ctext **result, ctext *c, BIGNUM *blinder, pail_pubkey *pubkey);
int L_func(BIGNUM **output, BIGNUM *u, BIGNUM *n);

/*
   Takes an existing plaintext, encrypts it with pubkey, creates
   ciphertext, then returns it. The caller is expected to cleanup
   the ciphertext.
*/
ctext* pail_encrypt(ptext *p, pail_pubkey *pubkey);

/*
   Takes an existing ciphertext, decrypts it with privkey, creates
   plaintext, then returns it. The caller is expected to cleanup
   the plaintext.
*/
ptext* pail_decrypt(ctext *c, pail_privkey *privkey);

#endif //PAIL_CRYPT_H
