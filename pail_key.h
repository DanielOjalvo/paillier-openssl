#ifndef PAIL_KEY_H
#define PAIL_KEY_H
/*
  OpenSSL Paillier
  By: Daniel Ojalvo, 2019
  An implementation of key creation for Paillier encryption using OpenSSL
  This is based on the scheme described in section 4 of the original paper.

  TODO: write a variant based on the fast decryption scheme described on the original
  fast decryption scheme described in section 6 of the paper

  "Public-Key Cryptosystems Based on Composite Degree Residuosity Classes"
  By Pascal Paillier
  https://link.springer.com/content/pdf/10.1007%2F3-540-48910-X_16.pdf
 */
#include <openssl/bn.h>

typedef struct pubkey_struct {
  BIGNUM *n; //Our modulus product of two primes
  BIGNUM *g; //Our generator, note: gcd(L(g^lambda mod n^2),n) = 1, usually n+1 in practice
  BIGNUM *n_square; //precomputation of n^2
} pail_pubkey;

typedef struct privkey_struct {
  pail_pubkey *pubkey;
  BIGNUM *lambda; // Result of  carmichael functionon p*q
  //BIGNUM *alpha; // 1 <= alpha <= lambda
  //note in pubkey n = p*q
} pail_privkey;

pail_privkey* allocate_privkey();

pail_pubkey* allocate_pubkey();

/*
  Generates a private key to use for encryption/decryption.
*/
pail_privkey* generate_key(int strength);

/* 
   Generates a public key with a deep copy of public key stored in pail_privkey.
   Caller is expected to cleanup returned value.
*/
pail_pubkey* generate_pubkey_from_priv(pail_privkey *priv);

/*
  Generates a public key with deep copy of modulus and generator.
  Caller is expected to cleanup the returned value.
 */
pail_pubkey* generate_pubkey_from_BN(BIGNUM *n, BIGNUM *g);

/*
  Generates a public key with deep copy of modulus and generator.
  Caller is expected to cleanup the returned value.
 */
pail_privkey* generate_privkey_from_BN(BIGNUM *n, BIGNUM *g, BIGNUM *lambda);

int check_g(BIGNUM* g, BIGNUM* n_square);

/*
  Tests the validity of the given lambda and modulus.
  Ensures that lambda is the LCM of (p-1) and (q-1).

  It does so by ensuring that this is true;
  w^lambda = 1 mod n
  w^(lambda*n) = 1 mod n^2

  for random w between 0 and n

  Returns 1 for valid lambda
  Returns 0 for invalid lambda
 */
int check_lambda(BIGNUM* lambda, BIGNUM* n);

/*
  Checks if the given generator is valid with the given modulus squared.
  The generator is valid if GCD(g, n_square) = 1
 */
int check_g(BIGNUM* g, BIGNUM* n_square);


#endif
