#include "pail_homomorph.h"
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>

int
multiply_ctext_ptext(ctext **result, ctext *c, ptext *k, pail_pubkey *pubkey)
{
  /* Multiply a ciphertext by a known plaintext*/
  /* E(c)^k = E(c * k) */
  BIGNUM *n_square = pubkey->n_square;
  *result = BN_new();
  BN_CTX *ctx = BN_CTX_secure_new();
  int output = BN_mod_exp(*result, c, k, n_square, ctx);
  return output;
}

int
add_ctext_ctext(ctext **result, ctext *c1, ctext *c2, pail_pubkey *pubkey)
{
  /* Add two ciphertexts */
  /* E(c1)*E(c2) = E(c1 + c2) */
  BIGNUM *n_square = pubkey->n_square;
  *result = BN_new();
  BN_CTX *ctx = BN_CTX_secure_new();
  int output = BN_mod_mul(*result, c1, c2, n_square, ctx);
  return output;
}

int
add_ctext_ptext(ctext **result, ctext *c, ptext *p, pail_pubkey *pubkey)
{
  /* Add a cipher text to a plaintext */
  /* E(c)*g^p = E(c+p)*/
  BIGNUM *n_square = pubkey->n_square;
  BIGNUM *g = pubkey->g;
  BIGNUM *g_to_p = BN_new();
  *result = BN_new();
  BN_CTX *ctx = BN_CTX_secure_new();

  int output = BN_mod_exp(g_to_p, g, p, n_square, ctx);
  
  output = BN_mod_mul(*result, c, g_to_p, n_square, ctx);

  return output;
}
