#include "pail_crypt.h"
#include "pail_utils.h"
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>

int
blind_direct(ctext **result, ctext *c, BIGNUM *blinder, pail_pubkey *pubkey)
{
  /* Transform c to an equivalent encryption */
  /* D(E(c)*r^n) = D(E(c)) = c*/

  BIGNUM *n_square = pubkey->n_square;
  BIGNUM *n = pubkey->n;
  BN_CTX *ctx = BN_CTX_secure_new();

  BIGNUM *r_to_n = BN_new();
  *result = BN_new();

  int output = BN_mod_exp(r_to_n, blinder, n, n_square, ctx);
  
  output = BN_mod_mul(*result, c, r_to_n, n_square, ctx);

  return output;
}

int
blind_indirect(ctext **result, ctext *c, BIGNUM *blinder, pail_pubkey *pubkey)
{
  /* Transform c to an equivalent encryption */
  /* D(E(c)*g^(r*n)) = D(E(c)) = c*/

  BIGNUM *n_square = pubkey->n_square;
  BIGNUM *n = pubkey->n;
  BIGNUM *g = pubkey->g;
  BIGNUM *n_blinder = BN_new(); // n*r
  BIGNUM *g_to_n_blinder = BN_new(); // g^(n*r)
  BN_CTX *ctx = BN_CTX_secure_new();

  *result = BN_new();

  int output = BN_mul(n_blinder, blinder, n, ctx);
  output = BN_mod_exp(g_to_n_blinder, g, n_blinder, n_square, ctx);
  output = BN_mod_mul(*result, c, g_to_n_blinder, n_square, ctx);

  return output;
}

int
L_func(BIGNUM **output, BIGNUM *u, BIGNUM *n)
{
  /*
    The L function is used in decryption process.
    L(u) = (u-1)/n
    where u is an element of {u < n^2 | u = 1 mod n}
    n is our modulus (p*q)
   */
  BN_CTX *ctx = BN_CTX_secure_new();
  /* Check result, ctx = Null -> error*/
  BIGNUM *u_minus_1 = BN_dup(u);
  int result = subtract_one(&u_minus_1);
  *output = BN_new();

  /* Check result, 1 = success, 0 = failure*/
  result = BN_div(*output, NULL, u_minus_1, n, ctx);
  /* Check result, 1=success, 0=failure*/
  BN_free(u_minus_1);
  BN_CTX_free(ctx);
  
  return result;
}

ctext*
pail_encrypt(ptext *m, pail_pubkey *pubkey)
{
  //Should check that m<n

  // Generate random r<n
  // ciphertext = g^m*r^n mod n^2

  ctext *c = (ctext*) BN_new();
  BIGNUM *g = pubkey->g;
  BIGNUM *n = pubkey->n;
  BIGNUM *r = BN_new();
  BIGNUM *n_square = pubkey->n_square;
  int result = BN_rand_range(r, n);
  //TODO: check result
  //printf("generated random number\n");
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *g_to_the_m = BN_new();
  BIGNUM *r_to_the_n = BN_new();
  //printf("Pointers, g_to_the_m: %d, g:%d, m:%d, n_square:%d, r_to_the_n:%d, r:%d\n", g_to_the_m, g, m, n_square, r_to_the_n, r);
  result = BN_mod_exp(g_to_the_m, g, m, n_square, ctx);
  //printf("g^m\n");
  //bn_printout(g_to_the_m);
  result = BN_mod_exp(r_to_the_n, r, n, n_square, ctx); //Can precalculate with constant r
  //printf("r^n\n");
  //bn_printout(r_to_the_n);

  result = BN_mod_mul(c, g_to_the_m, r_to_the_n, n_square, ctx);
  //bn_printout(c);
  int larger = BN_cmp(c, n_square);
  //printf("BN_cmp(c, n_square) = %d\n", larger);
  //printf("Finishing encryption\n");
  return c;
}

ptext*
pail_decrypt(ctext *c, pail_privkey *privkey)
{
  //Should check that c<n^2

  BIGNUM* lambda = privkey->lambda;
  BIGNUM* g = privkey->pubkey->g;
  BIGNUM* n = privkey->pubkey->n;
  BIGNUM* n_square = privkey->pubkey->n_square;

  BIGNUM* c_to_the_lambda = BN_new();
  BIGNUM* g_to_the_lambda = BN_new(); //Can precalculate
  BIGNUM *numerator = NULL;
  BIGNUM *denominator = NULL;
  
  BN_CTX *ctx = BN_CTX_secure_new();
  //printf("allocated all of our values\n");

  int result;
  result = BN_mod_exp(c_to_the_lambda, c, lambda, n_square, ctx);
  //printf("c^lambda mod n^2\n");
  //bn_printout(c_to_the_lambda);
  result = BN_mod_exp(g_to_the_lambda, g, lambda, n_square, ctx); //Can precalculate
  //printf("g^lambda mod n^2\n");
  //bn_printout(g_to_the_lambda);

  //result = L_func(&numerator, c_to_the_lambda, n_square);
  result = L_func(&numerator, c_to_the_lambda, n);
  //printf("First L func calculated %d\n", numerator);
  //bn_printout(numerator);
  //result = L_func(&denominator, g_to_the_lambda, n_square); // can precalculate
  result = L_func(&denominator, g_to_the_lambda, n); // can precalculate
  //printf("second L func calculated %d\n", denominator);
  //bn_printout(denominator);
  //denominator = BN_mod_mul(NULL, L_g_to_the_lambda, n, ctx); //can precalculate
  //printf(ERR_error_string(ERR_get_error(), NULL));

  //PRINT_ERR();
  /*
  ptext* p = BN_new();
  //printf("created p\n");
  //printf("Pointers, p: %d, numerator: %d, denominator: %d, n: %d, ctx: %d \n", p, numerator, denominator, n, ctx);
  result = BN_div(p, NULL, numerator, denominator, ctx);
  //bn_printout(n);
  bn_printout(p);
  ptext* p_reduced = BN_new();
  result = BN_nnmod(p_reduced, p, n, ctx);
  */
  /* calculate with inverse of denominator */

  BIGNUM *denominator_inverse = BN_mod_inverse(NULL, denominator, n, ctx);

  BIGNUM *p = BN_new();
  result = BN_mod_mul(p, numerator, denominator_inverse, n, ctx);
  //printf("BN_mod_mul");
  //bn_printout(p);
  
  //PRINT_ERR();
  return p;
}
