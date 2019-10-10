#include "pail_key.h"
#include "pail_utils.h"
#include "opaillier.h"
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>

int
check_g(BIGNUM* g, BIGNUM* n_square)
{
  BIGNUM *gcd = BN_new();
  BN_CTX *ctx = BN_CTX_new();

  BN_gcd(gcd, g, n_square, ctx);

  return BN_is_one(gcd);
}

int
check_lambda(BIGNUM* lambda, BIGNUM* n)
{
  BIGNUM *n_square = BN_new();
  BIGNUM *w = BN_new();
  BIGNUM *n_lambda = BN_new();
  BIGNUM *w_to_lambda = BN_new();
  BIGNUM *w_to_n_lambda = BN_new();
  BN_CTX *ctx = BN_CTX_secure_new();

  BN_mul(n_lambda, n, lambda, ctx);
  BN_sqr(n_square, n, ctx);
  BN_rand_range(w, n);
  BN_mul(w, w, n, ctx);
  subtract_one(&w);
  
  
  BN_mod_exp(w_to_lambda, w, lambda, n, ctx);
  BN_mod_exp(w_to_n_lambda, w, n_lambda, n_square, ctx);

  if (BN_cmp(w_to_lambda, w_to_n_lambda) != 0)
  {
    printf("Lambda is INVALID.\n");
    return 0;
  }
  else {
    printf("Lambda is VALID.\n");
    return 1;
  }
}

static int
compute_lambda(BIGNUM** lambda, BIGNUM *p, BIGNUM *q)
{
  /*
    Lambda is the least common multiple of p-1 and q-1.
    This has the property s.t.
    w^lambda = 1 mod n
    w^(lambda*n) = 1 mod n^2
    Note: LCM(a,b) = a*b/GCD(a,b)
   */

  BN_CTX *ctx = BN_CTX_secure_new();
  BIGNUM *gcd = BN_new();
  *lambda = BN_new();
  BIGNUM *pq = BN_new(); // Technically (p-1)(q-1)
  BIGNUM *rem = BN_new();
  BIGNUM *p_minus_1 = BN_dup(p);
  int result = subtract_one(&p_minus_1);
  BIGNUM *q_minus_1 = BN_dup(q);
  result = subtract_one(&q_minus_1);
  
  result = BN_gcd(gcd, p_minus_1, q_minus_1, ctx);
  result = BN_mul(pq, p_minus_1, q_minus_1, ctx);
  result = BN_div(*lambda, rem, pq, gcd, ctx);
  //TODO: check results

  result = check_lambda(*lambda, pq);
  
  BN_CTX_free(ctx);
  BN_free(gcd);
  BN_free(pq);
  BN_free(p_minus_1);
  BN_free(q_minus_1);

  return result;
}

/*
BIGNUM*
compute_alpha(BIGNUM *p, BIGNUM *q, BIGNUM *)
{
TODO: figure this out later.
}
*/

pail_privkey*
generate_key(int strength)
{
  // Generate prime p
  BIGNUM *p = BN_new();
  int result = BN_generate_prime_ex(p, strength, 1, NULL, NULL, NULL);
  //TODO: check result
  
  // Generate prime q
  BIGNUM *q = BN_new();
  result = BN_generate_prime_ex(q, strength, 1, NULL, NULL, NULL);
  //TODO: check result
  
  // Calculate n
  BN_CTX *ctx = BN_CTX_secure_new();
  BIGNUM *n = BN_new();
  result = BN_mul(n, p, q, ctx);
  //TODO: check result
  printf("modulus is: \n");
  bn_printout(n);
  //Calculate lambda
  BIGNUM *lambda = NULL;
  result = compute_lambda(&lambda, p, q);
  //TODO: check result

  BIGNUM *n_square = BN_new();
  BN_sqr(n_square, n, ctx);

  /*
    IMPORTANT NOTE:
    This implementation is currently setting the generator to be
    1 plus the modulus.
    In generally, g can be any number such that:

    GCD(L(g^lambda mod n^2), n) = 1

    Another way of computing this might be to run check_g with random values
    until check_g returns 1.
   */

  
  // Create g = (n+1)
  BIGNUM *g = BN_dup(n);
  result = add_one(&g);

  if (check_g(g, n_square)) {
    printf("Our generator checks out.\n");
  }
  
  pail_privkey* privkey = allocate_privkey();
  pail_pubkey* pubkey = allocate_pubkey();

  pubkey->n = n;
  pubkey->g = g;
  pubkey->n_square = n_square;
  privkey->pubkey = pubkey;
  privkey->lambda = lambda;
  
  return privkey;
}

void
pail_pubkey_free(pail_pubkey* k)
{
  BN_free(k->n);
  BN_free(k->g);
  free(k);
}

void
pail_privkey_free(pail_privkey* k)
{
  pail_pubkey_free(k->pubkey);
  BN_free(k->lambda);
  free(k);
}
  
pail_pubkey*
generate_pubkey_from_priv(pail_privkey *priv)
{
  //Generate pubkey with a deep copy of privkey->pubkey
  pail_pubkey* output = allocate_pubkey();
  pail_pubkey* input = priv->pubkey;
  output->n = BN_dup(input->n);
  output->g = BN_dup(input->g);
  output->n_square = BN_dup(input->n_square);
  
  return output;
}

pail_pubkey*
generate_pubkey_from_BN(BIGNUM *n, BIGNUM *g)
{
  pail_pubkey* output = allocate_pubkey();
  output->n = BN_dup(n);
  output->g = BN_dup(g);
  BIGNUM *n_square = BN_new();
  BN_CTX *ctx = BN_CTX_secure_new();

  BN_sqr(n_square, n, ctx);
  BN_CTX_free(ctx);

  output->n_square = n_square;
  return output;
}

pail_privkey*
generate_privkey_from_BN(BIGNUM *n, BIGNUM *g, BIGNUM *lambda)
{
  pail_privkey* output = allocate_privkey();
  output->pubkey = generate_pubkey_from_BN(n, g);
  output->lambda = BN_dup(lambda);
}

pail_privkey*
allocate_privkey()
{
  return (pail_privkey*) calloc(1, sizeof(pail_privkey));
}

pail_pubkey*
allocate_pubkey()
{
  return (pail_pubkey*) calloc(1, sizeof(pail_pubkey));
}
