#include "pail_utils.h"
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>

void
bn_printout(BIGNUM *bn)
{
  BIO* out = BIO_new_fp(stdout, BIO_NOCLOSE);
  BN_print(out, bn);
  printf("\n");
}

char *
bn_getstring(const BIGNUM* a)
{
  return BN_bn2hex(a);
}

int
subtract_one(BIGNUM **output)
{
  /* Note, there's a difference with add_one
     because we're guaranteed that we can use *output
     as an argument directly
  */
  BIGNUM *a = BN_dup(*output);
  /* a minus 1*/
  int result = BN_sub(*output, a, BN_value_one());
  BN_free(a);
  return result;
}

int
add_one(BIGNUM **output)
{
  return BN_add(*output, *output, BN_value_one());
}

int
print_pubkey_to_file(const char* filename, const pail_pubkey* pubkey)
{
  FILE *f = fopen(filename, "wb");
  if (f == NULL)
  {
    printf("Unable to create private key file %s.\n", filename);
    return 1;
  }

  char* modulus = bn_getstring(pubkey->n);
  char* generator = bn_getstring(pubkey->g);
  char* modulus_square = bn_getstring(pubkey->n_square);
  
  cJSON *output = cJSON_CreateObject();
  if (output == NULL) {
    printf("Unable to allocate cJSON object.\n");
    return 1;
  }

  //Check if Null
  cJSON_AddStringToObject(output, MOD, modulus);

  cJSON_AddStringToObject(output, GEN, generator);

  cJSON_AddStringToObject(output, MOD2, modulus_square);

  fprintf(f, "%s", cJSON_Print(output));

  cJSON_Delete(output);
  return 0;
}

int
print_privkey_to_file(const char* filename, const pail_privkey* privkey)
{
  FILE *f = fopen(filename, "wb");
  if (f == NULL)
  {
    printf("Unable to create private key file %s.\n", filename);
    return 1;
  }

  char* lambda = bn_getstring(privkey->lambda);
  char* modulus = bn_getstring(privkey->pubkey->n);
  char* generator = bn_getstring(privkey->pubkey->g);
  char* modulus_square = bn_getstring(privkey->pubkey->n_square);
  
  cJSON *output = cJSON_CreateObject();
  if (output == NULL) {
    printf("Unable to allocate cJSON object.\n");
    return 1;
  }

  //Check if Null
  cJSON_AddStringToObject(output, LAMB, lambda);

  cJSON_AddStringToObject(output, MOD, modulus);

  cJSON_AddStringToObject(output, GEN, generator);

  cJSON_AddStringToObject(output, MOD2, modulus_square);

  fprintf(f, "%s", cJSON_Print(output));

  cJSON_Delete(output);
  return 0;
}

static long
get_filesize(FILE *f)
{
  fseek(f, 0, SEEK_END);
  long length = ftell(f);
  fseek(f, 0, SEEK_SET);
  return length;
}

int
load_pubkey_from_file(const char* filename, const pail_pubkey** pubkey)
{
  FILE *f = fopen(filename, "rb");
  if (f == NULL)
  {
    printf("Unable to open public key file %s.\n", filename);
    return 1;
  }
  long json_len = get_filesize(f);

  char *json_str = (char*) malloc(json_len+1);
  json_str[json_len] = '\0'; // Ensure that we have a proper c string

  cJSON *pubkey = allocate_pubkey();
  
  if (*pubkey == NULL)
  {
    *pubkey = allocate_pubkey();
  }
}
