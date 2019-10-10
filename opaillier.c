#include "opaillier.h"
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>

int
main(void)
{
  printf("Generating private key\n");
  pail_privkey *priv = generate_key(255);
  //printf("generated\n");
  
  printf("Generating public key\n");
  pail_pubkey *pub = generate_pubkey_from_priv(priv);
  //printf("Generated\n");

  printf("generating plaintext\n");
  ptext* plaintext = NULL;
  int result = BN_hex2bn(&plaintext, "deadbeeffff");
  //printf("Made number\n");

  //printf("created new file pointer\n");
  bn_printout(plaintext);
  printf("plaintext generated\n");

  printf("encrypting\n");
  ctext* ciphertext = pail_encrypt(plaintext, pub);
  printf("Cipher text: \n");
  bn_printout(ciphertext);

  printf("decrypting\n");
  ptext* decryption = pail_decrypt(ciphertext, priv);
  printf("finished decryption\n");
  bn_printout(decryption);

  printf("Decryption finished \n");

  printf("Testing homomorphic properties.\n");

  ptext* a = NULL;
  ptext* b = NULL;
  ptext* c = NULL;

  result = BN_hex2bn(&a, "a");
  printf("a has hex value:\n");
  bn_printout(a);
  result = BN_hex2bn(&b, "b");
  printf("b has hex value:\n");
  bn_printout(b);
  result = BN_hex2bn(&c, "c");
  printf("c has hex value:\n");
  bn_printout(c);
  
  ctext* e_a = pail_encrypt(a, pub);
  printf("The encryption of a is:\n");
  bn_printout(e_a);
  ctext* e_b = pail_encrypt(b, pub);
  printf("Then encryption of b is:\n");
  bn_printout(e_b);
  // Leave c as plaintext
  printf("blinding e_a directly, result is:\n");
  BIGNUM* a_blinder = NULL;
  ctext* e_a_blinded = NULL;
  ctext* e_a_blinded_indirect = NULL;
  BN_hex2bn(&a_blinder, "abcde");
  printf("Our blinder is:\n");
  bn_printout(a_blinder);
  blind_direct(&e_a_blinded, e_a, a_blinder, pub);
  printf("The direct blinding of a is:\n");
  bn_printout(e_a_blinded);
  blind_indirect(&e_a_blinded_indirect, e_a, a_blinder, pub);
  printf("The indirect blinding of a is:\n");
  bn_printout(e_a_blinded_indirect);
  
  ptext* d_a = pail_decrypt(e_a, priv);
  ptext* d_a_blinded = pail_decrypt(e_a_blinded, priv);
  ptext* d_a_blinded_indirect = pail_decrypt(e_a_blinded_indirect, priv);
  printf("The expected decrypted value is:\n");
  bn_printout(a);
  printf("The decryption of a is:\n");
  bn_printout(d_a);
  printf("The decryption of the blinded encryption is:\n");
  bn_printout(d_a_blinded);
  printf("The decryption of the indirectly blinded encryption is:\n");
  bn_printout(d_a_blinded_indirect);


  printf("Testing multiplying by a plaintext\n");
  BIGNUM* e_a_times_c = NULL;
  BIGNUM* a_times_c = BN_new();
  BN_CTX *ctx = BN_CTX_secure_new();
  
  printf("Expecting the result:\n");
  BN_mul(a_times_c, a, c, ctx);
  bn_printout(a_times_c);

  printf("Calculating muliplying encrypted value times a plaintext\n");

  multiply_ctext_ptext(&e_a_times_c, e_a, c, pub);
  printf("Multiplied ciphertext is:\n");
  bn_printout(e_a_times_c);
  printf("Decrypted result:\n");
  bn_printout(pail_decrypt(e_a_times_c, priv));

  printf("Testing adding two encrypted values e_a + e_b:\n");
  BIGNUM *e_a_plus_e_b = NULL;
  BIGNUM *expected = BN_new();
  BN_add(expected, a, b);
  add_ctext_ctext(&e_a_plus_e_b, e_a, e_b, pub);
  printf("Expected Value:\n");
  bn_printout(expected);
  printf("Calculated encryption:\n");
  bn_printout(e_a_plus_e_b);

  printf("decryption:\n");
  bn_printout(pail_decrypt(e_a_plus_e_b, priv));

  
  printf("Testing adding encrypted and unencrypted number:\n");
  BIGNUM *e_a_plus_c = NULL;
  expected = BN_new();
  BN_add(expected, a, c);
  add_ctext_ptext(&e_a_plus_c, e_a, c, pub);
  printf("Expected Value:\n");
  bn_printout(expected);
  printf("Calculated Value:\n");
  bn_printout(e_a_plus_c);

  printf("decryption:\n");
  bn_printout(pail_decrypt(e_a_plus_c, priv));


  return 0;
}
