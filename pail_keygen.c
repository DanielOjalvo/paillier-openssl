#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include "opaillier.h"

#define FILENAME_LIMIT (NAME_MAX + PATH_MAX)

pail_privkey*
generate_privkey(int strength)
{
  return generate_key(strength);
}

void
print_help()
{
char *help_text =
  "usage: pail_keygen -s <bit> -p <pubkey filename> -k <privkey file>\n"
  "This tool will generate a public/private key pair to be used in Paillier encryption.";
}

int
main (int argc, char **argv)
{
  int key_strength = 0;
  char *pub_key_file = NULL;
  char *priv_key_file = NULL;
  int c;

  opterr = 0;


  while ((c = getopt (argc, argv, "k:s:p:")) != -1){
    switch (c)
      {
      case 'h':
	print_help();
	return 0;
	break;
      case 's':
	key_strength = atoi(optarg);
	if (key_strength <= 0)
	  {
	    fprintf(stderr, "A positive number must be the argument for -k.\n");
	  }
	break;
      case 'p':
	pub_key_file = strndup(optarg, FILENAME_LIMIT);
	break;
      case 'k':
	priv_key_file = strndup(optarg, FILENAME_LIMIT);
	break;
      case '?':
	if (optopt == 's')
	  fprintf (stderr, "Option -%c requires an numeric argument.\n", optopt);
	else if (optopt == 'p')
	  fprintf (stderr, "Option -%c requires a public key filename.\n", optopt);
	else if (optopt == 'k')
	  fprintf (stderr, "Option -%c requires a private key filename.\n", optopt);
	else if (isprint (optopt))
	  fprintf (stderr, "Unknown option `-%c'.\n", optopt);
	else
	  fprintf (stderr,
		   "Unknown option character `\\x%x'.\n",
		   optopt);
	return 1;
      default:
	abort ();
      }
  }

  pail_privkey* privkey = generate_key(key_strength);
  pail_pubkey* privkey_pubkey = privkey->pubkey;
  pail_pubkey* pubkey = generate_pubkey_from_priv(privkey);

  printf("Generated private key and public key.\n");

  printf("lambda:\n");
  bn_printout(privkey->lambda);

  printf("privkey_pubkey n:\n");
  bn_printout(privkey_pubkey->n);

  printf("privkey_pubkey g:\n");
  bn_printout(privkey_pubkey->g);

  printf("privkey_pubkey n_square:\n");
  bn_printout(privkey_pubkey->n_square);

  printf("pubkey n:\n");
  bn_printout(pubkey->n);

  printf("pubkey g:\n");
  bn_printout(pubkey->g);

  printf("pubkey n_square:\n");
  bn_printout(pubkey->n_square);

  print_privkey_to_file(priv_key_file, privkey);
  print_pubkey_to_file(pub_key_file, pubkey);

  
  return 0;
}
