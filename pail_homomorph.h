#ifndef PAIL_HOMOMORPH_H
#define PAIL_HOMOMORPH_H

#include "pail_key.h"
#include "pail_crypt.h"

int multiply_ctext_ptext(ctext **result, ctext *c, ptext *k, pail_pubkey *pubkey);

int add_ctext_ctext(ctext **result, ctext *c1, ctext *c2, pail_pubkey *pubkey);

int add_ctext_ptext(ctext **result, ctext *c, ptext *p, pail_pubkey *pubkey);

#endif //PAIL_HOMOMORPH_H
