/* na - A tool for asymmetric encryption of files by grunfink - public domain */

#include <stdio.h>

int na_init(void);
int na_generate_keys(char *pk_fn, char *sk_fn);
int na_rebuild_public_key(char *pk_fn, char *sk_fn);
int na_encrypt(FILE *i, FILE *o, char *pk_fn);
int na_decrypt(FILE *i, FILE *o, char *sk_fn);
char *na_info(void);
char *na_version(void);
