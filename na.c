/* na - A tool for asymmetric encryption of files by grunfink - public domain */

#include <string.h>

#include "na.h"


int usage(char *argv0)
{
    fprintf(stderr, "%s %s - An asymmetric encryption tool by grunfink - public domain\n\n",
        argv0, na_version());

    fprintf(stderr, "Encrypts/decrypts a stream of data using a pair of asymmetric keys.\n\n");

    fprintf(stderr, "Usage: \n\n");

    fprintf(stderr, "  %s -G -p pubkey -s seckey     Generate key pairs\n", argv0);
    fprintf(stderr, "  %s -R -p pubkey -s seckey     Regenerate pubkey from seckey\n", argv0);
    fprintf(stderr, "  %s -E -p pubkey               Encrypt STDIN to STDOUT\n", argv0);
    fprintf(stderr, "  %s -D -s seckey               Decrypt STDIN to STDOUT\n", argv0);

    fprintf(stderr, "\n");
    fprintf(stderr, "Crypto engine: %s\n\n", na_info());

    return 1;
}


int main(int argc, char *argv[])
{
    int ret;
    char *pk_fn = NULL;
    char *sk_fn = NULL;
    char *cmd = NULL;

    if (!na_init()) {
        int n;

        for (n = 1; n < argc; n++) {
            char *p = argv[n];

            if (strcmp(p, "-G") == 0 || strcmp(p, "-R") == 0 ||
                strcmp(p, "-E") == 0 || strcmp(p, "-D") == 0)
                cmd = p;
            else
            if (strcmp(p, "-p") == 0)
                pk_fn = argv[++n];
            else
            if (strcmp(p, "-s") == 0)
                sk_fn = argv[++n];
        }

        if (cmd == NULL)
            ret = usage(argv[0]);
        else
        if (strcmp(cmd, "-G") == 0 && pk_fn && sk_fn)
            ret = na_generate_keys(pk_fn, sk_fn);
        else
        if (strcmp(cmd, "-R") == 0 && pk_fn && sk_fn)
            ret = na_rebuild_public_key(pk_fn, sk_fn);
        else
        if (strcmp(cmd, "-E") == 0 && pk_fn)
            ret = na_encrypt(stdin, stdout, pk_fn);
        else
        if (strcmp(cmd, "-D") == 0 && sk_fn)
            ret = na_decrypt(stdin, stdout, sk_fn);
        else
            ret = usage(argv[0]);
    }
    else {
        ret = 4;
        fprintf(stderr, "ERROR: cannot initialize crypto engine\n");
    }

    return ret;
}
