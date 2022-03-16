/* na - A tool for asymmetric encryption of files by grunfink - public domain */

#include <stdio.h>
#include <string.h>

#include <sodium.h>

#define VERSION "1.08"


static int read_key_file(unsigned char *p, int size, char *fn)
/* reads a one-line base64 text file into buffer */
{
    int ret = 0;
    FILE *f = NULL;

    if ((f = fopen(fn, "r")) != NULL) {
        char base64[4096];

        if (fgets(base64, sizeof(base64) - 1, f)) {
            int l = strlen(base64);

            if (base64[l - 1] == '\n') {
                l--;
                base64[l] = '\0';
            }

            if (sodium_base642bin(p, size, base64, l, "", NULL, NULL,
                                  sodium_base64_VARIANT_ORIGINAL) != 0) {
                ret = 2;
                fprintf(stderr, "ERROR: sodium_base642bin() in '%s'\n", fn);
            }
        }
        else {
            ret = 2;
            fprintf(stderr, "ERROR: empty key in '%s'\n", fn);
        }

        fclose(f);
    }
    else {
        ret = 2;
        fprintf(stderr, "ERROR: cannot open '%s'\n", fn);
    }

    return ret;
}


static int write_key_file(unsigned char *p, int size, char *fn)
/* writes a buffer as a one-line base64 text file */
{
    int ret = 0;
    FILE *f;

    if ((f = fopen(fn, "w")) != NULL) {
        char base64[4096];

        /* convert buffer to base64 */
        sodium_bin2base64(base64, sizeof(base64), p, size,
                          sodium_base64_VARIANT_ORIGINAL);

        fprintf(f, "%s\n", base64);
        fclose(f);
    }
    else {
        ret = 3;
        fprintf(stderr, "ERROR: cannot create '%s'\n", fn);
    }

    return ret;
}


int na_init(void)
{
    return sodium_init();
}


int na_generate_keys(char *pk_fn, char *sk_fn)
{
    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];

    /* create a new keypair */
    crypto_box_keypair(pk, sk);

    /* write the secret and public keys */
    return write_key_file(sk, sizeof(sk), sk_fn) +
           write_key_file(pk, sizeof(pk), pk_fn);
}


int na_rebuild_public_key(char *pk_fn, char *sk_fn)
{
    int ret = 0;
    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];

    /* read the secret key */
    if ((ret = read_key_file(sk, sizeof(sk), sk_fn)) == 0) {
        /* recompute public key */
        crypto_scalarmult_base(pk, sk);

        /* write it */
        ret = write_key_file(pk, sizeof(pk), pk_fn);
    }

    return ret;
}

#define BLOCK_SIZE 4096

int na_encrypt(FILE *i, FILE *o, char *pk_fn)
{
    int ret = 0;
    unsigned char pk[crypto_box_PUBLICKEYBYTES];                        /* public key */
    unsigned char tmp_pk[crypto_box_PUBLICKEYBYTES];                    /* temp. public key */
    unsigned char tmp_sk[crypto_box_SECRETKEYBYTES];                    /* temp. secret key */
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];  /* stream key */
    unsigned char cy_key[crypto_box_MACBYTES +
        crypto_secretstream_xchacha20poly1305_KEYBYTES];                /* encrypted stream key */
    unsigned char nonce[crypto_box_NONCEBYTES];                         /* nonce */
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    unsigned char bi[BLOCK_SIZE];
    unsigned char bo[BLOCK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    int eof;
    unsigned long long l;

    /* read the public key file */
    if ((ret = read_key_file(pk, sizeof(pk), pk_fn)) != 0)
        goto end;

    /* create a disposable set of keys:
       the public one shall be inside the encrypted stream
       aside with the encrypted symmetric key */
    crypto_box_keypair(tmp_pk, tmp_sk);

    /* create a random nonce */
    randombytes_buf(nonce, sizeof(nonce));

    /* create the stream key */
    crypto_secretstream_xchacha20poly1305_keygen(key);

    /* now encrypt the symmetric key using the pk and the disposable sk */
    if (crypto_box_easy(cy_key, key, sizeof(key), nonce, pk, tmp_sk) != 0) {
        ret = 4;
        fprintf(stderr, "ERROR: crypto_box_easy()\n");
        goto end;
    }

    /* write the signature */
    bo[0] = 'n';
    bo[1] = 'a';
    bo[2] = 0x00;
    bo[3] = 0x01;
    fwrite(bo, 4, 1, o);

    /* write the disposable pk */
    fwrite(tmp_pk, sizeof(tmp_pk), 1, o);

    /* write the nonce */
    fwrite(nonce, sizeof(nonce), 1, o);

    /* write the encrypted symmetric key */
    fwrite(cy_key, sizeof(cy_key), 1, o);

    /* start encrypt stream */
    crypto_secretstream_xchacha20poly1305_init_push(&st, header, key);

    /* write the stream header */
    fwrite(header, sizeof(header), 1, o);

    do {
        l = fread(bi, 1, sizeof(bi), i);
        eof = feof(i);

        crypto_secretstream_xchacha20poly1305_push(&st, bo, &l, bi, l, NULL,
            0, eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0);

        fwrite(bo, 1, (size_t) l, o);
    } while (!eof);

end:
    return ret;
}


int na_decrypt(FILE *i, FILE *o, char *sk_fn)
{
    int ret = 0;
    unsigned char sk[crypto_box_PUBLICKEYBYTES];                        /* secret key */
    unsigned char tmp_pk[crypto_box_PUBLICKEYBYTES];                    /* temp. public key */
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];  /* stream key */
    unsigned char cy_key[crypto_box_MACBYTES +
        crypto_secretstream_xchacha20poly1305_KEYBYTES];                /* encrypted stream key */
    unsigned char nonce[crypto_box_NONCEBYTES];                         /* nonce */
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    unsigned char bi[BLOCK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char bo[BLOCK_SIZE];
    int eof;
    unsigned long long l;
    unsigned char tag;

    /* read the secret key */
    if ((ret = read_key_file(sk, sizeof(sk), sk_fn)) != 0)
        goto end;

    /* read 4 bytes */
    if (fread(bi, 4, 1, i) != 1) {
        ret = 2;
        fprintf(stderr, "ERROR: unexpected EOF reading signature\n");
        goto end;
    }

    /* does it have a signature? */
    if (bi[0] == 'n' && bi[1] == 'a' && bi[2] == 0x00) {
        if (bi[3] != 0x01) {
            ret = 2;
            fprintf(stderr, "ERROR: signature for another format (0x%02x)\n", bi[3]);
            goto end;
        }
    }
    else {
        ret = 2;
        fprintf(stderr, "ERROR: bad signature\n");
        goto end;
    }

    /* read the public key + the nonce + encrypted symmetric key */
    if (fread(tmp_pk, sizeof(tmp_pk), 1, i) != 1 ||
        fread(nonce,  sizeof(nonce),  1, i) != 1 ||
        fread(cy_key, sizeof(cy_key), 1, i) != 1) {
        ret = 2;
        fprintf(stderr, "ERROR: unexpected EOF reading header\n");
        goto end;
    }

    /* decrypt the symmetric key */
    if (crypto_box_open_easy(key, cy_key, sizeof(cy_key), nonce, tmp_pk, sk)) {
        ret = 4;
        fprintf(stderr, "ERROR: crypto_box_open_easy()\n");
        goto end;
    }

    /* read the stream header */
    if (fread(header, sizeof(header), 1, i) != 1) {
        ret = 2;
        fprintf(stderr, "ERROR: incomplete header\n");
        goto end;
    }

    /* init decryption */
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key)) {
        ret = 4;
        fprintf(stderr, "ERROR: crypto_secretstream_xchacha20poly1305_init_pull()\n");
        goto end;
    }

    do {
        l = fread(bi, 1, sizeof(bi), i);
        eof = feof(i);

        if (crypto_secretstream_xchacha20poly1305_pull(&st, bo, &l, &tag,
                                       bi, l, NULL, 0)) {
            ret = 4;
            fprintf(stderr, "ERROR: corrupted chunk\n");
            break;
        }

        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL && ! eof) {
            ret = 2;
            fprintf(stderr, "ERROR: premature end\n");
            break;
        }

        if (fwrite(bo, 1, (size_t) l, o) != l) {
            ret = 3;
            fprintf(stderr, "ERROR: write error\n");
            break;
        }

    } while (!eof);

end:
    return ret;
}


char *na_info(void)
/* returns information about the crypto engine */
{
    return "libsodium (Curve25519, XChacha20+Poly1305) format=0x01";
}


char *na_version(void)
/* returns the version */
{
    return VERSION;
}
