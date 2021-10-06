#include "encrypt.h"
#include <unistd.h>

static EVP_CIPHER_CTX *d_ctx;
static EVP_CIPHER_CTX *e_ctx;

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

static void _enc_ctx_init(EVP_CIPHER_CTX **ctx, unsigned char *key, unsigned char *iv, int enc)
{
    if(!(*ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if (1 != EVP_CipherInit_ex(*ctx, EVP_aes_256_cbc(), NULL, key, iv, enc))
        handleErrors();
}

void ctx_init(unsigned char *key, unsigned char *iv)
{
    _enc_ctx_init(&e_ctx, key, iv, 1);    /* 1 for encryption */
    _enc_ctx_init(&d_ctx, key, iv, 0);    /* 0 for decryption */
}

void _enc_ctx_reset(EVP_CIPHER_CTX **ctx, unsigned char *key, unsigned char *iv, int enc)
{
    if (1 != EVP_CipherInit_ex(*ctx, EVP_aes_256_cbc(), NULL, key, iv, enc))
        handleErrors();
}

void ctx_reset(unsigned char *key, unsigned char *iv)
{
    EVP_CIPHER_CTX_reset(e_ctx);
    EVP_CIPHER_CTX_reset(d_ctx);
    _enc_ctx_init(&e_ctx, key, iv, 1);    /* 1 for encryption */
    _enc_ctx_init(&d_ctx, key, iv, 0);    /* 0 for decryption */
}


static int encry_decry_ctx(unsigned char *inbuf, int in_len, EVP_CIPHER_CTX *ctx, unsigned char *outbuf)
{
    int len, out_len;

    if (ctx != NULL) {
        unsigned char mybuf[BUFSIZE];

        if (1 != EVP_CipherUpdate(ctx, mybuf, &len, (unsigned char *)inbuf, in_len)) 
            return -1;

        
        out_len = len;

        if (1 != EVP_CipherFinal_ex(ctx, mybuf + len, &len)) 
            return -1;
        

        out_len += len;
        memcpy(outbuf, mybuf, out_len);
    }
    return out_len;
}

int encry(unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext)
{
    return encry_decry_ctx(plaintext, plaintext_len, e_ctx, ciphertext);
}

int decry(unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext)
{
    return encry_decry_ctx(ciphertext, ciphertext_len, d_ctx, plaintext);
}

void ctx_cleanup(void)
{
    EVP_CIPHER_CTX_free(e_ctx);
    EVP_CIPHER_CTX_free(d_ctx);
}


