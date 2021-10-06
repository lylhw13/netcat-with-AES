#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

#define BUFSIZE 4096

static void handleErrors(void);

static void _enc_ctx_init(EVP_CIPHER_CTX **ctx, unsigned char *key, unsigned char *iv, int enc);
void ctx_init(unsigned char *key, unsigned char *iv);
void ctx_reset(unsigned char *key, unsigned char *iv);

static int encry_decry_ctx(unsigned char *inbuf, int in_len, EVP_CIPHER_CTX *ctx, unsigned char *outbuf);
int encry(unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext);
int decry(unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext);

void ctx_cleanup(void);
