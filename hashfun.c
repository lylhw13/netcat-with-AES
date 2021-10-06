#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define BUFF_LENGTH SHA512_DIGEST_LENGTH * 2 + 1

#define max(a, b) \
({  \
    typeof(a) _a = (a); \
    typeof(b) _b = (b); \
    _a >= _b ? _a : _b; \
})

char * sha_to_hex(unsigned char *sha512)
{
	static char buffer[BUFF_LENGTH];
	static const char hex[] = "0123456789abcdef";
	char *buf = buffer;
	int i;

    if (!sha512)
        return NULL;

	for (i = 0; i < SHA512_DIGEST_LENGTH; i++) {
		unsigned int val = *sha512++;
		*buf++ = hex[val >> 4];
		*buf++ = hex[val & 0xf];
	}
	return buffer;
}


char * sha512_once(const char *passwd)
{
    static unsigned char sha512[SHA512_DIGEST_LENGTH];
    SHA512_CTX c;
    SHA512_Init(&c);
    SHA512(passwd, strlen(passwd), sha512);
    return sha512;
}

char * sha512_multi(const char *passwd, int num)
{
    int i;
    unsigned char buffer[BUFF_LENGTH];
    char *sha_res;
    strcpy(buffer, passwd);

    if (num <=0)
        return NULL;

    for (i = 0; i< num; ++i) {
        sha_res = sha512_once(buffer);

        strcpy(buffer, sha_to_hex(sha_res));
    }
    return sha_res;
}

char * sha512_multi_salt(const char *passwd, const char *salt, int num)
{
    int i;
    int len = max(strlen(passwd) + strlen(salt), BUFF_LENGTH);
    char *res;
    unsigned char *buffer = malloc(len);
    strcpy(buffer, passwd);
    strcat(buffer, salt);
    res = sha512_multi(buffer, num);
    free(buffer);
    return res;
}
