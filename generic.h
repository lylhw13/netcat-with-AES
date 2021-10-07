#ifndef GENERIC_H
#define GENERIC_H

#include <errno.h>
#include <stddef.h>
#include <sys/types.h>
#include <unistd.h>
#include <poll.h>
#include <stdlib.h>
#include <stdio.h>

enum TRANSFER_TYPE
{
    NORMAL,
    AES,
};

// extern void readwrite(int sockfd, enum TRANSFER_TYPE tr_type);
extern void readwrite(int sockfd, enum TRANSFER_TYPE tr_type, const char *passwd);

extern char * sha_to_hex(unsigned char *sha512);
extern char * sha512_once(const char *passwd);
extern char * sha512_multi(const char *passwd, int num);
extern char * sha512_multi_salt(const char *passwd, const char *salt, int num);

#endif