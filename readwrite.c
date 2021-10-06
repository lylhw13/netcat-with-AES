#include "generic.h"
#include "encrypt.h"

#include <poll.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>

#define KEY_LEN 32
#define IV_LEN 16
#define KEY_OFFSET 30
#define IV_OFFSET 90
#define HASHTIMES 1e6

#define POLL_STDIN 0
#define POLL_NETOUT 1
#define POLL_NETIN 2
#define POLL_STDOUT 3

static unsigned char key[KEY_LEN + 1]; //= (unsigned char *)"01234567890123456789012345678901";
static unsigned char iv[IV_LEN + 1];  // = (unsigned char *)"0123456789012345";

static void error(const char *str)
{
    perror(str);
    exit(EXIT_FAILURE);
}

static void init_key_iv(const char *passwd)
{
    char * hash;
    hash = sha_to_hex(sha512_multi(passwd, HASHTIMES));
    memcpy(key, hash + KEY_OFFSET, KEY_LEN);
    key[KEY_LEN] = '\0';
    memcpy(iv, hash + IV_OFFSET, IV_LEN);
    iv[IV_LEN] = '\0';

    // printf("key is %s\n", key);
    // printf("iv is %s\n", iv);
    // ctx_init(key, iv);
    // return hash;
}

void readwrite(int sockfd, enum TRANSFER_TYPE tr_type, const char *passwd)
{
    struct pollfd pfds[4];
    int numfds;
    int timeout = 0;
    unsigned char stdinbuf[BUFSIZE];
    unsigned char netinbuf[BUFSIZE];
    int stdinbufpos = 0;
    int netinbufpos = 0;
    int ciphertextlen = 0;
    int decryptedtextlen = 0;
    int i, nread, nwrite;
    unsigned long errorcode;
    int decry_try_times = 3;

    pfds[POLL_STDIN].fd = STDIN_FILENO;
    pfds[POLL_STDIN].events = POLLIN;

    pfds[POLL_NETOUT].fd = sockfd;
    pfds[POLL_NETOUT].events = 0;

    pfds[POLL_NETIN].fd = sockfd;
    pfds[POLL_NETIN].events = POLLIN;

    pfds[POLL_STDOUT].fd = STDOUT_FILENO;
    pfds[POLL_STDOUT].events = 0;

    if (tr_type == AES) {
        init_key_iv(passwd);
        ctx_init(key, iv);
    }


    while (1)
    {
        /* no read */
        if (pfds[POLL_STDIN].fd == -1 || pfds[POLL_NETIN].fd == -1) 
            if (stdinbufpos == 0 && netinbufpos == 0 && ciphertextlen == 0 && decryptedtextlen == 0)
                return;

        /* no write */
        if (pfds[POLL_STDOUT].fd == -1 && pfds[POLL_NETOUT].fd == -1)
            return;

        numfds = poll(pfds, 4, timeout);

        if (numfds < 0)
            error("poll");

        if (!numfds)
            continue;

        /* check fd conditions */
        for (i = 0; i < 4; ++i)
            if (pfds[i].revents & (POLLERR | POLLNVAL))
                pfds[i].fd = -1;

        /* poll for normal type */
        if (tr_type == NORMAL)
        {
            /* stdin fo stdinbuf */
            if (pfds[POLL_STDIN].revents & POLLIN && stdinbufpos < BUFSIZE)
            {
                errno = 0;
                nread = read(pfds[POLL_STDIN].fd, stdinbuf + stdinbufpos, BUFSIZE - stdinbufpos);
                if (nread == 0) {   /* end of file */
                    pfds[POLL_STDIN].fd = -1;
                    continue;
                }
                if (nread < 0) {
                    if (errno == EAGAIN)
                        continue;
                    else {
                        perror("stdin read");
                        exit(EXIT_FAILURE);
                    }
                }
                        
                stdinbufpos += nread;

                if (stdinbufpos > 0)
                    pfds[POLL_NETOUT].events = POLLOUT;

                if (stdinbufpos == BUFSIZE)
                    pfds[POLL_STDIN].events = 0;
            }

            /* netout from stdinbuf */
            if (pfds[POLL_NETOUT].revents & POLLOUT && stdinbufpos > 0)
            {
                errno = 0;
                nwrite = write(pfds[POLL_NETOUT].fd, stdinbuf, stdinbufpos);
                if (nwrite < 0) {
                    if (errno == EAGAIN)
                        continue;
                    else {
                        perror("netout write");
                        exit(EXIT_FAILURE);
                    }
                }

                stdinbufpos -= nwrite;
                memmove(stdinbuf, stdinbuf + nwrite, stdinbufpos);

                if (stdinbufpos < BUFSIZE)
                    pfds[POLL_STDIN].events = POLLIN;

                if (stdinbufpos == 0) 
                    pfds[POLL_NETOUT].events = 0;
            }

            /* netin to netinbuf */
            if (pfds[POLL_NETIN].revents & POLLIN && netinbufpos < BUFSIZE)
            {
                errno = 0;
                nread = read(pfds[POLL_NETIN].fd, netinbuf + netinbufpos, BUFSIZE - netinbufpos);
                if (nread == 0) {   /* connection close */
                    pfds[POLL_NETIN].fd = -1;
                    continue;
                }
                if (nread < 0) {
                    if (errno == EAGAIN)
                        continue;
                    else {
                        perror("netin read");
                        exit(EXIT_FAILURE);
                    }
                }

                netinbufpos += nread;

                if (netinbufpos > 0)
                    pfds[POLL_STDOUT].events = POLLOUT;

                if (netinbufpos == BUFSIZE)
                    pfds[POLL_NETIN].events = 0;
            }

            /* stdout from netinbuf */
            if (pfds[POLL_STDOUT].revents & POLLOUT && netinbufpos > 0)
            {
                errno = 0;
                nwrite = write(pfds[POLL_STDOUT].fd, netinbuf, netinbufpos);
                if (nwrite < 0) {
                    if (errno == EAGAIN)
                        continue;
                    else {
                        perror("stdout write");
                        exit(EXIT_FAILURE);
                    }
                }

                /* write for next time */
                netinbufpos -= nwrite;
                memmove(netinbuf, netinbuf + nwrite, netinbufpos);

                if (netinbufpos < BUFSIZE)
                    pfds[POLL_NETIN].events = POLLIN;

                if (netinbufpos == 0)
                    pfds[POLL_STDOUT].events = 0;
            }
        }

        /* poll for AES type */
        if (tr_type == AES)
        {
            /* stdin fo stdinbuf */
            if (pfds[POLL_STDIN].revents & POLLIN && stdinbufpos < BUFSIZE - 1)
            {
                errno = 0;
                nread = read(pfds[POLL_STDIN].fd, stdinbuf + stdinbufpos, BUFSIZE - 1 - stdinbufpos);
                if (nread == 0) {   /* end of file */
                    pfds[POLL_STDIN].fd = -1;
                    continue;
                }
                if (nread < 0) {
                    if (errno == EAGAIN)
                        continue;
                    else {
                        perror("stdin read");
                        exit(EXIT_FAILURE);
                    }
                }
                
                stdinbufpos += nread;

                ctx_reset(key, iv);
                ciphertextlen = encry(stdinbuf, stdinbufpos, stdinbuf);

                if (ciphertextlen < 0) {
                    ERR_print_errors_fp(stderr);
                    exit(EXIT_FAILURE);
                }

                if (ciphertextlen > 0)
                {
                    pfds[POLL_NETOUT].events = POLLOUT;
                    pfds[POLL_STDIN].events = 0;
                    stdinbufpos = 0;
                }
                // printf("POLL_STDIN stdinpos %d, cipher len %d\n", stdinbufpos, ciphertextlen);
            }

            /* netout from stdinbuf */
            if (pfds[POLL_NETOUT].revents & POLLOUT && stdinbufpos < ciphertextlen)
            {
                errno = 0;
                nwrite = write(pfds[POLL_NETOUT].fd, stdinbuf + stdinbufpos, ciphertextlen - stdinbufpos);
                if (nwrite < 0) {
                    if (errno == EAGAIN)
                        continue;
                    else {
                        perror("netout write");
                        exit(EXIT_FAILURE);
                    }
                }
                
                stdinbufpos += nwrite;

                // printf("POLL_NETOUT stdinpos %d, cipher len %d\n", stdinbufpos, ciphertextlen);

                if (stdinbufpos == ciphertextlen)
                {
                    stdinbufpos = 0;
                    ciphertextlen = 0;
                    pfds[POLL_STDIN].events = POLLIN;
                    pfds[POLL_NETOUT].events = 0;
                }
            }

            /* netin to netinbuf */
            if (pfds[POLL_NETIN].revents & POLLIN && netinbufpos < BUFSIZE)
            {
                errno = 0;
                nread = read(pfds[POLL_NETIN].fd, netinbuf + netinbufpos, BUFSIZE - netinbufpos);
                if (nread == 0) {   /* connection close */
                    pfds[POLL_NETIN].fd = -1;
                    continue;
                }
                if (nread < 0) {
                    if (errno == EAGAIN)
                        continue;
                    else {
                        perror("netin read");
                        exit(EXIT_FAILURE);
                    }
                }

                netinbufpos += nread;
                if (netinbufpos == 0)
                    continue;

                ctx_reset(key, iv);
                decryptedtextlen = decry(netinbuf, netinbufpos, netinbuf);
                if (decryptedtextlen < 0) {
                    decry_try_times --;
                    errorcode = ERR_peek_last_error();
                    /*
                     * error:06065064:digital envelope routines:EVP_DecryptFinal_ex:bad decrypt:../crypto/evp/evp_enc.c:610: 
                     * error:0606506D:digital envelope routines:EVP_DecryptFinal_ex:wrong final block length:../crypto/evp/evp_enc.c:599:
                    */
                    if (decry_try_times > 0 && (errorcode == 0x0606506D || errorcode == 0x06065064)) {
                        ERR_get_error();    /* remove this errorcode */
                        continue;
                    }

                    ERR_print_errors_fp(stderr);
                    exit(EXIT_FAILURE);
                }

                // printf("POLL_NETIN netinpos %d, decry len %d\n", netinbufpos, decryptedtextlen);

                if (decryptedtextlen > 0)
                {
                    pfds[POLL_STDOUT].events = POLLOUT;
                    pfds[POLL_NETIN].events = 0;
                    netinbufpos = 0;
                    decry_try_times = 3;
                }
            }

            /* stdout from netinbuf */
            if (pfds[POLL_STDOUT].revents & POLLOUT && netinbufpos < decryptedtextlen)
            {
                errno = 0;
                nwrite = write(pfds[POLL_STDOUT].fd, netinbuf + netinbufpos, decryptedtextlen - netinbufpos);
                if (nwrite < 0) {
                    if (errno == EAGAIN)
                        continue;
                    else {
                        perror("stdout write");
                        exit(EXIT_FAILURE);
                    }
                }

                /* check nwrite */
                netinbufpos += nwrite;

                // printf("POLL_STDOUT netinpos %d, decry len %d\n", netinbufpos, decryptedtextlen);

                if (netinbufpos == decryptedtextlen)
                {
                    pfds[POLL_NETIN].events = POLLIN;
                    pfds[POLL_STDOUT].events = 0;
                    decryptedtextlen = 0;
                    netinbufpos = 0;
                }
            }
        }
    }

    ctx_cleanup();
}