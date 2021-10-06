#include "generic.h"
#include "encrypt.h"

#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
#include <netdb.h>

#define HASHTIMES 1e6
#define KEY_OFFSET 30
#define IV_OFFSET 90


int lflag;      /* listen for an incoming connection */
enum TRANSFER_TYPE aesflag;    /* AES type */

void error(const char *str)
{
    perror(str);
    exit(EXIT_FAILURE);
}

static struct option const longopts[] = 
{
    {"listen",  no_argument,       0, 'l'},   
    {"aes",     no_argument,       0, 's'},
};

void usage(int state)
{
    fprintf(stderr, 
        "usage: ncs [-s] -l port\n"
        "       ncs [-s] host port\n");
    exit(state);
}

int build_server(const char *port)
{
    struct addrinfo hints, *result, *rp;
    int ecode;
    int listenfd;

    struct sockaddr_storage cliaddr;
    socklen_t cliaddr_len;
    int connfd;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if ((ecode = getaddrinfo(NULL, port, &hints, &result))) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ecode));
        exit(EXIT_FAILURE);
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        listenfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (listenfd == -1)
            continue;

        int opt = 1;
        if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)))
            perror("setsockopt");

        if (bind(listenfd, rp->ai_addr, rp->ai_addrlen) == 0)
            break;

        close(listenfd);
    }

    freeaddrinfo(result);

    if (rp == NULL) {
        error("Could not bind");
    }

    if (listen(listenfd, 64) < 0)
        error("listen");
    for (;;) {
        cliaddr_len= sizeof(cliaddr);

        connfd = accept(listenfd, (struct sockaddr *)&cliaddr, &cliaddr_len);
        if (connfd >= 0)
            break;
    }

    return connfd;
}

int build_client(const char *host, const char *port)
{
    struct addrinfo hints, *result, *rp;
    int ecode;
    int sockfd;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if ((ecode = getaddrinfo(host, port, &hints, &result))) {
        fprintf(stderr, "client getaddrinfo: %s", gai_strerror(ecode));
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd < 0)
            continue;
        
        if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) == 0)
            break;
        close(sockfd);
    }
    freeaddrinfo(result);

    if (rp == NULL) 
        error("could not connect");
    
    return sockfd;
}


int main(int argc, char *argv[])
{
    char *host, *port;
    int sockfd;
    int c;

    aesflag = NORMAL;
    char *passwd;

    host = NULL;
    port = NULL;
    passwd = NULL;

    // signal(SIGPIPE, SIG_IGN);

    while (1) {
        c = getopt_long(argc, argv, "ls:", longopts, NULL);

        if (c == -1)
            break;

        switch (c)
        {
        case 'l':
            lflag = 1;
            // fprintf(stderr, "current is %c\n", c);
            break;
        case 's':
            aesflag = AES;
            passwd = optarg;
            // fprintf(stderr, "ssl is %c\n", c);
            break;

        default:
            usage(EXIT_FAILURE);
        }
    }

    argc -= optind;
    argv += optind;

    if (argc == 1 && lflag)
        port = argv[0];
    else if (argc == 2 && !lflag) {
        host = argv[0];
        port = argv[1];
    }
    else 
        usage(EXIT_FAILURE);

    if (!port || (!lflag && !host))
        usage(EXIT_FAILURE);

    if (lflag) 
        sockfd = build_server(port);
    else
        sockfd = build_client(host, port);

    
    readwrite(sockfd, aesflag, passwd);

    return 0;
}