/*
 *
 *  chirc: a simple multi-threaded IRC server
 *
 *  This module provides the main() function for the server,
 *  and parses the command-line arguments to the chirc executable.
 *
 */

/*
 *  Copyright (c) 2011-2020, The University of Chicago
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or withsend
 *  modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 *  - Neither the name of The University of Chicago nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software withsend specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY send OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include "log.h"
#include "ctx.h"
#include "user.h"

/* A single message has max length of 512 characters */
#define BUFFER_SIZE 512

int main(int argc, char *argv[])
{
    int opt;
    char *port = NULL, *passwd = NULL, *server_name = NULL, *network_file = NULL;
    int verbosity = 0;

    while ((opt = getopt(argc, argv, "p:o:s:n:vqh")) != -1)
        switch (opt)
        {
        case 'p':
            port = strdup(optarg);
            break;
        case 'o':
            passwd = strdup(optarg);
            break;
        case 's':
            server_name = strdup(optarg);
            break;
        case 'n':
            if (access(optarg, R_OK) == -1)
            {
                printf("ERROR: No such file: %s\n", optarg);
                exit(-1);
            }
            network_file = strdup(optarg);
            break;
        case 'v':
            verbosity++;
            break;
        case 'q':
            verbosity = -1;
            break;
        case 'h':
            printf("Usage: chirc -o OPER_PASSWD [-p PORT] [-s SERVERNAME] [-n NETWORK_FILE] [(-q|-v|-vv)]\n");
            exit(0);
            break;
        default:
            fprintf(stderr, "ERROR: Unknown option -%c\n", opt);
            exit(-1);
        }

    if (!passwd)
    {
        fprintf(stderr, "ERROR: You must specify an operator password\n");
        exit(-1);
    }

    if (network_file && !server_name)
    {
        fprintf(stderr, "ERROR: If specifying a network file, you must also specify a server name.\n");
        exit(-1);
    }

    /* Set logging level based on verbosity */
    switch(verbosity)
    {
    case -1:
        chirc_setloglevel(QUIET);
        break;
    case 0:
        chirc_setloglevel(INFO);
        break;
    case 1:
        chirc_setloglevel(DEBUG);
        break;
    case 2:
        chirc_setloglevel(TRACE);
        break;
    default:
        chirc_setloglevel(TRACE);
        break;
    }

    /* ADDED: Malloc the server context and initialize its values,
     * which includes initializing the mutex.*/
    struct ctx_t *ctx = calloc(1, sizeof(struct ctx_t));
    ctx->users = NULL;
    ctx->channels = NULL;
    ctx->unknown_clients = 0;
    ctx->connected_clients = 0;
    strncpy(ctx->password, passwd, MAX_MSG_LEN);
    pthread_mutex_init(&ctx->users_lock, NULL);
    pthread_mutex_init(&ctx->channels_lock, NULL);

    sigset_t new;
    sigemptyset (&new);
    sigaddset(&new, SIGPIPE);
    if (pthread_sigmask(SIG_BLOCK, &new, NULL) != 0)
    {
        perror("Unable to mask SIGPIPE");
        exit(-1);
    }

    int server_socket;
    int client_socket;
    int error;
    pthread_t worker_thread;
    struct addrinfo hints, *res, *p;
    struct sockaddr_storage *client_addr;
    socklen_t sin_size = sizeof(struct sockaddr_storage);
    struct worker_args *wa;
    int yes = 1;
    char server_name_buffer[NI_MAXHOST];

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if (getaddrinfo(NULL, port, &hints, &res) != 0)
    {
        perror("getaddrinfo() failed");
        pthread_exit(NULL);
    }

    for(p = res;p != NULL; p = p->ai_next)
    {
        if ((server_socket = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
        {
            perror("Could not open socket");
            continue;
        }

        if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
        {
            perror("Socket setsockopt() failed");
            close(server_socket);
            continue;
        }

        if (bind(server_socket, p->ai_addr, p->ai_addrlen) == -1)
        {
            perror("Socket bind() failed");
            close(server_socket);
            continue;
        }

        if (listen(server_socket, 5) == -1)
        {
            perror("Socket listen() failed");
            close(server_socket);
            continue;
        }

        /* Get server hostname */
        error = getnameinfo(p, sizeof(struct sockaddr_storage), 
                            server_name_buffer, NI_MAXHOST, NULL, 0, 0); 
        if (error)
        {
            perror("Failed to resolve server hostname");
            close(server_socket);
            continue;
        }
        else if (strlen(server_name_buffer) > MAX_HOST_LEN)
        {
            error = getnameinfo(p, sizeof(struct sockaddr_storage),
                                ctx->server_name, MAX_HOST_LEN, NULL,
                                0, NI_NUMERICHOST);
            if (error)
            {
                perror("Failed to resolve server hostname");
                close(server_socket);
                continue;
            }
        } 
        else
        {
            strncpy(ctx->server_name, server_name_buffer, MAX_HOST_LEN);
        }
        break;
    }

    freeaddrinfo(res);

    if (p == NULL)
    {
        fprintf(stderr, "Could not find a socket to bind to.\n");
        pthread_exit(NULL);
    }

    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    sprintf(ctx->date_created, "%d-%02d-%02d %02d:%02d:%02d", tm.tm_year + 1900,
            tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    while (1)
    {
        client_addr = calloc(1, sin_size);
        if ((client_socket = accept(server_socket, (struct sockaddr *) client_addr, &sin_size)) == -1)
        {
            free(client_addr);
            perror("Could not accept() connection");
            continue;
        }

        wa = calloc(1, sizeof(struct worker_args));
        wa->socket = client_socket;
        wa->ctx = ctx;
        wa->client_addr = (struct sockaddr *) client_addr;
        if (pthread_create(&worker_thread, NULL, service_user, wa) != 0)
        {
            perror("Could not create a worker thread");
            free(client_addr);
            free(wa);
            close(client_socket);
            close(server_socket);
            return 1;
        }
    }
/*
    HASH_ITER(hh, ctx->users, s, tmp) {
      HASH_DEL(ctx->users, s);
      free(s);
    }
    HASH_ITER(hh, ctx->channels, s, tmp) {
      HASH_DEL(ctx->channels, s);
      free(s);
    }
*/
    pthread_mutex_destroy(&ctx->users_lock);
    pthread_mutex_destroy(&ctx->channels_lock);
    free(ctx);

    return 0;
}
