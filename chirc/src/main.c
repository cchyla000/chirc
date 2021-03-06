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
#include "connection.h"

/* A single message has max length of 512 characters */
#define BUFFER_SIZE 512

int main(int argc, char *argv[])
{
    int opt;
    char *port = NULL, *passwd = NULL, *server_name = NULL, *network_file = NULL;
    int verbosity = 0;
    FILE *fp;

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

    sigset_t new;
    sigemptyset (&new);
    sigaddset(&new, SIGPIPE);
    if (pthread_sigmask(SIG_BLOCK, &new, NULL) != 0)
    {
        perror("Unable to mask SIGPIPE");
        exit(-1);
    }

    /* Malloc the global context and initialize its values */
    struct ctx_t *ctx = calloc(1, sizeof(struct ctx_t));
    pthread_mutex_init(&ctx->users_lock, NULL);
    pthread_mutex_init(&ctx->channels_lock, NULL);
    pthread_mutex_init(&ctx->servers_lock, NULL);

    /* Store the network specification file in data structure: */
    char *token = NULL;
    char *rest = NULL;
    int i;
    struct chirc_server_t *server;
    struct chirc_server_t *tmp;
    char buffer[NI_MAXHOST];

    if (network_file)
    {
        fp = fopen(network_file, "r");
        if (fp == NULL)
        {
            perror("Could not open network file");
            exit(-1);
        }

        while (fgets(buffer, NI_MAXHOST, fp) != NULL)
        {
            rest = buffer;
            for (i = 0; token = strtok_r(rest, ",\n", &rest); i++)
            {
                switch (i)
                {
                    case 0:  // Server name
                        server = calloc(1, sizeof (struct chirc_server_t));
                        pthread_mutex_init(&server->lock, NULL);
                        strncpy(server->servername, token, MAX_SERVER_LEN);
                        break;
                    case 1:
                        strncpy(server->hostname, token, MAX_HOST_LEN);
                        break;
                    case 2:
                        strncpy(server->port, token, MAX_PORT_LEN);
                        break;
                    case 3:
                        strncpy(server->password, token, MAX_PASSWORD_LEN);
                        /* Don't need a lock here because we are initializing
                           the server at startup; no race condition can occur */
                        HASH_ADD_STR(ctx->servers, servername, server);
                        break;
                    default:
                        free(server);
                        HASH_ITER(hh, ctx->servers, server, tmp)
                        {
                            HASH_DEL(ctx->servers, server);
                            free(server);
                        }
                        perror("Too many commas per line in "
                               "network specification file");
                        exit(-1);
                }
            }
        }

        /* Find the server corresponding to this program
           in network specification file */
        HASH_FIND_STR(ctx->servers, server_name, server);
        if (server)
        {
            server->is_registered = true;
            strncpy(server->oper_password, passwd, MAX_PASSWORD_LEN);
            ctx->this_server = server;
            HASH_DEL(ctx->servers, server);
        }
        else  // Server not specified. Exit with error.
        {
            HASH_ITER(hh, ctx->servers, server, tmp)
            {
                HASH_DEL(ctx->servers, server);
                free(server);
            }
            perror("Servername not specified in network file");
            exit(-1);
        }
    }
    else
    {
        server = calloc(1, sizeof (struct chirc_server_t));
        pthread_mutex_init(&server->lock, NULL);
        strncpy(server->oper_password, passwd, MAX_PASSWORD_LEN);
        strncpy(server->port, port, MAX_PORT_LEN);
        server->is_registered = true;
        ctx->this_server = server;
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

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if (getaddrinfo(NULL, server->port, &hints, &res) != 0)
    {
        perror("getaddrinfo() failed");
        pthread_exit(NULL);
    }

    for(p = res;p != NULL; p = p->ai_next)
    {
        if ((server_socket = socket(p->ai_family, p->ai_socktype,
                                                        p->ai_protocol)) == -1)
        {
            perror("Could not open socket");
            continue;
        }

        if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR,
                                                      &yes, sizeof(int)) == -1)
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
        if ((client_socket = accept(server_socket,
                            (struct sockaddr *) client_addr, &sin_size)) == -1)
        {
            free(client_addr);
            perror("Could not accept() connection");
            continue;
        }
        wa = calloc(1, sizeof(struct worker_args));
        wa->socket = client_socket;
        wa->ctx = ctx;
        wa->client_addr = (struct sockaddr *) client_addr;
        wa->connection = NULL;
        if (pthread_create(&worker_thread, NULL, service_connection, wa) != 0)
        {
            perror("Could not create a worker thread");
            free(client_addr);
            free(wa);
            close(client_socket);
            close(server_socket);
            return 1;
        }
    }

    return 0;
}
