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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "log.h"
#include "main.h"

/* A single message has max length of 512 characters */
#define BUFFER_SIZE 512

static int parse_buffer (char *buffer, char *nick,
                         char *user, int bytes_in_buffer);
static void construct_wel_msg(char *msg, char *nick, char *user);

int main(int argc, char *argv[])
{
    int opt;
    char *port = NULL, *passwd = NULL, *servername = NULL, *network_file = NULL;
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
            servername = strdup(optarg);
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

    if (network_file && !servername)
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

    int server_socket;
    int client_socket;
    struct addrinfo hints, *res, *p;
    struct sockaddr_in *client_addr;
    int yes = 1;
    socklen_t sin_size = sizeof(struct sockaddr_in);

    char buffer[BUFFER_SIZE + 1];  // +1 for '\0' at end of max msg for parsing
    char constructed_msg[BUFFER_SIZE + 1];
    char nick[BUFFER_SIZE];
    char user[BUFFER_SIZE];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    int nbytes;
    int bytes_in_buffer = 0;

    if (getaddrinfo (NULL, port, &hints, &res) != 0)
    {
        chilog(INFO, "getaddrinfo() failed");
        exit (-1);
    }

    for (p = res; p != NULL; p = p->ai_next)
    {
      if ((server_socket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
      {
          chilog(INFO, "Could not open socket");
          continue;
      }

      if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
      {
          chilog(INFO, "Socket setsockopt() failed");
          close(server_socket);
          continue;
      }

      if (bind(server_socket, p->ai_addr, p->ai_addrlen) == -1)
      {
          chilog(INFO, "Socket bind() failed");
          close(server_socket);
          continue;
      }

      if (listen(server_socket, 5) == -1)
      {
          chilog(INFO, "Socket listen() failed");
          close(server_socket);
          continue;
      }

      break;
    }

    freeaddrinfo(res);  // Free the linked list

    if (p == NULL)
    {
        chilog(INFO, "Could not find a socket to bind to");
        exit (-1);
    }

    while (1)
    {
        /* Clear contents from previous client. */
        memset(buffer, '\0', BUFFER_SIZE + 1);
        memset(nick, '\0', BUFFER_SIZE);
        memset(user, '\0', BUFFER_SIZE);

        client_socket = accept(server_socket, (struct sockaddr *) &client_addr, &sin_size);

        /* Continue receiving messages until we have a nickname and username. */
        while ((*nick == '\0') || (*user == '\0'))
        {
            nbytes = recv(client_socket, &buffer[bytes_in_buffer],
                          (BUFFER_SIZE - bytes_in_buffer), 0);
            if (nbytes == 0)  // Client closed the connection
            {
                close(server_socket);
                return 0;
            }
            bytes_in_buffer += nbytes;
            bytes_in_buffer = parse_buffer(buffer, nick, user, bytes_in_buffer);
        }

        /*
         * Construct welcome message and send to client
         */
        construct_wel_msg(constructed_msg, nick, user);
        send(client_socket, constructed_msg, strlen(constructed_msg), 0);
    }

    close(server_socket);
    return 0;
}

/*
 * Reset msg buffer in case previous welcome message
 * was sent to another client. Then, construct the message with
 * given nickname and username parameters in specified template
 */
static void construct_wel_msg(char *msg, char *nick, char *user)
{
    char *msg_first_part = ":bar.example.com 001 ";
    char *msg_second_part = " :Welcome to the Internet Relay Network ";
    char *msg_third_part = "@foo.example.com\r\n";

    memset(msg, '\0', BUFFER_SIZE + 1);
    strcpy(msg, msg_first_part);
    strcat(msg, nick);
    strcat(msg, msg_second_part);
    strcat(msg, nick);
    strcat(msg, "!");
    strcat(msg, user);
    strcat(msg, msg_third_part);
}

/*
 * Parses the buffer so long as the buffer contains the substring
 * "\r\n" within it. If the message is a nickname, put the contents
 * in *nick; if the message is a username, put the contents in
 * *user. Once the buffer is completely parsed, move the remaining
 * contents of the buffer to front of the buffer, recalculate
 * bytes_in_buffer, and return this recalculated value
 */
static int parse_buffer (char *buffer, char *nick,
                         char *user, int bytes_in_buffer)
{
    char *rest;
    char *token;
    /* The start of the current msg being parsed: */
    char *current_msg = buffer;

    /*
     * So long as the buffer contains the substring "\r\n" within
     * it, there remains a message that must be parsed before a
     * new message (or fragment of a message) is read into the buffer.
     */
    while (strstr(current_msg, "\r\n") != NULL)
    {
        /*
         * Parse the buffer and put contents in nick[],
         * user[], or neither (if invalid).
         */
        rest = current_msg;
        token = strtok_r(rest, " ", &rest);
        if (strcmp(token, "NICK") == 0)
        {
            token = strtok_r(rest, "\r", &rest);
            strcpy (nick, token);
        }
        else if (strcmp(token, "USER") == 0)
        {
            token = strtok_r(rest, " ", &rest);
            strcpy(user, token);
            token = strtok_r(rest, "\r", &rest);
        }
        else
        {
            token = strtok_r(rest, "\r", &rest);
        }

        rest = rest + 1;  // Point past the end of parsed message
        current_msg = rest;
    }
    if (*current_msg == '\0')  // No next message, so reset buffer
    {
        memset(buffer, '\0', BUFFER_SIZE + 1);
        return 0;
    }
    else  // Another message already started in buffer, move to front of buffer
    {
        strcpy(buffer, current_msg);
        bytes_in_buffer = bytes_in_buffer - (current_msg - buffer);
        memset(&buffer[bytes_in_buffer], '\0', (BUFFER_SIZE - bytes_in_buffer));
        return bytes_in_buffer;
    }
}
