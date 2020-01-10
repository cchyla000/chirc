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

/* A single message has max length of 512 characters */
#define BUFFER_SIZE 512 

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

    /* Your code goes here */


    /* IMPORTANT: Like the oneshot-single.c, we are creating the socket and sockaddr
     * structures manually. Your solution _must_ use getaddrinfo instead. You can see
     * examples of this in client.c and in server-pthreads.c */

    int server_socket;
    int client_socket;
    struct addrinfo hints, *res, *p;
    struct sockaddr_in *client_addr;
    int yes = 1;
    socklen_t sin_size = sizeof(struct sockaddr_in);

    int have_user = 0;
    int have_nick = 0;
    char buffer[BUFFER_SIZE + 1]; // +1 for '\0'
    char nick[BUFFER_SIZE + 1];
    char user[BUFFER_SIZE + 1];
    memset (buffer, '\0', BUFFER_SIZE + 1);
    memset (nick, '\0', BUFFER_SIZE + 1);
    memset (user, '\0', BUFFER_SIZE + 1);

    char *token;
    char *rest;
    char *msg = ":bar.example.com 001 user1 :Welcome to the Internet Relay Network user1!user1@foo.example.com\r\n";
    char *msgFirstPart = ":bar.example.com 001 ";
    char *msgSecondPart = " :Welcome to the Internet Relay Network ";
    char *msgThirdPart = "@foo.example.com\r\n";
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // return my address, so I can bind() to it

    char *current_msg = buffer;
    char* buf;
    buf = buffer;

    int nbytes;
    int bytes_left;

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

    freeaddrinfo(res); // free the linked list

    if (p == NULL)
    {
        chilog(INFO, "Could not find a socket to bind to");
        exit (-1);
    }

    while(1)
    {

        client_socket = accept(server_socket, (struct sockaddr *) &client_addr, &sin_size);

        bytes_left = BUFFER_SIZE;

        while ((!have_nick) || (!have_user))
        {

          nbytes = recv(client_socket, buf, bytes_left, 0);
          bytes_left -= nbytes;

          if (nbytes == 0) // client closed the connection
          {
            chilog(INFO, "client closed connection");
            close(server_socket);
            return 0;
          }

          /* if the characters "\r\n" are not in the buffer,
             increment the pointer buf by nbytes: */
          if (strstr(current_msg, "\r\n") == NULL)
          {
            buf += nbytes;
          }
          else
          {
            do
            {
              /* parse the buffer, put contents in nick[], user[],
                 or neither */

              rest = current_msg;
              token = strtok_r(rest, " ", &rest);
              if (strcmp(token, "NICK") == 0)
              {
                token = strtok_r(rest, "\r", &rest);
                strcpy (nick,token);
                have_nick = 1;
              }
              else if (strcmp(token, "USER") == 0)
              {
                token = strtok_r(rest, " ", &rest);
                strcpy(user,token);
                have_user = 1;
                token = strtok_r(rest, "\r", &rest);
              }
              else // not a valid message
              {
                token = strtok_r(rest, "\r", &rest);
              } 

              rest = rest + 1; // points past end of parsed message
              if (*rest == '\0') // no next message, reset
              {
                memset (buffer, '\0', BUFFER_SIZE + 1);
                buf = buffer;
                bytes_left = BUFFER_SIZE;
                current_msg = buffer;
              }              
              else // another message already started in buffer, cannot reset
              {
                current_msg = rest;
              }

            }
            while (strstr(current_msg, "\r\n") != NULL);

          }
        }

        char actualMsg[BUFFER_SIZE + 1];
        strcpy(actualMsg,msgFirstPart);
        strcat(actualMsg,nick);
        strcat(actualMsg,msgSecondPart);
        strcat(actualMsg,nick);
        strcat(actualMsg,"!");
        strcat(actualMsg,user);
        strcat(actualMsg,msgThirdPart);
        chilog(TRACE, actualMsg);
        send(client_socket, actualMsg, strlen(actualMsg), 0);
    }

    close(server_socket);

    return 0;
}
