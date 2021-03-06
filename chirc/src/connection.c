/*
 *  FILENAME: connection.c
 *  DESCRIPTION: Implementation of connection.h
 *  AUTHORS: Cameron Chyla and Artur Genser (acknowledgement to CMSC 23320)
 *  LAST DATE MODIFIED: January 30th, 2020
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

#include "connection.h"
#include "user_handler.h"
#include "server_handler.h"
#include "log.h"
#include "ctx.h"
#include "reply.h"
#include "message.h"

/*
 * Worst case scenario is if we cannot parse a first message of
 * MAX_MSG_LENGTH because the last '\n' does not come in until
 * a call to recv() that also returns a 2nd message of length
 * MAX_MSG_LENGTH - 1; therefore, we need a buffer the size of 2
 * messages
 */
#define MAX_MSG_LEN 512
#define BUFFER_LEN ((2 * MAX_MSG_LEN) + 1)

typedef int (*user_handler_function)(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_user_t *user);

typedef int (*server_handler_function)(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_server_t *server);

struct user_handler_entry
{
    char *name;
    user_handler_function func;
};

struct server_handler_entry
{
    char *name;
    server_handler_function func;
};

#define USER_HANDLER_ENTRY(NAME) { #NAME, handle_ ## NAME ## _USER }
#define SERVER_HANDLER_ENTRY(NAME) { #NAME, handle_ ## NAME ## _SERVER }

struct user_handler_entry user_handlers[] = {
                                     USER_HANDLER_ENTRY(NICK),
                                     USER_HANDLER_ENTRY(USER),
                                     USER_HANDLER_ENTRY(QUIT),
                                     USER_HANDLER_ENTRY(PRIVMSG),
                                     USER_HANDLER_ENTRY(PING),
                                     USER_HANDLER_ENTRY(PONG),
                                     USER_HANDLER_ENTRY(LUSERS),
                                     USER_HANDLER_ENTRY(WHOIS),
                                     USER_HANDLER_ENTRY(JOIN),
                                     USER_HANDLER_ENTRY(MODE),
                                     USER_HANDLER_ENTRY(LIST),
                                     USER_HANDLER_ENTRY(OPER),
                                     USER_HANDLER_ENTRY(CONNECT)
                                  };

struct server_handler_entry server_handlers[] = {
                                     SERVER_HANDLER_ENTRY(NICK),
                                     SERVER_HANDLER_ENTRY(PRIVMSG),
                                     SERVER_HANDLER_ENTRY(JOIN),
                                     SERVER_HANDLER_ENTRY(PASS),
                                     SERVER_HANDLER_ENTRY(SERVER)
                                  };

int num_user_handlers = sizeof(user_handlers) / sizeof(struct user_handler_entry);
int num_server_handlers = sizeof(server_handlers) / sizeof(struct server_handler_entry);

int send_message(struct chirc_message_t *msg, struct chirc_user_t *user)
{
    int nbytes;
    char to_send[MAX_MSG_LEN + 1] = {0};
    chirc_message_to_string(msg, to_send);

    pthread_mutex_lock(&user->lock);
    nbytes = send(user->socket, to_send, strlen(to_send), 0);
    pthread_mutex_unlock(&user->lock);

    if (nbytes == -1)
    {
        return -1;
    }

    return 0;
}

int send_message_to_server(struct chirc_message_t *msg, struct chirc_server_t *server)
{
    int nbytes;
    char to_send[MAX_MSG_LEN + 1] = {0};
    chirc_message_to_string(msg, to_send);

    pthread_mutex_lock(&server->lock);
    nbytes = send(server->socket, to_send, strlen(to_send), 0);
    pthread_mutex_unlock(&server->lock);

    if (nbytes == -1)
    {
        return -1;
    }

    return 0;
}

/*
 * Set struct user hostname field using getnameinfo(); if
 * hostname can't be resolved or is greater than 63 characters
 * in length, then use the numeric form of the hostname.
*/
static int set_host_name(char *hostname, struct worker_args *wa)
{
    char buffer[NI_MAXHOST];
    int error;

    error = getnameinfo(wa->client_addr, sizeof(struct sockaddr_storage),
                          buffer, NI_MAXHOST, NULL, 0, 0);
    if (error)
    {
        return -1;
    }
    else if (strlen(buffer) > MAX_HOST_LEN)
    {
        error = getnameinfo(wa->client_addr, sizeof(struct sockaddr_storage),
                            buffer, MAX_HOST_LEN, NULL, 0, NI_NUMERICHOST);
        if (error)
        {
            return -1;
        }
    }

    strncpy(hostname, buffer, MAX_HOST_LEN);
    return 0;
}

void *service_connection(void *args)
{
    struct worker_args *wa;
    struct chirc_message_t msg;
    struct ctx_t *ctx;
    struct chirc_connection_t *connection;
    struct chirc_message_t reply_msg;
    char buffer[BUFFER_LEN + 1] = {0};  // + 1 for extra '\0' at end
    char tosend[MAX_MSG_LEN + 1] = {0};
    char prefix_buffer[MAX_MSG_LEN + 1] = {0};
    char hostname[MAX_HOST_LEN + 1] = {0};
    char *tmp;
    char *cmd;
    int client_socket, nbytes, i, error, bytes_in_buffer = 0;

    struct chirc_user_t *user = NULL;
    struct chirc_server_t *server = NULL;

    wa = (struct worker_args*) args;
    client_socket = wa->socket;
    ctx = wa->ctx;
    connection = wa->connection;
    ctx->num_direct_connections++;

    /* Create connection struct */
    if (connection == NULL)
    {
        connection = calloc(1, sizeof(struct chirc_connection_t));
        connection->type = UNKNOWN;
        if (set_host_name(hostname, wa) == -1)
        {
            close(client_socket);
            free(wa);
            free(connection);
            ctx->num_direct_connections--;
            pthread_exit(NULL);
        }
    }
    else if (connection->type == USER)
    {
        connection->user->socket = client_socket;
        user = connection->user;
        ctx->num_direct_users++;
    }
    else if (connection->type == SERVER)
    {
        server = connection->server;
        ctx->num_direct_servers++;
    }



    /*
     * Tells the pthread library that no other thread is going to
     * join() this thread, so we can free its resources at termination
     */
    pthread_detach(pthread_self());

    while(1)
    {
        nbytes = recv(client_socket, &buffer[bytes_in_buffer],
                     (BUFFER_LEN - bytes_in_buffer), 0);
        if (nbytes == 0)
        {
            close(client_socket);
            destroy_connection(connection, ctx);
            free(wa);
            pthread_exit(NULL);
        }
        bytes_in_buffer += nbytes;

        tmp = buffer;
        while (strstr(tmp, "\r\n") != NULL)
        {
            memset(&msg, 0, sizeof(msg));
            nbytes = chirc_message_from_string(&msg, tmp);

            /* Point to beginning of next msg if present. */
            tmp += (nbytes + 1);
            /* Send msg to handler */
            cmd = msg.cmd;

            if (connection->type == UNKNOWN)
            {
                if (!strcmp("NICK", cmd) || (!strcmp("USER", cmd)))
                {
                    connection->type = USER;
                    user = calloc(1, sizeof(struct chirc_user_t));
                    strncpy(user->hostname, hostname, MAX_HOST_LEN);
                    user->socket = client_socket;
                    pthread_mutex_init(&user->lock, NULL);
                    ctx->num_direct_users++;
                }
                else if (!strcmp("PASS", cmd) || (!strcmp("SERVER", cmd)))
                {
                    connection->type = SERVER;
                    server = calloc(1, sizeof(struct chirc_server_t));
                    strncpy(server->hostname, hostname, MAX_HOST_LEN);
                    server->socket = client_socket;
                    pthread_mutex_init(&server->lock, NULL);
                    ctx->num_direct_servers++;
                }
            }

            if (connection->type == USER)
            {
                for(i=0; i<num_user_handlers; i++)
                {
                    if (!strcmp(user_handlers[i].name, cmd))
                    {
                        error = user_handlers[i].func(ctx, &msg, user);
                        if (error == -1)
                        {
                            close(client_socket);
                            destroy_connection(connection, ctx);
                            free(wa);
                            pthread_exit(NULL);
                        }
                        break;
                    }
                }
                if (i == num_user_handlers && user->is_registered)
                {
                    chirc_message_construct(&reply_msg,
                                            ctx->this_server->servername,
                                            ERR_UNKNOWNCOMMAND);
                    chirc_message_add_parameter(&reply_msg,
                                                user->nickname, false);
                    sprintf(prefix_buffer, "%s :Unknown command", cmd);
                    chirc_message_add_parameter(&reply_msg,
                                                prefix_buffer, false);
                    chirc_message_to_string(&reply_msg, tosend);
                    send(client_socket, tosend, strlen(tosend), 0);
                }
            }
            else if (connection->type == SERVER)
            {
                for(i=0; i<num_server_handlers; i++)
                {
                    if (!strcmp(server_handlers[i].name, cmd))
                    {
                        error = server_handlers[i].func(ctx, &msg, server);
                        if (error == -1)
                        {
                            close(client_socket);
                            destroy_connection(connection, ctx);
                            free(wa);
                            pthread_exit(NULL);
                        }
                        break;
                    }
                }
            }
        }
        /* Clear Buffer */
        if (*tmp == '\0')  // No next message, so reset buffer
        {
            memset(buffer, '\0', BUFFER_LEN);
            bytes_in_buffer = 0;
        }
        else
        {
            /* Another message already started in buffer,
               so move it to the front of the buffer. */
            strcpy(buffer, tmp);
            bytes_in_buffer = bytes_in_buffer - (tmp - buffer);
            memset(&buffer[bytes_in_buffer], '\0',
                                (BUFFER_LEN - bytes_in_buffer));
        }
    }
}

void destroy_connection(struct chirc_connection_t *connection, struct ctx_t *ctx)
{
    struct chirc_channel_t *channel;
    struct chirc_user_t *user;
    struct chirc_server_t *server;
    /* Remove user from the ctx hash of users */
    if (connection->type == USER && connection->user != NULL)
    {
        ctx->num_direct_users--;
        user = connection->user;
        pthread_mutex_lock(&ctx->users_lock);
        if (user->is_registered)
        {
            HASH_DEL(ctx->users, user);
        }
        pthread_mutex_unlock(&ctx->users_lock);

        if (user->is_irc_operator)
        {
            ctx->num_operators--;
        }
        pthread_mutex_destroy(&user->lock);
        free(user);
    }
    else if (connection->type == SERVER && connection->server != NULL)
    {
        server = connection->server;
        ctx->num_direct_servers--;
        pthread_mutex_lock(&ctx->servers_lock);
        HASH_DEL(ctx->servers, server);
        pthread_mutex_unlock(&ctx->servers_lock);
        pthread_mutex_destroy(&server->lock);
        free(server);
    }

    ctx->num_direct_connections--;
    free(connection);
}
