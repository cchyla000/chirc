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
#include "handler.h"
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

typedef int (*handler_function)(struct ctx_t *ctx, struct chirc_message_t *msg,
                                struct chirc_user_t *connection);

struct handler_entry
{
    char *name;
    handler_function func;
};

#define HANDLER_ENTRY(NAME) { #NAME, handle_ ## NAME}

struct handler_entry handlers[] = {
                                     HANDLER_ENTRY(NICK),
                                     HANDLER_ENTRY(USER),
                                     HANDLER_ENTRY(QUIT),
                                     HANDLER_ENTRY(PRIVMSG),
                                     HANDLER_ENTRY(NOTICE),
                                     HANDLER_ENTRY(PING),
                                     HANDLER_ENTRY(PONG),
                                     HANDLER_ENTRY(LUSERS),
                                     HANDLER_ENTRY(WHOIS),
                                     HANDLER_ENTRY(JOIN),
                                     HANDLER_ENTRY(PART),
                                     HANDLER_ENTRY(PART),
                                     HANDLER_ENTRY(MODE),
                                     HANDLER_ENTRY(LIST),
                                     HANDLER_ENTRY(OPER)
                                  };

int num_handlers = sizeof(handlers) / sizeof(struct handler_entry);

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
    char buffer[BUFFER_LEN + 1] = {0};  // + 1 for extra '\0' at end
    char tosend[MAX_MSG_LEN] = {0};
    char hostname[MAX_HOST_LEN + 1] = {0};
    char nickname[MAX_NICK_LEN + 1] = "*";
    char username[MAX_USER_LEN + 1] = "*";
    char *tmp;
    char *cmd;
    int client_socket, nbytes, i, error, bytes_in_buffer = 0;

    struct chirc_user_t *user = NULL;
    struct chirc_server_t *server = NULL;

    wa = (struct worker_args*) args;
    client_socket = wa->socket;
    ctx = wa->ctx;

    /* Create user struct */
    connection = calloc(1, sizeof(struct chirc_connection_t));
    connection->type = UNKNOWN;
    connection->socket = client_socket;
    if (set_host_name(hostname, wa) == -1)
    {
        close(client_socket);
        free(wa);
        free(connection);
        pthread_exit(NULL);
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
            for(i=0; i<num_handlers; i++)
                if (!strcmp(handlers[i].name, cmd))
                {
                    error = handlers[i].func(ctx, &msg, user);
                    if (error == -1)
                    {
                        close(client_socket);
                        destroy_connection(connection, ctx);
                        free(wa);
                        pthread_exit(NULL);
                    }
                    break;
                }

            if(i == num_handlers && connection->type != UNKNOWN)
            {
                struct chirc_message_t reply_msg;
                char prefix_buffer[MAX_MSG_LEN + 1] = {0};
                chirc_message_construct(&reply_msg, 
                                        ctx->this_server->servername, 
                                        ERR_UNKNOWNCOMMAND);
                chirc_message_add_parameter(&reply_msg, nickname, false);
                sprintf(prefix_buffer, "%s :Unknown command", cmd);
                chirc_message_add_parameter(&reply_msg, prefix_buffer, false);
                int nbytes;
                char to_send[MAX_MSG_LEN + 1] = {0};
                chirc_message_to_string(&reply_msg, to_send);
                nbytes = send(client_socket, to_send, strlen(to_send), 0);
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
    struct chirc_channel_cont_t *channel_container;
    struct chirc_user_t *user;

    /* Remove user from the ctx hash of users */
    if (connection->type == USER)
    {
        user = connection->user;
        pthread_mutex_lock(&user->lock);
        pthread_mutex_lock(&ctx->users_lock);

        if (user->is_irc_operator)
        {
            ctx->num_operators--;
        }

        if (user->is_registered)
        {
            HASH_DEL(ctx->users, user);
        }
        pthread_mutex_unlock(&ctx->users_lock);

        /* Remove user from all of the channels it is in */

        for (channel_container=user->channels; channel_container != NULL;
                                channel_container = channel_container->hh.next)
        {
            channel = find_channel_in_user(ctx, user, channel_container->channel_name);
            remove_user_from_channel(channel, user);
            if (channel->nusers == 0)
            {
                destroy_channel(ctx, channel);
            }
        }
        pthread_mutex_unlock(&user->lock);
        pthread_mutex_destroy(&user->lock);
        free(user);
    }
    else if (connection->type == SERVER)
    {

    }

    ctx->num_clients--;
    free(connection);

}
