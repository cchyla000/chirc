/*
 *  FILENAME: server_handler.c
 *  DESCRIPTION: Implementation of user_handler.h
 *  AUTHORS: Cameron Chyla and Artur Genser (acknowledgement to CMSC 23320)
 *  LAST DATE MODIFIED: January 30th, 2020
 */

#include <stdio.h>

#include "server_handler.h"
#include "reply.h"
#include "log.h"

/* NAME: handle_not_enough_parameters
 *
 * DESCRIPTION: Sends the ERR_NEEDMOREPARAMS response to a server if a message
 * does not have enough parameters.
 *
 * PARAMETERS:
 *  ctx - context for this server
 *  msg - message to check for proper number of parameters
 *  server - server that the message should be sent to if needed
 *  nparams - desired minimum number of parameters
 *
 * RETURN: 0 if response not sent, 1 if response sent, -1 if error with sending
 * message.
 */
static int handle_not_enough_parameters(struct ctx_t *ctx,
        struct chirc_message_t *msg, struct chirc_server_t *server, int nparams)
{
    struct chirc_message_t reply_msg;
    int error = 0;
    struct chirc_server_t *this_server = ctx->this_server;

    if (msg->nparams < nparams)  // Not enough parameters
    {
        chirc_message_construct(&reply_msg, this_server->servername,
                                ERR_NEEDMOREPARAMS);
        chirc_message_add_parameter(&reply_msg, server->servername, false);
        chirc_message_add_parameter(&reply_msg, msg->cmd, false);
        chirc_message_add_parameter(&reply_msg,
                                    "Not enough parameters", true);
        error = send_message_to_server(&reply_msg, server);
        if (error)
        {
            return -1;
        }
        else
        {
            return 1;
        }
    }
    return error;
}

/* NAME: server_complete_registration
 *
 * DESCRIPTION: Responds to a server that sends PASS and SERVER messages,
 * and registers the server if it was unregistered previously.
 *
 * PARAMETERS:
 *  ctx - context for this server
 *  server - server that has sent PASS and SERVER
 *
 * RETURN: 0 upon succesful completion, any other integer if error with sending
 */
static int server_complete_registration(struct ctx_t *ctx,
                                                 struct chirc_server_t *server)
{
    char param_buffer[MAX_MSG_LEN + 1] = {0};
    struct chirc_server_t *network_server = NULL;
    struct chirc_server_t *this_server = ctx->this_server;
    int error;
    struct chirc_message_t reply_msg;
    chirc_message_clear(&reply_msg);

    pthread_mutex_lock(&ctx->servers_lock);
    HASH_FIND_STR(ctx->servers, server->servername, network_server);
    pthread_mutex_unlock(&ctx->servers_lock);

    if (!network_server)
    {
      /* Server not in network specification file */
      chirc_message_construct(&reply_msg, this_server->servername,
                              "ERROR");
      chirc_message_add_parameter(&reply_msg,
                                  "Server not configured here", true);
      error = send_message_to_server(&reply_msg, server);
    }
    else if (network_server->is_registered)
    {
      /* Server already registered */
      chirc_message_construct(&reply_msg, this_server->servername,
                              "ERROR");
      sprintf(param_buffer, "ID \"%s\" already registered", server->servername);
      chirc_message_add_parameter(&reply_msg, param_buffer, true);
      error = send_message_to_server(&reply_msg, server);
    }
    else if (strcmp(this_server->password, server->password))
    {
        /* Incorrect password */
        server->is_registered = true;
        chirc_message_construct(&reply_msg, this_server->servername,
                                "ERROR");
        chirc_message_add_parameter(&reply_msg, "Bad password", true);
        error = send_message_to_server(&reply_msg, server);
        return error;
    }
    else
    {
        network_server->is_registered = true;
        chirc_message_construct(&reply_msg, this_server->servername,
                                "PASS");
        chirc_message_add_parameter(&reply_msg, network_server->password, false);
        chirc_message_add_parameter(&reply_msg, "0210", false);
        chirc_message_add_parameter(&reply_msg, "chirc|0.5.1", false);
        error = send_message_to_server(&reply_msg, server);

        chirc_message_construct(&reply_msg, this_server->servername,
                                "SERVER");
        chirc_message_add_parameter(&reply_msg, this_server->servername, false);
        chirc_message_add_parameter(&reply_msg, "1", false);
        chirc_message_add_parameter(&reply_msg, "chirc server", true);
        error = send_message_to_server(&reply_msg, server);

        server->is_registered = true;
        strncpy(server->password, network_server->password, MAX_PASSWORD_LEN);
        strncpy(server->port, network_server->port, MAX_PORT_LEN);

        pthread_mutex_lock(&ctx->servers_lock);
        HASH_DEL(ctx->servers, network_server);
        HASH_ADD_STR(ctx->servers, servername, server);
        pthread_mutex_unlock(&ctx->servers_lock);
        free(network_server);
    }
    return error;
}

/* NAME: forward_to_other_servers
 *
 * DESCRIPTION: Forwards a given message to other connected servers
 *
 * PARAMETERS:
 *  ctx - context for this server
 *  msg - message to be forwarded
 *  server - server that this message should not be forwarded to (usually the
 *  server that sent the message)
 *
 * RETURN: 0 upon succesful completion, any other integer if error with sending
 */
static int forward_to_other_servers(struct ctx_t *ctx,
                    struct chirc_message_t *msg, struct chirc_server_t *server)
{
    int error = 0;
    pthread_mutex_lock(&ctx->servers_lock);
    for (struct chirc_server_t *other_server = ctx->servers; other_server != NULL;
                                          other_server = other_server->hh.next)
    {
        if (other_server->is_registered && other_server != server)
        {
            error += send_message_to_server(msg, other_server);
        }
    }
    pthread_mutex_unlock(&ctx->servers_lock);
    return error;
}

int handle_NICK_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_server_t *server)
{
    forward_to_other_servers(ctx, msg, server);
    struct chirc_user_t *user = calloc(1, sizeof(struct chirc_user_t));
    struct chirc_server_t *home_server;
    pthread_mutex_init(&user->lock, NULL);

    pthread_mutex_lock(&ctx->servers_lock);
    HASH_FIND_STR(ctx->servers, msg->prefix, home_server);
    pthread_mutex_unlock(&ctx->servers_lock);
    if (!home_server)
    {
        return 0;
    }
    /* copy all information from the message to a new user in the context */
    strcpy(user->nickname, msg->params[0]);
    strcpy(user->username, msg->params[2]);
    strcpy(user->hostname, msg->params[3]);
    strcpy(user->realusername, msg->params[6]);
    user->is_registered = true;
    user->is_on_server = false;
    user->channels = NULL;
    user->server = home_server;

    pthread_mutex_lock(&ctx->users_lock);
    HASH_ADD_STR(ctx->users, nickname, user);
    pthread_mutex_unlock(&ctx->users_lock);
    return 0;
}

int handle_PRIVMSG_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                                  struct chirc_server_t *server)
{
    forward_to_other_servers(ctx, msg, server);
    struct chirc_user_t *recipient;
    struct chirc_channel_t *recipient_channel;
    struct chirc_user_cont_t *user_container;
    char buffer[MAX_MSG_LEN + 1] = {0};
    char recipient_nick[MAX_NICK_LEN + 1];
    char recipient_ch_name[MAX_CHANNEL_NAME_LEN + 1];
    strcpy(recipient_nick, msg->params[0]);
    strcpy(recipient_ch_name, msg->params[0]);
    pthread_mutex_lock(&ctx->users_lock);
    HASH_FIND_STR(ctx->users, recipient_nick, recipient);
    pthread_mutex_unlock(&ctx->users_lock);
    pthread_mutex_lock(&ctx->channels_lock);
    HASH_FIND_STR(ctx->channels, recipient_ch_name, recipient_channel);
    pthread_mutex_unlock(&ctx->channels_lock);
    if (recipient && recipient->is_on_server)
    {
        /* recipient is a user on this server, so send to them */
        send_message(msg, recipient);
    }
    else if (recipient_channel)
    {
      /* recipient is a channel, so send to all users on this server that
       * are a part of the server */
      for (user_container=recipient_channel->users; user_container != NULL;
                                     user_container=user_container->hh.next)
      {
          if (user_container->user->is_on_server)
          {
              send_message(msg, user_container->user);
          }
      }
    }
    /* If recipient is a user not on this server, this is not an error, the
     * message simply gets forwarded to other servers */
    return 0;
}

int handle_JOIN_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                                  struct chirc_server_t *server)
{
    forward_to_other_servers(ctx, msg, server);
    char channel_name[MAX_CHANNEL_NAME_LEN + 1];
    strcpy(channel_name, msg->params[0]);
    char nickname[MAX_NICK_LEN + 1];
    strcpy(nickname, msg->prefix);
    struct chirc_channel_t *channel;
    struct chirc_user_cont_t *user_container;
    pthread_mutex_lock(&ctx->channels_lock);
    HASH_FIND_STR(ctx->channels, channel_name, channel);
    pthread_mutex_unlock(&ctx->channels_lock);
    struct chirc_user_t *user = NULL;
    pthread_mutex_lock(&ctx->users_lock);
    HASH_FIND_STR(ctx->users, nickname, user);
    pthread_mutex_unlock(&ctx->users_lock);
    if (channel)
    {
        add_user_to_channel(channel, user);
    }
    else
    {
        /* Channel does not exist, create channel */
        channel = create_channel(ctx, channel_name);
        user_container = add_user_to_channel(channel, user);
        /* First user in channel should be channel operator: */
        pthread_mutex_lock(&channel->lock);
        user_container->is_channel_operator = true;
        pthread_mutex_unlock(&channel->lock);
    }
    /* Send to users on this server that are on the channel */
    for (user_container=channel->users; user_container != NULL;
                                   user_container=user_container->hh.next)
    {
        if (user_container->user->is_on_server)
        {
            send_message(msg, user_container->user);
        }
    }
    return 0;
}

int handle_PASS_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                                  struct chirc_server_t *server)
{
    int error;
    struct chirc_message_t reply_msg;
    chirc_message_clear(&reply_msg);
    struct chirc_server_t *this_server = ctx->this_server;

    if ((error = handle_not_enough_parameters(ctx, msg, server, 3)))
    {
        return error;
    }
    else if (server->is_registered)
    {
        chirc_message_construct(&reply_msg, this_server->servername,
                                ERR_ALREADYREGISTERED);
        chirc_message_add_parameter(&reply_msg, server->servername, false);
        chirc_message_add_parameter(&reply_msg, "Connection already registered",
                                                                          true);
        error = send_message_to_server(&reply_msg, server);
    }
    else
    {
        strncpy(server->password, msg->params[0], MAX_PASSWORD_LEN);

        /* Complete Registration */
        if (*server->servername != '\0')
        {
            server_complete_registration(ctx, server);
        }
    }
}

int handle_SERVER_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_server_t *server)
{
    int error;
    struct chirc_message_t reply_msg;
    chirc_message_clear(&reply_msg);
    struct chirc_server_t *this_server = ctx->this_server;

    if (server->is_registered)
    {
        chirc_message_construct(&reply_msg, this_server->servername,
                                ERR_ALREADYREGISTERED);
        chirc_message_add_parameter(&reply_msg, server->servername, false);
        chirc_message_add_parameter(&reply_msg, "Connection already registered",
                                                                          true);
        error = send_message_to_server(&reply_msg, server);
    }
    else if (msg->params[0] != NULL)
    {
        strncpy(server->servername, msg->params[0], MAX_SERVER_LEN);
        if (*server->password != '\0')
        {
            server_complete_registration(ctx, server);
        }

    }
    return 0;
}
