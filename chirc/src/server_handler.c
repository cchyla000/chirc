#include "server_handler.h"
#include "reply.h"
#include <stdio.h>
#include "log.h"

static int send_message_to_server(struct chirc_message_t *msg, struct chirc_server_t *server)
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

static int send_message(struct chirc_message_t *msg, struct chirc_user_t *user)
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

static int handle_not_registered(struct ctx_t *ctx, struct chirc_server_t *server)
{
    int error;
    struct chirc_message_t reply_msg;
    chirc_message_clear(&reply_msg);
    struct chirc_server_t *this_server = ctx->this_server;

    if (!server->is_registered)
    {
        chirc_message_construct(&reply_msg, this_server->servername,
                                ERR_NOTREGISTERED);
        chirc_message_add_parameter(&reply_msg, server->servername, false);
        chirc_message_add_parameter(&reply_msg, "You have not registered",
                                    true);
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
    return 0;
}

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

static int server_complete_registration(struct ctx_t *ctx,
             struct chirc_message_t *msg, struct chirc_server_t *server)
{
    chilog(DEBUG, "server completing registration");
    char param_buffer[MAX_MSG_LEN + 1] = {0};
    struct chirc_server_t *network_server = NULL;
    struct chirc_server_t *this_server = ctx->this_server;
    int error;
    struct chirc_message_t reply_msg;
    chirc_message_clear(&reply_msg);

    chilog(DEBUG, "Expected:");
    chilog(DEBUG, this_server->password);
    chilog(DEBUG, "Got: ");
    chilog(DEBUG, server->password);

    HASH_FIND_STR(ctx->servers, server->servername, network_server);

    if (!network_server)
    {
      /* Server not in network specification file */
      chilog(DEBUG, "server not in network file");
      chirc_message_construct(&reply_msg, this_server->servername,
                              "ERROR");
      chirc_message_add_parameter(&reply_msg,
                                  "Server not configured here", true);
      error = send_message_to_server(&reply_msg, server);
    }
    else if (network_server->is_registered)
    {
      /* Server already registered */
      chilog(DEBUG, "server already registered");
      chirc_message_construct(&reply_msg, this_server->servername,
                              "ERROR");
      sprintf(param_buffer, "ID \"%s\" already registered", server->servername);
      chirc_message_add_parameter(&reply_msg, param_buffer, true);
      error = send_message_to_server(&reply_msg, server);
    }
    else if (strcmp(this_server->password, server->password))
    {
        chilog(DEBUG, "incorrect password");
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
        chilog(DEBUG, "Sending PASS and SERVER replies");
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
        chilog(DEBUG, "Sent PASS and SERVER replies");

        server->is_registered = true;
        strncpy(server->password, network_server->password, MAX_PASSWORD_LEN);
        strncpy(server->port, network_server->port, MAX_PORT_LEN);

        HASH_DEL(ctx->servers, network_server);
        HASH_ADD_STR(ctx->servers, servername, server);
        free(network_server);
    }
    return error;
}

static int forward_to_other_servers(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_server_t *server)
{
    for (struct chirc_server_t *other_server = ctx->servers; other_server != NULL;
                                          other_server = other_server->hh.next)
    {
        if (other_server->is_registered && other_server != server)
        {
            send_message_to_server(msg, other_server);
        }
    }
}

int handle_NICK_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_server_t *server)
{
    forward_to_other_servers(ctx, msg, server);
    struct chirc_user_t *user = calloc(1, sizeof(struct chirc_user_t));
    strcpy(user->nickname, msg->params[0]);
    strcpy(user->username, msg->params[2]);
    strcpy(user->hostname, msg->params[3]);
    strcpy(user->realusername, msg->params[6]);
    user->is_registered = true;
    user->is_on_server = false;
    user->channels = NULL;
    pthread_mutex_lock(&ctx->users_lock);
    HASH_ADD_STR(ctx->users, nickname, user);
    pthread_mutex_unlock(&ctx->users_lock);
    return 0;
}

int handle_USER_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_server_t *server)
{
    return 0;
}

int handle_QUIT_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_server_t *server)
{
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
        send_message(msg, recipient);
    }
    else if (recipient_channel)
    {
      for (user_container=recipient_channel->users; user_container != NULL;
                                     user_container=user_container->hh.next)
      {
          if (user_container->user->is_on_server)
          {
              send_message(msg, user_container->user);
          }
      }
    }
    return 0;
}

int handle_NOTICE_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_server_t *server)
{
    return 0;
}

int handle_PING_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_server_t *server)
{
    return 0;
}

int handle_PONG_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_server_t *server)
{
    return 0;
}

int handle_LUSERS_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_server_t *server)
{
    return 0;
}

int handle_WHOIS_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_server_t *server)
{
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

int handle_MODE_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_server_t *server)
{
    return 0;
}

int handle_LIST_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_server_t *server)
{
    return 0;
}

int handle_OPER_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_server_t *server)
{
    return 0;
}

int handle_PART_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_server_t *server)
{
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
        chirc_message_add_parameter(&reply_msg, "Connection already registered", true);
        error = send_message_to_server(&reply_msg, server);
    }
    else
    {
        chilog(DEBUG, "About to set password");
        strncpy(server->password, msg->params[0], MAX_PASSWORD_LEN);

        /* Complete Registration */
        if (*server->servername != '\0')
        {
            server_complete_registration(ctx, msg, server);
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
        chirc_message_add_parameter(&reply_msg, "Connection already registered", true);
        error = send_message_to_server(&reply_msg, server);
    }
    else if (msg->params[0] != NULL)
    {
        chilog(DEBUG, "About to set servername");
        strncpy(server->servername, msg->params[0], MAX_SERVER_LEN);
        if (*server->password != '\0')
        {
            server_complete_registration(ctx, msg, server);
        }

    }
    return 0;
}
