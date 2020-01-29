#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>

#include "user_handler.h"
#include "channel.h"
#include "log.h"
#include "reply.h"
#include "connection.h"

#define MAX_MSG_LEN 512
#define MAX_HOST_LEN 63

#define IRC_VERSION "2.10"

/* Sends messages and does error checking; terminates
 * thread and destroys user if error in sending detected */
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

static int send_nick_to_servers(struct ctx_t *ctx, struct chirc_user_t *user)
{
    struct chirc_message_t msg;
    chirc_message_clear(&msg);
    struct chirc_server_t *server = ctx->this_server;
    chirc_message_construct(&msg, server->servername, "NICK");
    chirc_message_add_parameter(&msg, user->nickname, false);
    chirc_message_add_parameter(&msg, "1", false);
    chirc_message_add_parameter(&msg, user->username, false);
    chirc_message_add_parameter(&msg, user->hostname, false);
    chirc_message_add_parameter(&msg, "1", false);
    chirc_message_add_parameter(&msg, "+", false);
    chirc_message_add_parameter(&msg, user->realusername, true);
    pthread_mutex_lock(&ctx->servers_lock);
    for (server = ctx->servers; server != NULL; server = server->hh.next)
    {
        if (server->is_registered)
        {
            send_message_to_server(&msg, server);
        }
    }
    pthread_mutex_unlock(&ctx->servers_lock);
}

/* Sends Replies 001 to 004 to specified user upon successful registration */
static int send_welcome_messages(struct ctx_t *ctx, struct chirc_user_t *user)
{
    send_nick_to_servers(ctx, user);
    char param_buffer[MAX_MSG_LEN + 1] = {0};
    struct chirc_message_t msg;
    int error;
    struct chirc_server_t *server = ctx->this_server;
    chirc_message_clear (&msg);

    /* Send RPL_WELCOME: */
    chirc_message_construct(&msg, server->servername, RPL_WELCOME);
    chirc_message_add_parameter(&msg, user->nickname, false);
    sprintf(param_buffer, "Welcome to the Internet Relay Network %s!%s@%s",
                                user->nickname, user->username, user->hostname);
    chirc_message_add_parameter(&msg, param_buffer, true);
    error = send_message(&msg, user);
    if (error)
    {
        return error;
    }
    chirc_message_clear(&msg);

    /* Send RPL_YOURHOST: */
    chirc_message_construct(&msg, server->servername, RPL_YOURHOST);
    chirc_message_add_parameter(&msg, user->nickname, false);
    sprintf(param_buffer, "Your host is %s, running version %s",
            server->servername, IRC_VERSION);
    chirc_message_add_parameter(&msg, param_buffer, true);
    error = send_message(&msg, user);
    if (error)
    {
        return error;
    }
    chirc_message_clear(&msg);

    /* Send RPL_CREATED: */
    chirc_message_construct(&msg, server->servername, RPL_CREATED);
    chirc_message_add_parameter(&msg, user->nickname, false);
    sprintf(param_buffer, "This server was created %s",
            ctx->date_created);
    chirc_message_add_parameter(&msg, param_buffer, true);
    error = send_message(&msg, user);
    if (error)
    {
        return error;
    }
    chirc_message_clear(&msg);

    /* Send RPL_MYINFO: */
    chirc_message_construct(&msg, server->servername, RPL_MYINFO);
    chirc_message_add_parameter(&msg, user->nickname, false);
    chirc_message_add_parameter(&msg, server->servername, false);
    chirc_message_add_parameter(&msg, IRC_VERSION, false);
    chirc_message_add_parameter(&msg, "ao", false);
    chirc_message_add_parameter(&msg, "mtov", false);
    error = send_message(&msg, user);
    if (error)
    {
        return error;
    }
    chirc_message_clear(&msg);

    pthread_mutex_lock(&ctx->users_lock);
    int registered_users = HASH_COUNT(ctx->users);
    int unknown_clients = ctx->unknown_clients;
    int connected_clients = ctx->connected_clients;
    pthread_mutex_unlock(&ctx->users_lock);

    /* RPL_LUSERCLIENT */
    chirc_message_construct(&msg, server->servername, RPL_LUSERCLIENT);
    chirc_message_add_parameter(&msg, user->nickname, false);
    sprintf(param_buffer, "There are %d users and %d services on %d servers",
                                                        registered_users, 0, 1);
    chirc_message_add_parameter(&msg, param_buffer, true);
    error = send_message(&msg, user);
    if (error)
    {
        return error;
    }
    chirc_message_clear(&msg);

    /* Send RPL_LUSEROP */
    chirc_message_construct(&msg, server->servername, RPL_LUSEROP);
    chirc_message_add_parameter(&msg, user->nickname, false);
    chirc_message_add_parameter(&msg, "0", false);
    chirc_message_add_parameter(&msg, "operator(s) online", true);
    error = send_message(&msg, user);
    if (error)
    {
        return error;
    }
    chirc_message_clear(&msg);

    /* Send RPL_LUSERUNKNOWN */
    chirc_message_construct(&msg, server->servername, RPL_LUSERUNKNOWN);
    chirc_message_add_parameter(&msg, user->nickname, false);
    sprintf(param_buffer, "%d", unknown_clients);
    chirc_message_add_parameter(&msg, param_buffer, false);
    chirc_message_add_parameter(&msg, "unknown connection(s)", true);
    error = send_message(&msg, user);
    if (error)
    {
        return error;
    }
    chirc_message_clear(&msg);

    /* Send RPL_LUSERCHANNELS */
    chirc_message_construct(&msg, server->servername, RPL_LUSERCHANNELS);
    chirc_message_add_parameter(&msg, user->nickname, false);

    pthread_mutex_lock(&ctx->channels_lock);
    int num_channels = HASH_COUNT(ctx->channels);
    pthread_mutex_unlock(&ctx->channels_lock);

    sprintf(param_buffer, "%d", num_channels);
    chirc_message_add_parameter(&msg, param_buffer, false);
    chirc_message_add_parameter(&msg, "channels formed", true);
    error = send_message(&msg, user);
    if (error)
    {
        return error;
    }
    chirc_message_clear(&msg);

    /* Send RPL_LUSERME */
    chirc_message_construct(&msg, server->servername, RPL_LUSERME);
    chirc_message_add_parameter(&msg, user->nickname, false);
    sprintf(param_buffer, "I have %d clients and 1 servers",
            connected_clients);
    chirc_message_add_parameter(&msg, param_buffer, true);
    error = send_message(&msg, user);
    if (error)
    {
        return error;
    }
    chirc_message_clear(&msg);

    /* Send MOTD */
    chirc_message_construct(&msg, server->servername, ERR_NOMOTD);
    chirc_message_add_parameter(&msg, user->nickname, false);
    chirc_message_add_parameter(&msg, "MOTD File is missing", true);
    error = send_message(&msg, user);
    if (error)
    {
        return error;
    }


    return 0;
}

/* Given a user, sends the ERR_NOTREGISTERED response to them */
static int handle_not_registered(struct ctx_t *ctx, struct chirc_user_t *user)
{
    int error;
    struct chirc_message_t reply_msg;
    struct chirc_server_t *server = ctx->this_server;
    chirc_message_clear(&reply_msg);

    if (!user->is_registered)
    {
        chirc_message_construct(&reply_msg, server->servername,
                                ERR_NOTREGISTERED);
        chirc_message_add_parameter(&reply_msg, user->nickname, false);
        chirc_message_add_parameter(&reply_msg, "You have not registered",
                                    true);
        error = send_message(&reply_msg, user);
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

/* Given a user, a message, and the desired number of parameters, sends the
 * ERR_NEEDMOREPARAMS response to the user if the message does not have
 * enough parameters. */
static int handle_not_enough_parameters(struct ctx_t *ctx,
            struct chirc_message_t *msg, struct chirc_user_t *user, int nparams)
{
    struct chirc_message_t reply_msg;
    int error = 0;
    struct chirc_server_t *server = ctx->this_server;

    if (msg->nparams < nparams)  // Not enough parameters
    {
        chirc_message_construct(&reply_msg, server->servername,
                                ERR_NEEDMOREPARAMS);
        chirc_message_add_parameter(&reply_msg, user->nickname, false);
        chirc_message_add_parameter(&reply_msg, msg->cmd, false);
        chirc_message_add_parameter(&reply_msg,
                                    "Not enough parameters", true);
        error = send_message(&reply_msg, user);
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

/* Forwards message with prefix to the given recipient user or all users on
 * a recipient channel. Used by PRIVMSG and NOTICE. */
static int forward_message_to_user_or_channel(struct ctx_t *ctx,
  struct chirc_message_t *msg, struct chirc_user_t *user,
  struct chirc_user_t *recipient, struct chirc_channel_t *recipient_channel)
{
    struct chirc_message_t local_msg; // message that gets sent to users on server
    chirc_message_clear(&local_msg);
    char local_buffer[MAX_MSG_LEN + 1] = {0};
    struct chirc_message_t outgoing_msg; // message that gets sent to connected servers
    chirc_message_clear(&outgoing_msg);

    sprintf(local_buffer, "%s!%s@%s", user->nickname, user->username, user->hostname);
    chirc_message_construct(&local_msg, local_buffer, msg->cmd);
    chirc_message_construct(&outgoing_msg, user->nickname, msg->cmd);
    for (int i = 0; i < msg->nparams - 1; i++)
    {
        chirc_message_add_parameter(&local_msg, msg->params[i], false);
        chirc_message_add_parameter(&outgoing_msg, msg->params[i], false);
    }
    chirc_message_add_parameter(&local_msg, msg->params[msg->nparams - 1], true);
    chirc_message_add_parameter(&outgoing_msg, msg->params[msg->nparams - 1], true);
    if (recipient)
    {
        if (recipient->is_on_server)
        {
            send_message(&local_msg, recipient);
        }
        else
        {
            pthread_mutex_lock(&ctx->servers_lock);
            for (struct chirc_server_t *server = ctx->servers; server != NULL; server = server->hh.next)
            {
                if (server->is_registered)
                {
                    send_message_to_server(&outgoing_msg, server);
                }
            }
            pthread_mutex_unlock(&ctx->servers_lock);
        }
    }
    else
    {
        /* Recipient is a channel, so send to all members of the channel
         * and connected servers */
        struct chirc_user_t *user_in_channel;
        struct chirc_user_cont_t *user_container;
        struct chirc_server_t *server;
        pthread_mutex_lock(&recipient_channel->lock);
        for (user_container=recipient_channel->users; user_container != NULL;
                                       user_container=user_container->hh.next)
        {
            if (user_container->user->is_on_server)
            {
                send_message(&local_msg, user_container->user);
            }
        }
        pthread_mutex_lock(&ctx->servers_lock);
        for (server = ctx->servers; server != NULL; server = server->hh.next)
        {
            if (server->is_registered)
            {
                send_message_to_server(&outgoing_msg, server);
            }
        }
        pthread_mutex_unlock(&ctx->servers_lock);
        pthread_mutex_unlock(&recipient_channel->lock);
    }
}

int handle_NICK_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                                      struct chirc_user_t *user)
{
    char nick[MAX_NICK_LEN + 1];
    struct chirc_user_t *found_user;
    struct chirc_message_t reply_msg;
    struct chirc_server_t *server = ctx->this_server;
    chirc_message_clear (&reply_msg);
    int error = 0;
    char param_buffer[MAX_MSG_LEN] = {0};

    if (msg->nparams < 1)  // No nickname given
    {
        chirc_message_construct(&reply_msg, server->servername,
                                ERR_NONICKNAMEGIVEN);
        chirc_message_add_parameter(&reply_msg, user->nickname, false);
        chirc_message_add_parameter(&reply_msg, "No nickname given", true);
        error = send_message(&reply_msg, user);
        return error;
    }

    strncpy(nick, msg->params[0], MAX_NICK_LEN);
    HASH_FIND_STR(ctx->users, nick, found_user);

    if (found_user)  // Nickname already in use
    {
        chirc_message_construct(&reply_msg, server->servername,
                                ERR_NICKNAMEINUSE);
        chirc_message_add_parameter(&reply_msg, user->nickname, false);
        chirc_message_add_parameter(&reply_msg, nick, false);
        chirc_message_add_parameter(&reply_msg, "Nickname is already in use",
                                    true);
        error = send_message(&reply_msg, user);
    }
    else if (user->is_registered)
    {
        sprintf(param_buffer, "%s!%s@%s", user->nickname, user->username,
                user->hostname);
        chirc_message_construct(&reply_msg, param_buffer, "NICK");
        chirc_message_add_parameter(&reply_msg, nick, true);
        // Must send this message to all channels that user is in...
        struct chirc_channel_t *channel;
        struct chirc_channel_cont_t *channel_container;
        struct chirc_user_t *user_in_channel;
        struct chirc_user_cont_t*user_container;
        for (channel_container=user->channels; channel_container != NULL;
                                channel_container = channel_container->hh.next)
        {
            channel = find_channel_in_user(ctx, user,
                                              channel_container->channel_name);
            pthread_mutex_lock(&channel->lock);
            for (user_container=channel->users; user_container != NULL;
                                        user_container=user_container->hh.next)
            {
                pthread_mutex_unlock(&channel->lock);
                user_in_channel = find_user_in_channel(ctx, channel,
                                                      user_container->nickname);
                pthread_mutex_lock(&channel->lock);
                send_message(&reply_msg, user_in_channel);
            }
            pthread_mutex_unlock(&channel->lock);
        }

        pthread_mutex_lock(&ctx->users_lock);
        pthread_mutex_lock(&user->lock);
        HASH_DEL(ctx->users, user);
        strcpy(user->nickname, nick);
        HASH_ADD_STR(ctx->users, nickname, user);
        pthread_mutex_unlock(&user->lock);
        pthread_mutex_unlock(&ctx->users_lock);

    }
    else  // User not registered
    {
        strcpy(user->nickname, nick);

        if (*user->username)  // Registration complete
        {
            chilog(DEBUG, "About to add user to hash");
            user->is_registered = true;
            user->is_on_server = true;
            pthread_mutex_lock(&ctx->users_lock);
            HASH_ADD_STR(ctx->users, nickname, user);
            pthread_mutex_unlock(&ctx->users_lock);
            error = send_welcome_messages(ctx, user);
        }
    }
    return error;
}

int handle_USER_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                struct chirc_user_t *user)
{
    char user_buffer[MAX_MSG_LEN] = {0};
    struct chirc_message_t reply_msg;
    chirc_message_clear (&reply_msg);
    struct chirc_server_t *server = ctx->this_server;
    int error = 0;

    if ((error = handle_not_enough_parameters(ctx, msg, user, 4)))
    {
        return error;
    }
    else if (user->is_registered)
    {
        chirc_message_construct(&reply_msg, server->servername,
                                ERR_ALREADYREGISTERED);
        chirc_message_add_parameter(&reply_msg, user->nickname, false);
        chirc_message_add_parameter(&reply_msg, "Unauthorized command "
                                    "(already registered)", true);
        error = send_message(&reply_msg, user);
    }
    else  // User not registered
    {
        strcpy(user->username, msg->params[0]);
        strncpy(user->realusername, msg->params[3], MAX_HOST_LEN);
        if (*user->nickname)  // Registration complete
        {
            user->is_registered = true;
            user->is_on_server = true;
            pthread_mutex_lock(&ctx->users_lock);
            HASH_ADD_STR(ctx->users, nickname, user);
            pthread_mutex_unlock(&ctx->users_lock);
            error = send_welcome_messages(ctx, user);
        }
    }

    return error;

}

int handle_QUIT_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                                      struct chirc_user_t *user)
{
    int error;
    struct chirc_server_t *server = ctx->this_server;
    struct chirc_message_t reply_msg;
    struct chirc_message_t reply_msg_to_user;
    chirc_message_clear (&reply_msg);
    char param_buffer[MAX_MSG_LEN + 1] = {0};
    char param_buffer_user[MAX_MSG_LEN + 1] = {0};
    char prefix_buffer[MAX_MSG_LEN + 1] = {0};
    sprintf(prefix_buffer, "%s!%s@%s", user->nickname, user->username,
                                                                user->hostname);

    chirc_message_construct(&reply_msg, prefix_buffer, "QUIT");
    chirc_message_construct(&reply_msg_to_user, prefix_buffer, "ERROR");
    if (msg->nparams < 1)
    {
        sprintf(param_buffer, "Client Quit");
        chirc_message_add_parameter(&reply_msg, param_buffer, true);
        sprintf(param_buffer_user, "Closing Link: %s (Client Quit)",
                                                                user->hostname);
        chirc_message_add_parameter(&reply_msg_to_user, param_buffer_user, true);
    }
    else
    {
        sprintf(param_buffer, "%s", msg->params[0]);
        chirc_message_add_parameter(&reply_msg, param_buffer, true);
        sprintf(param_buffer_user, "Closing Link: %s (%s)", user->hostname,
                msg->params[0]);
        chirc_message_add_parameter(&reply_msg_to_user, param_buffer_user, true);
    }

    struct chirc_channel_t *channel;
    struct chirc_channel_cont_t *channel_container;
    struct chirc_user_t *user_in_channel;
    struct chirc_user_cont_t*user_container;
    for (channel_container=user->channels; channel_container != NULL;
                            channel_container = channel_container->hh.next)
    {
        channel = find_channel_in_user(ctx, user, channel_container->channel_name);
        pthread_mutex_lock(&channel->lock);
        for (user_container=channel->users; user_container != NULL;
                                       user_container=user_container->hh.next)
        {
            pthread_mutex_unlock(&channel->lock);
            user_in_channel = find_user_in_channel(ctx, channel,
                                                  user_container->nickname);
            pthread_mutex_lock(&channel->lock);
            if (user != user_in_channel)
            {
                send_message(&reply_msg, user_in_channel);
            }
        }
        pthread_mutex_unlock(&channel->lock);
    }
    send_message(&reply_msg_to_user, user);
    return -1;  // return error code so user is destroyed and exits
}

int handle_PRIVMSG_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                                      struct chirc_user_t *user)
{
    int error;
    struct chirc_server_t *server = ctx->this_server;
    if ((error = handle_not_registered(ctx, user)))
    {
        return error;
    }
    struct chirc_message_t reply_msg;
    chirc_message_clear(&reply_msg);
    if (msg->nparams == 0) // No parameters, so no recipient given
    {
        chirc_message_construct(&reply_msg, server->servername,
                                ERR_NORECIPIENT);
        chirc_message_add_parameter(&reply_msg, user->nickname, false);
        chirc_message_add_parameter(&reply_msg,
                                    ":No recipient given (PRIVMSG)", false);
        error = send_message(&reply_msg, user);
        if (error)
        {
            return -1;
        }
        else
        {
            return 1;
        }
    }
    if (msg->nparams == 1) // Only one parameter, so no text given
    {
        chirc_message_construct(&reply_msg, server->servername,
                                ERR_NOTEXTTOSEND);
        chirc_message_add_parameter(&reply_msg, user->nickname, false);
        chirc_message_add_parameter(&reply_msg,
                                    ":No text to send", false);
        error = send_message(&reply_msg, user);
        if (error)
        {
            return -1;
        }
        else
        {
            return 1;
        }
    }
    /* Check if the first parameter is a user, a channel, and if the sender is a
     * member of the channel. */
    struct chirc_user_t *recipient;
    struct chirc_channel_t *recipient_channel;
    struct chirc_channel_t *channel_exists;
    char buffer[MAX_MSG_LEN + 1] = {0};
    char recipient_nick[MAX_NICK_LEN + 1];
    char recipient_ch_name[MAX_CHANNEL_NAME_LEN + 1];
    strcpy(recipient_nick, msg->params[0]);
    strcpy(recipient_ch_name, msg->params[0]);
    pthread_mutex_lock(&ctx->users_lock);
    HASH_FIND_STR(ctx->users, recipient_nick, recipient);
    pthread_mutex_unlock(&ctx->users_lock);
    recipient_channel = find_channel_in_user(ctx, user, recipient_ch_name);
    pthread_mutex_lock(&ctx->channels_lock);
    HASH_FIND_STR(ctx->channels, recipient_ch_name, channel_exists);
    pthread_mutex_unlock(&ctx->channels_lock);
    if (recipient || recipient_channel)
    {
        /* First parameter is either a user that exists or a channel that sender
         * is a member of */
        forward_message_to_user_or_channel(ctx, msg, user, recipient,
                                                            recipient_channel);
    }
    else if (channel_exists)
    {
        /* Channel exists in the context, but user is not a member */
        chirc_message_construct(&reply_msg, server->servername, ERR_CANNOTSENDTOCHAN);
        chirc_message_add_parameter(&reply_msg, user->nickname, false);
        sprintf(buffer, "%s :Cannot send to channel", recipient_ch_name);
        chirc_message_add_parameter(&reply_msg, buffer, false);
        send_message(&reply_msg, user);
        if (error)
        {
            return -1;
        }
        else
        {
            return 1;
        }
    }
    else
    {
        /* A channel or user could not be found of the given name */
        chirc_message_construct(&reply_msg, server->servername, ERR_NOSUCHNICK);
        chirc_message_add_parameter(&reply_msg, user->nickname, false);
        sprintf(buffer, "%s :No such nick/channel", recipient_ch_name);
        chirc_message_add_parameter(&reply_msg, buffer, false);
        error = send_message(&reply_msg, user);
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

int handle_NOTICE_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                                      struct chirc_user_t *user)
{
    /* The same as PRIVMSG, but with no replies sent to the sender */
    int error;
    struct chirc_server_t *server = ctx->this_server;
    if ((error = handle_not_registered(ctx, user)))
    {
        return error;
    }
    if (msg->nparams == 0 || msg->nparams == 1)
    {
        return 1;
    }
    struct chirc_user_t *recipient;
    struct chirc_channel_t *recipient_channel;
    char recipient_nick[MAX_NICK_LEN + 1];
    char recipient_ch_name[MAX_CHANNEL_NAME_LEN + 1];
    strcpy(recipient_nick, msg->params[0]);
    strcpy(recipient_ch_name, msg->params[0]);
    pthread_mutex_lock(&ctx->users_lock);
    HASH_FIND_STR(ctx->users, recipient_nick, recipient);
    pthread_mutex_unlock(&ctx->users_lock);
    recipient_channel = find_channel_in_user(ctx, user, recipient_ch_name);
    if (recipient || recipient_channel)
    {
        forward_message_to_user_or_channel(ctx, msg, user, recipient,
                                                            recipient_channel);
    }
    return 0;
}

int handle_PING_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                                      struct chirc_user_t *user)
{
    int error = handle_not_registered(ctx, user);
    struct chirc_server_t *server = ctx->this_server;
    if (error)
    {
        return error;
    }

    struct chirc_message_t reply_msg;
    chirc_message_clear(&reply_msg);

    chirc_message_construct(&reply_msg, NULL, "PONG");
    chirc_message_add_parameter(&reply_msg, server->servername, false);
    error = send_message(&reply_msg, user);
    if (error)
    {
        return error;
    }

    return 0;
}

int handle_PONG_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                                      struct chirc_user_t *user)
{
    int error = handle_not_registered(ctx, user);
    struct chirc_server_t *server = ctx->this_server;
    if (error)
    {
        return error;
    }
    return 0;
}

int handle_LUSERS_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                                      struct chirc_user_t *user)
{
    int error = handle_not_registered(ctx, user);
    struct chirc_server_t *server = ctx->this_server;
    if (error)
    {
        return error;
    }

    struct chirc_message_t reply_msg;
    chirc_message_clear(&reply_msg);
    char param_buffer[MAX_MSG_LEN + 1] = {0};
    chirc_message_construct(&reply_msg, server->servername, RPL_LUSERCLIENT);
    chirc_message_add_parameter(&reply_msg, user->nickname, false);

    pthread_mutex_lock(&ctx->users_lock);
    int registered_users = HASH_COUNT(ctx->users);
    int unknown_clients = ctx->unknown_clients;
    int connected_clients = ctx->connected_clients;
    pthread_mutex_unlock(&ctx->users_lock);

    sprintf(param_buffer, "There are %d users and %d services on %d servers",
                                                        registered_users, 0, 1);

    chirc_message_add_parameter(&reply_msg, param_buffer, true);
    error = send_message(&reply_msg, user);
    if (error)
    {
        return error;
    }
    chirc_message_clear(&reply_msg);

    /* Send RPL_LUSEROP */
    chirc_message_construct(&reply_msg, server->servername, RPL_LUSEROP);
    chirc_message_add_parameter(&reply_msg, user->nickname, false);
    chirc_message_add_parameter(&reply_msg, "0", false);
    chirc_message_add_parameter(&reply_msg, "operator(s) online", true);
    error = send_message(&reply_msg, user);
    if (error)
    {
        return error;
    }
    chirc_message_clear(&reply_msg);

    /* Send RPL_LUSERUNKNOWN */
    chirc_message_construct(&reply_msg, server->servername, RPL_LUSERUNKNOWN);
    chirc_message_add_parameter(&reply_msg, user->nickname, false);
    sprintf(param_buffer, "%d", unknown_clients);
    chirc_message_add_parameter(&reply_msg, param_buffer, false);
    chirc_message_add_parameter(&reply_msg, "unknown connection(s)", true);
    error = send_message(&reply_msg, user);
    if (error)
    {
        return error;
    }
    chirc_message_clear(&reply_msg);

    /* Send RPL_LUSERCHANNELS */
    chirc_message_construct(&reply_msg, server->servername, RPL_LUSERCHANNELS);
    chirc_message_add_parameter(&reply_msg, user->nickname, false);
    pthread_mutex_lock(&ctx->channels_lock);
    int num_channels = HASH_COUNT(ctx->channels);
    pthread_mutex_unlock(&ctx->channels_lock);
    sprintf(param_buffer, "%d", num_channels);
    chirc_message_add_parameter(&reply_msg, param_buffer, false);
    chirc_message_add_parameter(&reply_msg, "channels formed", true);
    error = send_message(&reply_msg, user);
    if (error)
    {
        return error;
    }
    chirc_message_clear(&reply_msg);

    /* Send RPL_LUSERME */
    chirc_message_construct(&reply_msg, server->servername, RPL_LUSERME);
    chirc_message_add_parameter(&reply_msg, user->nickname, false);
    sprintf(param_buffer, "I have %d clients and 1 servers",
            registered_users);
    chirc_message_add_parameter(&reply_msg, param_buffer, true);
    error = send_message(&reply_msg, user);
    if (error)
    {
        return error;
    }
    return 0;
}

int handle_WHOIS_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                                      struct chirc_user_t *user)
{
    int error = handle_not_registered(ctx, user);
    struct chirc_server_t *server = ctx->this_server;
    if (error)
    {
        return error;
    }

    struct chirc_user_t *found_user;
    struct chirc_message_t reply_msg;
    chirc_message_clear(&reply_msg);

    if (msg->nparams < 1)  // Assignment says to ignore for now...
    {
        return 0;
    }

    /* Since we are dealing with a pointer to found_user, we
       cannot unlock until we are done accessing all of its fields. */
    pthread_mutex_lock(&ctx->users_lock);
    HASH_FIND_STR(ctx->users, msg->params[0], found_user);

    if (!found_user)
    {
        pthread_mutex_unlock(&ctx->users_lock);
        chirc_message_construct(&reply_msg, server->servername, ERR_NOSUCHNICK);
        chirc_message_add_parameter(&reply_msg, user->nickname, false);
        chirc_message_add_parameter(&reply_msg, msg->params[0], false);
        chirc_message_add_parameter(&reply_msg, "No such nick/channel", true);
        error = send_message(&reply_msg, user);
        if (error)
        {
            return error;
        }
    }
    else
    {
        /* RPL_WHOISUSER */
        chirc_message_construct(&reply_msg, server->servername, RPL_WHOISUSER);
        chirc_message_add_parameter(&reply_msg, user->nickname, false);
        chirc_message_add_parameter(&reply_msg, msg->params[0], false);
        chirc_message_add_parameter(&reply_msg, found_user->nickname, false);
        chirc_message_add_parameter(&reply_msg, found_user->username, false);
        chirc_message_add_parameter(&reply_msg, found_user->hostname, false);
        chirc_message_add_parameter(&reply_msg, found_user->realusername, true);
        error = send_message(&reply_msg, user);
        if (error)
        {
            pthread_mutex_unlock(&ctx->users_lock);
            return error;
        }
        chirc_message_clear(&reply_msg);

        /* RPL_WHOISSERVER */
        chirc_message_construct(&reply_msg, server->servername, RPL_WHOISSERVER);
        chirc_message_add_parameter(&reply_msg, user->nickname, false);
        chirc_message_add_parameter(&reply_msg, msg->params[0], false);
        chirc_message_add_parameter(&reply_msg, server->servername, false);
        chirc_message_add_parameter(&reply_msg, "server info", true);
        error = send_message(&reply_msg, user);
        if (error)
        {
            pthread_mutex_unlock(&ctx->users_lock);
            return error;
        }
        chirc_message_clear(&reply_msg);

        /* RPL_ENDOFWHOIS */
        chirc_message_construct(&reply_msg, server->servername, RPL_ENDOFWHOIS);
        chirc_message_add_parameter(&reply_msg, user->nickname, false);
        chirc_message_add_parameter(&reply_msg, msg->params[0], false);
        chirc_message_add_parameter(&reply_msg, "End of WHOIS list", true);
        error = send_message(&reply_msg, user);
        if (error)
        {
            pthread_mutex_unlock(&ctx->users_lock);
            return error;
        }

    }

    pthread_mutex_unlock(&ctx->users_lock);
    return 0;
}

int handle_JOIN_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                                      struct chirc_user_t *user)
{
    int error;
    struct chirc_server_t *server = ctx->this_server;
    if ((error = (handle_not_registered(ctx, user))) ||
                  (error = (handle_not_enough_parameters(ctx, msg, user, 1))))
    {
        return error;
    }
    struct chirc_channel_t *channel;
    struct chirc_message_t local_msg; // message that gets sent to users on server
    chirc_message_clear(&local_msg);
    char local_buffer[MAX_MSG_LEN + 1] = {0};
    struct chirc_message_t outgoing_msg; // message that gets sent to connected servers
    chirc_message_clear(&outgoing_msg);
    char channel_name[MAX_CHANNEL_NAME_LEN + 1];
    strcpy(channel_name, msg->params[0]);
    pthread_mutex_lock(&ctx->channels_lock);
    HASH_FIND_STR(ctx->channels, channel_name, channel);
    pthread_mutex_unlock(&ctx->channels_lock);

    struct chirc_user_t *user_in_channel;
    struct chirc_user_cont_t *user_container;
    struct chirc_server_t *server_other;
    if (channel)
    {
        /* channel exists, check if user in channel
         * and ignore if they are */
        user_in_channel = find_user_in_channel(ctx, channel, user->nickname);
        if (user_in_channel)
        {
            return 0;
        }
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

    /* Send JOIN message to everyone on channel and other servers */
    sprintf(local_buffer, "%s!%s@%s", user->nickname, user->username, user->hostname);
    chirc_message_construct(&local_msg, local_buffer, msg->cmd);
    chirc_message_construct(&outgoing_msg, user->nickname, msg->cmd);
    for (int i = 0; i < msg->nparams; i++)
    {
        chirc_message_add_parameter(&local_msg, msg->params[i], false);
        chirc_message_add_parameter(&outgoing_msg, msg->params[i], false);
    }
    pthread_mutex_lock(&channel->lock);
    for (user_container=channel->users; user_container != NULL;
                                   user_container=user_container->hh.next)
    {
        if (user_container->user->is_on_server)
        {
            send_message(&local_msg, user_container->user);
        }
    }
    for (server_other = ctx->servers; server_other != NULL; server_other = server_other->hh.next)
    {
        if (server_other->is_registered)
        {
            send_message_to_server(&outgoing_msg, server_other);
        }
    }
    pthread_mutex_unlock(&channel->lock);
    chirc_message_clear(&local_msg);

    /* Send list of member users to user that is joining */
    chirc_message_construct(&local_msg, server->servername, RPL_NAMREPLY);
    chirc_message_add_parameter(&local_msg, user->nickname, false);
    chirc_message_add_parameter(&local_msg, "=", false);
    chirc_message_add_parameter(&local_msg, channel->channel_name, false);
    pthread_mutex_lock(&channel->lock);
    char nicks_buffer[MAX_MSG_LEN + 1] = {0};
    for (user_container = channel->users; user_container != NULL;
                                    user_container = user_container->hh.next)
    {
        sprintf(nicks_buffer, "%s", user_container->nickname);
    }
    chirc_message_add_parameter(&local_msg, nicks_buffer, true);
    pthread_mutex_unlock(&channel->lock);
    error = send_message(&local_msg, user);
    if (error)
    {
        return -1;
    }
    chirc_message_clear(&local_msg);
    chirc_message_construct(&local_msg, server->servername, RPL_ENDOFNAMES);
    chirc_message_add_parameter(&local_msg, user->nickname, false);
    pthread_mutex_lock(&channel->lock);
    chirc_message_add_parameter(&local_msg, channel->channel_name, false);
    pthread_mutex_unlock(&channel->lock);
    chirc_message_add_parameter(&local_msg, "End of NAMES list", true);
    error = send_message(&local_msg, user);
    if (error)
    {
        return -1;
    }
    chirc_message_clear(&local_msg);

    return 0;
}

int handle_PART_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                                      struct chirc_user_t *user)
{
    int error;
    struct chirc_server_t *server = ctx->this_server;
    if ((error = (handle_not_registered(ctx, user))) ||
                  (error = (handle_not_enough_parameters(ctx, msg, user, 1))))
    {
        return error;
    }
    /* Check if channel exists and that the user is a member of it */
    struct chirc_message_t reply_msg;
    chirc_message_clear(&reply_msg);
    struct chirc_channel_t *recipient_channel;
    struct chirc_channel_t *channel_exists;
    char buffer[MAX_MSG_LEN + 1] = {0};
    char recipient_ch_name[MAX_CHANNEL_NAME_LEN + 1];
    strcpy(recipient_ch_name, msg->params[0]);
    recipient_channel = find_channel_in_user(ctx, user, recipient_ch_name);
    pthread_mutex_lock(&ctx->channels_lock);
    HASH_FIND_STR(ctx->channels, recipient_ch_name, channel_exists);
    pthread_mutex_unlock(&ctx->channels_lock);
    if (recipient_channel)
    {
        /* Channel exists and user is a member, so forward message to channel */
        sprintf(buffer, "%s!%s@%s", user->nickname, user->username, user->hostname);
        chirc_message_construct(&reply_msg, buffer, msg->cmd);

        for (int i = 0; i < msg->nparams - 1; i++)
        {
            chirc_message_add_parameter(&reply_msg, msg->params[i], false);
        }
        chirc_message_add_parameter(&reply_msg, msg->params[msg->nparams - 1], true);
        reply_msg.longlast = msg->longlast;

        struct chirc_user_t *user_in_channel;
        struct chirc_user_cont_t *user_container;
        pthread_mutex_lock(&recipient_channel->lock);
        for (user_container=recipient_channel->users; user_container != NULL;
                                       user_container=user_container->hh.next)
        {
            pthread_mutex_unlock(&recipient_channel->lock);
            user_in_channel = find_user_in_channel(ctx, recipient_channel,
                                                  user_container->nickname);
            pthread_mutex_lock(&recipient_channel->lock);
            send_message(&reply_msg, user_in_channel);
        }
        pthread_mutex_unlock(&recipient_channel->lock);

        remove_user_from_channel(recipient_channel, user);
        if (recipient_channel->nusers == 0)
        {
            /* If user is the last user in the channel, destroy the channel */
            destroy_channel(ctx, recipient_channel);
        }
    }
    else if (channel_exists)
    {
        /* Channel exists, but user is not a member */
        chirc_message_construct(&reply_msg, server->servername, ERR_NOTONCHANNEL);
        chirc_message_add_parameter(&reply_msg, user->nickname, false);
        sprintf(buffer, "%s :You're not on that channel", recipient_ch_name);
        chirc_message_add_parameter(&reply_msg, buffer, false);
        send_message(&reply_msg, user);
        if (error)
        {
            return -1;
        }
        else
        {
            return 1;
        }
    }
    else
    {
        /* Channel does not exist */
        chirc_message_construct(&reply_msg, server->servername, ERR_NOSUCHCHANNEL);
        chirc_message_add_parameter(&reply_msg, user->nickname, false);
        sprintf(buffer, "%s :No such channel", recipient_ch_name);
        chirc_message_add_parameter(&reply_msg, buffer, false);
        error = send_message(&reply_msg, user);
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

int handle_MODE_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                                      struct chirc_user_t *user)
{
    int error = 0;
    struct chirc_server_t *server = ctx->this_server;

    if ((error = handle_not_registered(ctx, user)) ||
        (error = handle_not_enough_parameters(ctx, msg, user, 3)))
    {
        return error;
    }

    struct chirc_channel_t *channel;
    struct chirc_message_t reply_msg;
    struct chirc_user_cont_t *user_container;
    struct chirc_user_cont_t *requester_container;
    struct chirc_user_t *user_in_channel;
    char buffer[MAX_MSG_LEN + 1] = {0};
    int i;

    pthread_mutex_lock(&ctx->channels_lock);
    HASH_FIND_STR(ctx->channels, msg->params[0], channel);

    if (channel)
    {
        /* Cannot result in deadlock because we will always
           hold ctx->channels_lock before we try to acquire
           a particular channel lock: */
        pthread_mutex_lock(&channel->lock);
        pthread_mutex_unlock(&ctx->channels_lock);
        HASH_FIND_STR(channel->users, msg->params[2], user_container);

        if (user_container)
        {
            /* Check if user has sufficient privileges */
            if (!user->is_irc_operator)  // Is requester an IRC operator?
            {
                /* If IRC operator, requester must be a channel
                   operator in their specified channel */
                HASH_FIND_STR(channel->users, user->nickname,
                              requester_container);

                if (!requester_container ||
                   (!requester_container->is_channel_operator))
                {
                    pthread_mutex_unlock(&channel->lock);
                    chirc_message_construct(&reply_msg, server->servername,
                                            ERR_CHANOPRIVSNEEDED);
                    chirc_message_add_parameter(&reply_msg, user->nickname,
                                                false);
                    chirc_message_add_parameter(&reply_msg, msg->params[0],
                                                false);
                    chirc_message_add_parameter(&reply_msg, "You're not "
                                                "channel operator", true);
                    return (send_message(&reply_msg, user));
                }
            }

            if (!strcmp("+o", msg->params[1]))  // Add privileges
            {
                user_container->is_channel_operator = true;
                pthread_mutex_unlock(&channel->lock);
                sprintf(buffer, "%s!%s@%s", user->nickname, user->username,
                        user->hostname);
                chirc_message_construct(&reply_msg, buffer, msg->cmd);
                chirc_message_add_parameter(&reply_msg, msg->params[0], false);
                chirc_message_add_parameter(&reply_msg, msg->params[1], false);


                chirc_message_add_parameter(&reply_msg, msg->params[2], false);
                for (user_container=channel->users; user_container != NULL;
                                     user_container=user_container->hh.next)
                {
                    user_in_channel = find_user_in_channel(ctx, channel,
                                                         user_container->nickname);
                    send_message(&reply_msg, user_in_channel);
                }
            }
            else if (!strcmp("-o", msg->params[1]))  // Remove privileges
            {
                user_container->is_channel_operator = false;
                pthread_mutex_unlock(&channel->lock);
                sprintf(buffer, "%s!%s@%s", user->nickname, user->username,
                        user->hostname);
                chirc_message_construct(&reply_msg, buffer, msg->cmd);
                chirc_message_add_parameter(&reply_msg, msg->params[0], false);
                chirc_message_add_parameter(&reply_msg, msg->params[1], false);
                chirc_message_add_parameter(&reply_msg, msg->params[2], false);
                for (user_container=channel->users; user_container != NULL;
                                     user_container=user_container->hh.next)
                {
                    user_in_channel = find_user_in_channel(ctx, channel,
                                                         user_container->nickname);
                    send_message(&reply_msg, user_in_channel);
                }
            }
            else  // Unknown Mode
            {
                pthread_mutex_unlock(&channel->lock);
                chirc_message_construct(&reply_msg, server->servername,
                                        ERR_UNKNOWNMODE);
                chirc_message_add_parameter(&reply_msg, user->nickname, false);
                chirc_message_add_parameter(&reply_msg, msg->params[1], false);
                sprintf(buffer, "is unknown mode char to me for %s",
                        msg->params[0]);
                chirc_message_add_parameter(&reply_msg, buffer, true);
                return (send_message(&reply_msg, user));
            }
        }
        else  // User not in channel
        {
            pthread_mutex_unlock(&channel->lock);
            chirc_message_construct(&reply_msg, server->servername,
                                    ERR_USERNOTINCHANNEL);
            chirc_message_add_parameter(&reply_msg, user->nickname, false);
            chirc_message_add_parameter(&reply_msg, msg->params[2], false);
            chirc_message_add_parameter(&reply_msg, msg->params[0], false);
            chirc_message_add_parameter(&reply_msg,
                                          "They aren't on that channel", true);
            return (send_message(&reply_msg, user));
        }
    }
    else  // Channel doesn't exist
    {
        pthread_mutex_unlock(&ctx->channels_lock);
        chirc_message_construct(&reply_msg, server->servername, ERR_NOSUCHCHANNEL);
        chirc_message_add_parameter(&reply_msg, user->nickname, false);
        chirc_message_add_parameter(&reply_msg, msg->params[0], false);
        chirc_message_add_parameter(&reply_msg, "No such channel", true);
        return (send_message(&reply_msg, user));
    }

    return error;
}

int handle_LIST_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                                      struct chirc_user_t *user)
{
    int error = handle_not_registered(ctx, user);
    struct chirc_server_t *server = ctx->this_server;
    if (error)
    {
        return error;
    }
    struct chirc_message_t reply_msg;
    char buffer[MAX_MSG_LEN + 1] = {0};
    char prefix_buffer[MAX_MSG_LEN + 1] = {0};
    sprintf(prefix_buffer, "%s!%s@%s", user->nickname, user->username,
                                                                user->hostname);
    struct chirc_channel_t *channel;
    if (msg->nparams == 1)
    {
        /* send info for one channel */
        chirc_message_clear(&reply_msg);
        char ch_name[MAX_CHANNEL_NAME_LEN + 1];
        strcpy(ch_name, msg->params[0]);
        pthread_mutex_lock(&ctx->channels_lock);
        HASH_FIND_STR(ctx->channels, ch_name, channel);
        pthread_mutex_unlock(&ctx->channels_lock);
        if (channel)
        {
            chirc_message_construct(&reply_msg, prefix_buffer, RPL_LIST);
            pthread_mutex_lock(&channel->lock);
            sprintf(buffer, "%s %i :", ch_name, channel->nusers);
            pthread_mutex_unlock(&channel->lock);
            chirc_message_add_parameter(&reply_msg, buffer, false);
            send_message(&reply_msg, user);
        }
    }
    else
    {
        /* send all channel info */
        pthread_mutex_lock(&ctx->channels_lock);
        for (channel=ctx->channels; channel != NULL; channel = channel->hh.next)
        {
            chirc_message_clear(&reply_msg);
            memset(buffer, 0, MAX_MSG_LEN + 1);
            chirc_message_construct(&reply_msg, prefix_buffer, RPL_LIST);
            chirc_message_add_parameter(&reply_msg, user->nickname, false);
            pthread_mutex_lock(&channel->lock);
            sprintf(buffer, "%s %i :", channel->channel_name, channel->nusers);
            pthread_mutex_unlock(&channel->lock);
            chirc_message_add_parameter(&reply_msg, buffer, false);
            send_message(&reply_msg, user);
        }
        pthread_mutex_unlock(&ctx->channels_lock);
    }
    chirc_message_clear(&reply_msg);
    chirc_message_construct(&reply_msg, prefix_buffer, RPL_LISTEND);
    chirc_message_add_parameter(&reply_msg, user->nickname, false);
    chirc_message_add_parameter(&reply_msg, "End of LIST", true);
    send_message(&reply_msg, user);
    return 0;
}

int handle_OPER_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                                      struct chirc_user_t *user)
{
    int error;
    struct chirc_server_t *server = ctx->this_server;
    if ((error = handle_not_registered(ctx, user)) ||
        (error = handle_not_enough_parameters(ctx, msg, user, 2)))
    {
        return error;
    }

    struct chirc_message_t reply_msg;
    chirc_message_clear(&reply_msg);

    chilog(DEBUG, "Expected: ");
    chilog(DEBUG, ctx->this_server->password);
    chilog(DEBUG, "Got: ");
    chilog(DEBUG, msg->params[1]);
    if (strcmp(ctx->this_server->oper_password, msg->params[1]))  // Password does not match
    {
        chirc_message_construct(&reply_msg, server->servername, ERR_PASSWDMISMATCH);
        chirc_message_add_parameter(&reply_msg, user->nickname, false);
        chirc_message_add_parameter(&reply_msg, "Password incorrect", true);
        error = send_message(&reply_msg, user);
        if (error)
        {
            return error;
        }
    }
    else
    {
        pthread_mutex_lock(&ctx->users_lock);
        pthread_mutex_lock(&user->lock);
        ctx->num_operators++;
        user->is_irc_operator = true;
        pthread_mutex_unlock(&user->lock);
        pthread_mutex_unlock(&ctx->users_lock);

        chirc_message_construct(&reply_msg, server->servername, RPL_YOUREOPER);
        chirc_message_add_parameter(&reply_msg, user->nickname, false);
        chirc_message_add_parameter(&reply_msg, "You are now an IRC operator",
                                    true);
        error = send_message(&reply_msg, user);
        if (error)
        {
            return error;
        }
    }

    return 0;
}

int handle_CONNECT_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_user_t *user)
{
    int error;
    struct chirc_message_t reply_msg;
    chirc_message_clear(&reply_msg);
    struct chirc_server_t *this_server = ctx->this_server;
    struct chirc_server_t *found_server = NULL;
    int client_socket;
    struct addrinfo hints, *res, *p;
    pthread_t worker_thread;
    struct worker_args *wa;

    if ((error = handle_not_enough_parameters(ctx, msg, user, 2)))
    {
        return error;
    }
    else if (!user->is_irc_operator)
    {
        chirc_message_construct(&reply_msg, user->nickname, ERR_NOPRIVILEGES);
        chirc_message_add_parameter(&reply_msg, user->nickname, false);
        chirc_message_add_parameter(&reply_msg, "Permission Denied- "
                                    "You're not an IRC operator", true);
        error = send_message(&reply_msg, user);
    }

    HASH_FIND_STR(ctx->servers, msg->params[0], found_server);

    if (!found_server)
    {
        chirc_message_construct(&reply_msg, user->nickname, ERR_NOSUCHSERVER);
        chirc_message_add_parameter(&reply_msg, user->nickname, false);
        chirc_message_add_parameter(&reply_msg, msg->params[0], false);
        chirc_message_add_parameter(&reply_msg, "No such server", true);
        error = send_message(&reply_msg, user);
    }
    else if (found_server->is_registered)
    {
        // What error message??
    }
    else
    {
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        if (getaddrinfo(found_server->hostname, found_server->port,
          &hints, &res) != 0)
        {
            return -1;
        }

        for (p = res; p != NULL; p = p->ai_next)
        {
            if ((client_socket = socket(p->ai_family, p->ai_socktype,
                                        p->ai_protocol)) == -1)
            {
                continue;
            }
            if (connect(client_socket, p->ai_addr, p->ai_addrlen) == -1)
            {
                close(client_socket);
                continue;
            }
            break;
        }

        freeaddrinfo(res);

        if (p == NULL)
        {
            chilog(INFO, "CONNECT: failed to connect with server");
        }
        else
        {
            chirc_message_construct(&reply_msg, this_server->servername,
                                "PASS");
            chirc_message_add_parameter(&reply_msg, found_server->password, false);
            chirc_message_add_parameter(&reply_msg, "0210", false);
            chirc_message_add_parameter(&reply_msg, "chirc|0.5.1", false);
            send_message_to_server(&reply_msg, found_server);

            chirc_message_construct(&reply_msg, this_server->servername,
                                    "SERVER");
            chirc_message_add_parameter(&reply_msg, this_server->servername, false);
            chirc_message_add_parameter(&reply_msg, "1", false);
            chirc_message_add_parameter(&reply_msg, "chirc server", true);
            send_message_to_server(&reply_msg, found_server);
         
            found_server->is_registered = true;
            ctx->num_clients += 1;
            wa = calloc(1, sizeof(struct worker_args));
            wa->socket = client_socket;
            wa->ctx = ctx;
            wa->client_addr = p->ai_addr;

            wa->connection = calloc(1, sizeof(struct chirc_connection_t));
            wa->connection->type = SERVER;
            wa->connection->server = found_server;

            if (pthread_create(&worker_thread, NULL, service_connection, wa) != 0)
            {
                perror("Could not create a worker thread");
                free(wa);
                close(client_socket);
                return 0;
            }
        }

    }


}
