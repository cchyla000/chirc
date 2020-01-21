#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include "handler.h"
#include "channel.h"
#include "log.h"
#include "reply.h"

#define MAX_MSG_LEN 512
#define MAX_HOST_LEN 63

#define IRC_VERSION "2.10"

/*
 * Sends messages and does error checking; terminates
 * thread and destroys user if error in sending detected
 */
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

/*
 * Sends Replies 001 to 004 to specified user upon successful registration
 */
static int send_welcome_messages(struct ctx_t *ctx, struct chirc_user_t *user)
{
    char param_buffer[MAX_MSG_LEN + 1] = {0};
    struct chirc_message_t msg;
    int error;

    chirc_message_clear (&msg);

    /* Send RPL_WELCOME: */
    chirc_message_construct(&msg, ctx->server_name, RPL_WELCOME);
    chirc_message_add_parameter(&msg, user->nickname, false);
    sprintf(param_buffer, "Welcome to the Internet Relay Network %s!%s@%s", user->nickname, user->username, user->hostname);
    chirc_message_add_parameter(&msg, param_buffer, true);
    error = send_message(&msg, user);
    if (error)
    {
        return error;
    }
    chirc_message_clear(&msg);

    /* Send RPL_YOURHOST: */
    chirc_message_construct(&msg, ctx->server_name, RPL_YOURHOST);
    chirc_message_add_parameter(&msg, user->nickname, false);
    sprintf(param_buffer, "Your host is %s, running version %s",
            ctx->server_name, IRC_VERSION);
    chirc_message_add_parameter(&msg, param_buffer, true);
    error = send_message(&msg, user);
    if (error)
    {
        return error;
    }
    chirc_message_clear(&msg);

    /* Send RPL_CREATED: */
    chirc_message_construct(&msg, ctx->server_name, RPL_CREATED);
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
    chirc_message_construct(&msg, ctx->server_name, RPL_MYINFO);
    chirc_message_add_parameter(&msg, user->nickname, false);
    chirc_message_add_parameter(&msg, ctx->server_name, false);
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
    int connected_clients = ctx->connected_clients;
    int unknown_clients = connected_clients - registered_users;
    pthread_mutex_unlock(&ctx->users_lock);

    /* RPL_LUSERCLIENT */
    chirc_message_construct(&msg, ctx->server_name, RPL_LUSERCLIENT);
    chirc_message_add_parameter(&msg, user->nickname, false);
    sprintf(param_buffer, "There are %d users and %d services on %d servers", registered_users, 0, 1);
    chirc_message_add_parameter(&msg, param_buffer, true);
    error = send_message(&msg, user);
    if (error)
    {
        return error;
    }
    chirc_message_clear(&msg);

    /* Send RPL_LUSEROP */
    chirc_message_construct(&msg, ctx->server_name, RPL_LUSEROP);
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
    chirc_message_construct(&msg, ctx->server_name, RPL_LUSERUNKNOWN);
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
    chirc_message_construct(&msg, ctx->server_name, RPL_LUSERCHANNELS);
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
    chirc_message_construct(&msg, ctx->server_name, RPL_LUSERME);
    chirc_message_add_parameter(&msg, user->nickname, false);
    sprintf(param_buffer, "I have %d clients and 1 servers",
            registered_users);
    chirc_message_add_parameter(&msg, param_buffer, true);
    error = send_message(&msg, user);
    if (error)
    {
        return error;
    }
    chirc_message_clear(&msg);

    /* Send MOTD */
    chirc_message_construct(&msg, ctx->server_name, ERR_NOMOTD);
    chirc_message_add_parameter(&msg, user->nickname, false);
    chirc_message_add_parameter(&msg, "MOTD File is missing", true);
    error = send_message(&msg, user);
    if (error)
    {
        return error;
    }


    return 0;
}
static int handle_not_registered(struct ctx_t *ctx, struct chirc_user_t *user)
{
    int error;
    struct chirc_message_t reply_msg;
    chirc_message_clear(&reply_msg);

    if (!user->is_registered)
    {
        chirc_message_construct(&reply_msg, ctx->server_name,
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

static int
handle_not_enough_parameters(struct ctx_t *ctx, struct chirc_message_t *msg,
                             struct chirc_user_t *user, int nparams)
{
    struct chirc_message_t reply_msg;
    int error = 0;
    if (msg->nparams < nparams)  // Not enough parameters
    {
        chirc_message_construct(&reply_msg, ctx->server_name,
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

int handle_NICK(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_user_t *user)
{
    char nick[MAX_NICK_LEN + 1];
    struct chirc_user_t *found_user;
    struct chirc_message_t reply_msg;
    chirc_message_clear (&reply_msg);
    int error = 0;
    char param_buffer[MAX_MSG_LEN] = {0};

    if (msg->nparams < 1)  // No nickname given
    {
        chirc_message_construct(&reply_msg, ctx->server_name,
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
        chirc_message_construct(&reply_msg, ctx->server_name,
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
        chirc_message_add_parameter(&reply_msg, nick, false);
        // Must send this message to all channels that user is in...

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
            user->is_registered = true;
            pthread_mutex_lock(&ctx->users_lock);
            HASH_ADD_STR(ctx->users, nickname, user);
            pthread_mutex_unlock(&ctx->users_lock);
            error = send_welcome_messages(ctx, user);
        }
    }
    return error;
}

int handle_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                struct chirc_user_t *user)
{
    chilog(TRACE, "USER recieved! user: %s nick: %s registered: %d", user->username, user->nickname, user->is_registered);
    char user_buffer[MAX_MSG_LEN] = {0};
    struct chirc_message_t reply_msg;
    chirc_message_clear (&reply_msg);
    int error = 0;

    if ((error = handle_not_enough_parameters(ctx, msg, user, 4)))
    {
        return error;
    }
    else if (user->is_registered)
    {
        chirc_message_construct(&reply_msg, ctx->server_name,
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
            pthread_mutex_lock(&ctx->users_lock);
            HASH_ADD_STR(ctx->users, nickname, user);
            pthread_mutex_unlock(&ctx->users_lock);
            error = send_welcome_messages(ctx, user);
        }
    }

    return error;

}

int handle_QUIT(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_user_t *user)
{
    int error;
    struct chirc_message_t reply_msg;
    chirc_message_clear (&reply_msg);
    char param_buffer[MAX_MSG_LEN + 1] = {0};

    chirc_message_construct(&reply_msg, NULL, "ERROR");
    if (msg->nparams < 1)
    {
        sprintf(param_buffer, "Closing Link: %s (Client Quit)", 
                user->hostname);
        chirc_message_add_parameter(&reply_msg, param_buffer, true);
    }
    else
    {
        sprintf(param_buffer, "Closing Link: %s (%s)", user->hostname,
                msg->params[0]);
        chirc_message_add_parameter(&reply_msg, param_buffer, true);
    }

    send_message(&reply_msg, user);
    return -1;  // return error code so user is destroyed and exits
}

int handle_PRIVMSG(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_user_t *user)
{
    int error;
    if ((error = handle_not_registered(ctx, user)))
    {
        return error;
    }
    struct chirc_message_t reply_msg;
    if (msg->nparams == 0)
    {
      chirc_message_construct(&reply_msg, ctx->server_name,
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
    if (msg->nparams == 1)
    {
        chirc_message_construct(&reply_msg, ctx->server_name,
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
    HASH_FIND_STR(user->channels, recipient_ch_name, recipient_channel);
    pthread_mutex_unlock(&ctx->users_lock);
    pthread_mutex_lock(&ctx->channels_lock);
    HASH_FIND_STR(ctx->channels, recipient_ch_name, channel_exists);
    pthread_mutex_unlock(&ctx->channels_lock);
    if (recipient || recipient_channel)
    {
        sprintf(buffer, "%s!%s@%s", user->nickname, user->username, user->hostname);
        chirc_message_construct(&reply_msg, buffer, msg->cmd);
        for (int i = 0; i < msg->nparams - 1; i++)
        {
            chirc_message_add_parameter(&reply_msg, msg->params[i], false);
        }
        chirc_message_add_parameter(&reply_msg, msg->params[msg->nparams - 1], true);
        reply_msg.longlast = msg->longlast;
        if (recipient)
        {
            send_message(&reply_msg, recipient);
        }
        else
        {
            struct chirc_user_t *user_in_channel;
            for (user_in_channel=recipient_channel->users; user_in_channel != NULL;
                                           user_in_channel=user_in_channel->hh.next)
            {
                if (user != user_in_channel)
                {
                    send_message(&reply_msg, user_in_channel);
                }
            }
        }
    }
    else if (channel_exists)
    {
        chirc_message_construct(&reply_msg, ctx->server_name, ERR_CANNOTSENDTOCHAN);
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
        chirc_message_construct(&reply_msg, ctx->server_name, ERR_NOSUCHNICK);
        chirc_message_add_parameter(&reply_msg, user->nickname, false);
        sprintf(buffer, "%s :No such nick/channel", recipient_nick);
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

int handle_NOTICE(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_user_t *user)
{
  int error;
  if ((error = handle_not_registered(ctx, user)))
  {
      return error;
  }
  struct chirc_message_t reply_msg;
  if (msg->nparams == 0 || msg->nparams == 1)
  {
    return 1;
  }
  struct chirc_user_t *recipient;
  struct chirc_channel_t *recipient_channel;
  char buffer[MAX_MSG_LEN + 1] = {0};
  char recipient_nick[MAX_NICK_LEN + 1];
  char recipient_ch_name[MAX_CHANNEL_NAME_LEN + 1];
  strcpy(recipient_nick, msg->params[0]);
  strcpy(recipient_ch_name, msg->params[0]);
  pthread_mutex_lock(&ctx->users_lock);
  HASH_FIND_STR(ctx->users, recipient_nick, recipient);
  HASH_FIND_STR(user->channels, recipient_ch_name, recipient_channel);
  pthread_mutex_unlock(&ctx->users_lock);
  if (recipient || recipient_channel)
  {
      sprintf(buffer, "%s!%s@%s", user->nickname, user->username, user->hostname);
      chirc_message_construct(&reply_msg, buffer, msg->cmd);
      for (int i = 0; i < msg->nparams - 1; i++)
      {
          chirc_message_add_parameter(&reply_msg, msg->params[i], false);
      }
      chirc_message_add_parameter(&reply_msg, msg->params[msg->nparams - 1], true);
      reply_msg.longlast = msg->longlast;
      if (recipient)
      {
          send_message(&reply_msg, recipient);
      }
      else
      {
          struct chirc_user_t *user_in_channel;
          for (user_in_channel=recipient_channel->users; user_in_channel != NULL;
                                         user_in_channel=user_in_channel->hh.next)
          {
              if (user != user_in_channel)
              {
                  send_message(&reply_msg, user_in_channel);
              }
          }
      }
  }
  return 0;
}

int handle_PING(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_user_t *user)
{
    int error = handle_not_registered(ctx, user);
    if (error)
    {
        return error;
    }

    struct chirc_message_t reply_msg;
    chirc_message_clear(&reply_msg);

    chirc_message_construct(&reply_msg, NULL, "PONG");
    chirc_message_add_parameter(&reply_msg, ctx->server_name, false);
    error = send_message(&reply_msg, user);
    if (error)
    {
        return error;
    }

/*
    if (msg->nparam < 1) 
    {
        chirc_message_construct(&reply_msg, ctx->server_name, ERR_NOORIGIN); 
        chirc_message_add_parameter(&reply_msg, "No origin specified", true);
        error = send_message(&reply_msg, user);
        if (error)
        {
            return error;
        }
    }
    else if (msg->nparam < 2)  // We are target; PONG back at sender
    {
        chirc_message_construct(&reply_msg, ctx->server_name, "PONG"); 
        chirc_message_add_parameter(&reply_msg, msg->nparam[0], false);
        chirc_message_add_parameter(&reply_msg, user, false);
        error = send_message(&reply_msg, user);
        if (error)
        {
            return error;
        }

    }
*/
    return 0;
}

int handle_PONG(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_user_t *user)
{
    int error = handle_not_registered(ctx, user);
    if (error)
    {
        return error;
    }
    return 0;
}

int handle_LUSERS(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_user_t *user)
{
    int error = handle_not_registered(ctx, user);
    if (error)
    {
        return error;
    }

    struct chirc_message_t reply_msg;
    chirc_message_clear(&reply_msg);
    char param_buffer[MAX_MSG_LEN + 1] = {0};
    chirc_message_construct(&reply_msg, ctx->server_name, RPL_LUSERCLIENT);
    chirc_message_add_parameter(&reply_msg, user->nickname, false);

    pthread_mutex_lock(&ctx->users_lock);
    int registered_users = HASH_COUNT(ctx->users);
    int connected_clients = ctx->connected_clients;
    int unknown_clients = connected_clients - registered_users;
    pthread_mutex_unlock(&ctx->users_lock);

    sprintf(param_buffer, "There are %d users and %d services on %d servers", registered_users, 0, 1);

    chirc_message_add_parameter(&reply_msg, param_buffer, true);
    error = send_message(&reply_msg, user);
    if (error)
    {
        return error;
    }
    chirc_message_clear(&reply_msg);

    /* Send RPL_LUSEROP */
    chirc_message_construct(&reply_msg, ctx->server_name, RPL_LUSEROP);
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
    chirc_message_construct(&reply_msg, ctx->server_name, RPL_LUSERUNKNOWN);
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
    chirc_message_construct(&reply_msg, ctx->server_name, RPL_LUSERCHANNELS);
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
    chirc_message_construct(&reply_msg, ctx->server_name, RPL_LUSERME);
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

int handle_WHOIS(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_user_t *user)
{
    int error = handle_not_registered(ctx, user);
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
        chirc_message_construct(&reply_msg, ctx->server_name, ERR_NOSUCHNICK); 
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
        chirc_message_construct(&reply_msg, ctx->server_name, RPL_WHOISUSER); 
        chirc_message_add_parameter(&reply_msg, found_user->nickname, false);
        chirc_message_add_parameter(&reply_msg, found_user->username, false);
        chirc_message_add_parameter(&reply_msg, found_user->hostname, false);
        chirc_message_add_parameter(&reply_msg, "*", false);
        chirc_message_add_parameter(&reply_msg, found_user->realusername, true);
        error = send_message(&reply_msg, user);
        if (error)
        {
            pthread_mutex_unlock(&ctx->users_lock);
            return error;
        }
        chirc_message_clear(&reply_msg); 

        /* RPL_WHOISSERVER */
        chirc_message_construct(&reply_msg, ctx->server_name, RPL_WHOISSERVER); 
        chirc_message_add_parameter(&reply_msg, user->nickname, false);
        chirc_message_add_parameter(&reply_msg, ctx->server_name, false);
        chirc_message_add_parameter(&reply_msg, "server info", true);
        error = send_message(&reply_msg, user);
        if (error)
        {
            pthread_mutex_unlock(&ctx->users_lock);
            return error;
        }
        chirc_message_clear(&reply_msg); 

        /* RPL_ENDOFWHOIS */
        chirc_message_construct(&reply_msg, ctx->server_name, RPL_ENDOFWHOIS); 
        chirc_message_add_parameter(&reply_msg, user->nickname, false);
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

int handle_JOIN(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_user_t *user)
{
    int error;
    if ((error = (handle_not_registered(ctx, user))) ||
                  (error = (handle_not_enough_parameters(ctx, msg, user, 1))))
    {
        return error;
    }
    struct chirc_channel_t *channel;
    struct chirc_message_t reply_msg;
    char buffer[MAX_MSG_LEN + 1] = {0};
    char channel_name[MAX_CHANNEL_NAME_LEN + 1];
    strcpy(channel_name, msg->params[0]);
    pthread_mutex_lock(&ctx->channels_lock);
    HASH_FIND_STR(ctx->channels, channel_name, channel);
    pthread_mutex_unlock(&ctx->channels_lock);
    if (channel_name[0] == '0')
    {
        /* remove from all channels */
    }
    else
    {
      struct chirc_user_t *user_in_channel;
      if (channel)
      {
          /* channel exists, check if user in channel
           * and ignore if they are
           */
          struct chirc_user_t* user_in_channel;
          pthread_mutex_lock(&channel->lock);
          HASH_FIND_STR(channel->users, user->nickname, user_in_channel);
          pthread_mutex_unlock(&channel->lock);
          if (user_in_channel) {
            return 0;
          }
      }
      else
      {
          /* channel does not exist, create channel */
          channel = create_channel(ctx, channel_name);
      }
      add_user_to_channel(channel, user);

      sprintf(buffer, "%s!%s@%s", user->nickname, user->username, user->hostname);
      chirc_message_construct(&reply_msg, buffer, msg->cmd);
      for (int i = 0; i < msg->nparams; i++)
      {
          chirc_message_add_parameter(&reply_msg, msg->params[i], false);
      }
      pthread_mutex_lock(&channel->lock);
      for(user_in_channel=channel->users; user_in_channel != NULL;
                                     user_in_channel=user_in_channel->hh.next)
      {
          send_message(&reply_msg, user_in_channel);
      }
      pthread_mutex_unlock(&channel->lock);
      chirc_message_clear(&reply_msg);

      chirc_message_construct(&reply_msg, ctx->server_name, RPL_NAMREPLY);
      chirc_message_add_parameter(&reply_msg, user->nickname, false);
      chirc_message_add_parameter(&reply_msg, "= #foobar :foobar1 foobar2 foobar3", false);
      error = send_message(&reply_msg, user);
      if (error)
      {
          return -1;
      }
      chirc_message_clear(&reply_msg);
      chirc_message_construct(&reply_msg, ctx->server_name, RPL_ENDOFNAMES);
      chirc_message_add_parameter(&reply_msg, user->nickname, false);
      chirc_message_add_parameter(&reply_msg, "#foobar :End of NAMES list", false);
      error = send_message(&reply_msg, user);
      if (error)
      {
          return -1;
      }
      chirc_message_clear(&reply_msg);
    }
    return 0;
}

int handle_PART(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_user_t *user)
{
    int error = handle_not_registered(ctx, user);
    if (error)
    {
        return error;
    }
    return 0;
}

int handle_MODE(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_user_t *user)
{
    int error = handle_not_registered(ctx, user);
    if (error)
    {
        return error;
    }
    return 0;
}

int handle_LIST(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_user_t *user)
{
    int error = handle_not_registered(ctx, user);
    if (error)
    {
        return error;
    }
    return 0;
}

int handle_OPER(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_user_t *user)
{
    int error = handle_not_registered(ctx, user);
    if (error)
    {
        return error;
    }
    return 0;
}
