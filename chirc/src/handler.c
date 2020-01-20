#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include "handler.h"
#include "log.h"

#define MAX_MSG_LEN 512
#define MAX_HOST_LEN 63

#define RPL_WELCOME "001"
#define RPL_YOURHOST "002"
#define RPL_CREATED "003"
#define RPL_MYINFO "004"
#define RPL_LUSERCLIENT "251"
#define RPL_LUSEROP "252"
#define RPL_LUSERUNKNOWN "253"
#define RPL_LUSERCHANNELS "254"
#define RPL_LUSERME "255"

#define ERR_NOSUCHNICK "401"

/* PING or PONG message missing the originator parameter: */
#define ERR_NOORIGIN "409"

#define ERR_NORECIPIENT "411"

/* Used by PRIVMSG: */
#define ERR_NOTEXTTOSEND "412"
#define ERR_NOTOPLEVEL "413"
#define ERR_WILDTOPLEVEL "414"
#define ERR_BADMASK "415"

#define ERR_UNKNOWNCOMMAND "421"
#define ERR_NOMOTD "422"
#define ERR_NONICKNAMEGIVEN "431"
#define ERR_NICKNAMEINUSE "433"
#define ERR_NOTREGISTERED "451"
#define ERR_NEEDMOREPARAMS "461"
#define ERR_ALREADYREGISTERED "462"

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

    /* Send RPL_LUSERCLIENT */
    chirc_message_construct(&msg, ctx->server_name, RPL_LUSERCLIENT);
    chirc_message_add_parameter(&msg, user->nickname, false);
    chirc_message_add_parameter(&msg, "There are 1 users and 0 services"
                                " on 1 servers", true);
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
    chirc_message_add_parameter(&msg, "0", false);
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
    chirc_message_add_parameter(&msg, "0", false);
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
    chirc_message_add_parameter(&msg, "I have 1 clients and 1 servers", true);
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
    chirc_message_clear(&msg);


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
    chilog(TRACE, "NICK recieved! user: %s nick: %s registered: %d", user->username, user->nickname, user->is_registered);
    char nick[MAX_NICK_LEN + 1];
    struct chirc_user_t *found_user;
    struct chirc_message_t reply_msg;
    chirc_message_clear (&reply_msg);
    int error = 0;

    if (msg->nparams < 1)  // No nickname given
    {
        chirc_message_construct(&reply_msg, ctx->server_name,
                                ERR_NONICKNAMEGIVEN);
        chirc_message_add_parameter(&reply_msg, user->nickname, false);
        chirc_message_add_parameter(&reply_msg, "No nickname given", true);
        error = send_message(&reply_msg, user);
        return error;
    }

    strcpy(nick, msg->params[0]);
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
            chilog(TRACE, "completing registration");
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

        if (*user->nickname)  // Registration complete
        {
            chilog(TRACE, "completing registration");
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
        chirc_message_add_parameter(&reply_msg, "Closing Link: (Client Quit)",
                                    true);
    }
    else
    {
        sprintf(param_buffer, "Closing Link: (%s)", msg->params[0]);
        chirc_message_add_parameter(&reply_msg, param_buffer, true);
    }
    error = send_message(&reply_msg, user);
    return error;
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
    char buffer[MAX_MSG_LEN + 1] = {0};
    char recipient_nick[MAX_NICK_LEN + 1];
    strcpy(recipient_nick, msg->params[0]);
    pthread_mutex_lock(&ctx->users_lock);
    HASH_FIND_STR(ctx->users, recipient_nick, recipient);
    pthread_mutex_unlock(&ctx->users_lock);
    if (recipient)
    {
        sprintf(buffer, "%s!%s@%s", user->nickname, user->username, user->hostname);
        chirc_message_construct(&reply_msg, buffer, msg->cmd);
        for (int i = 0; i < msg->nparams - 1; i++)
        {
            chirc_message_add_parameter(&reply_msg, msg->params[i], false);
        }
        chirc_message_add_parameter(&reply_msg, msg->params[msg->nparams - 1], true);
        reply_msg.longlast = msg->longlast;
        send_message(&reply_msg, recipient);
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
  char buffer[MAX_MSG_LEN + 1] = {0};
  char recipient_nick[MAX_NICK_LEN + 1];
  strcpy(recipient_nick, msg->params[0]);
  pthread_mutex_lock(&ctx->users_lock);
  HASH_FIND_STR(ctx->users, recipient_nick, recipient);
  pthread_mutex_unlock(&ctx->users_lock);
  if (recipient)
  {
      sprintf(buffer, "%s!%s@%s", user->nickname, user->username, user->hostname);
      chirc_message_construct(&reply_msg, buffer, msg->cmd);
      for (int i = 0; i < msg->nparams - 1; i++)
      {
          chirc_message_add_parameter(&reply_msg, msg->params[i], false);
      }
      chirc_message_add_parameter(&reply_msg, msg->params[msg->nparams - 1], true);
      reply_msg.longlast = msg->longlast;
      send_message(&reply_msg, recipient);
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
    sprintf(param_buffer, "There are %d users and %d services on %d servers", HASH_COUNT(ctx->users), 0, 1);

    return 0;
}

int handle_WHOIS(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_user_t *user)
{
    int error = handle_not_registered(ctx, user);
    if (error)
    {
        return error;
    }
    return 0;
}

int handle_JOIN(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_user_t *user)
{
    int error = handle_not_registered(ctx, user);
    if (error)
    {
        return error;
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
