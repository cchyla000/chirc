#include "handler.h"

#define NICK_LEN 9
#define MAX_MSG_LEN 512

#define ERR_NOSUCHNICK "401"
#define ERR_NORECIPIENT "411"
#define ERR_NOTEXTTOSEND "412"
#define ERR_UNKNOWNCOMMAND "421"
#define ERR_NONICKNAMEGIVEN "431" 
#define ERR_NICKNAMEINUSE "433"
#define ERR_NOTREGISTERED "451"
#define ERR_NEEDMOREPARAMS "461" 
#define ERR_ALREADYREGISTERED "462"
 

int handle_NICK(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_user_t *user)
{
    char[NICK_LEN + 1] nick; 
    struct chirc_user_t *found_user;
    struct chirc_message_t *reply_msg;
    char to_send[MAX_MSG_LEN + 1] = {0};
    int nbytes;

    if (user->nparams < 1)  // No nickname given 
    {
        chirc_message_construct(reply_msg, ctx->server_name, 
                                ERR_NONICKNAMEGIVEN);
        chirc_message_add_nickname_parameter(reply_msg, msg->nick);
        chirc_message_add_parameter(reply_msg, ":No nickname given");
        chirc_message_to_string(reply_msg, to_send);
        nbytes = send(user->socket, to_send, strlen(to_send), 0); 
        // separate function to send messages and do error checking (see Borja code lines 206-220 in server-pthreads.c
    }

    strcpy(nick, msg->params[0]);

    HASH_FIND_STR(ctx->users, nick, found_user);

    if (found_user)  // Nickname already in use
    {
    
    }
    else if (user->is_registered)
    {

    }
    else  // User not registered
    {

    } 

}

int handle_USER(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_user_t *user)
{
  return 0;
}

int handle_QUIT(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_user_t *user)
{
  return 0;
}

int handle_PRIVMSG(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_user_t *user)
{
  return 0;
}

int handle_NOTICE(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_user_t *user)
{
  return 0;
}

int handle_PING(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_user_t *user)
{
  return 0;
}

int handle_PONG(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_user_t *user)
{
  return 0;
}

int handle_LUSERS(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_user_t *user)
{
  return 0;
}

int handle_WHOIS(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_user_t *user)
{
  return 0;
}

int handle_JOIN(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_user_t *user)
{
  return 0;
}

int handle_PART(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_user_t *user)
{
  return 0;
}

int handle_MODE(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_user_t *user)
{
  return 0;
}

int handle_LIST(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_user_t *user)
{
  return 0;
}

int handle_OPER(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_user_t *user)
{
  return 0;
}
