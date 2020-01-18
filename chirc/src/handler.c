#include "handler.h"

#define MAX_MSG_LEN 512
#define MAX_HOST_LEN 63

#define RPL_WELCOME "001"
#define RPL_YOURHOST "002"
#define RPL_CREATED "003"
#define RPL_MYINFO "004"

#define ERR_NOSUCHNICK "401"
#define ERR_NORECIPIENT "411"
#define ERR_NOTEXTTOSEND "412"
#define ERR_UNKNOWNCOMMAND "421"
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
static int send_message(struct chirc_message_t *msg, struct chirc_user_t *user,
                        struct worker_args *wa)
{
    int nbytes;
    char to_send[MAX_MSG_LEN + 1] = {0};
    chirc_message_to_string(msg, to_send);

    pthread_mutex_lock(&user->lock);
    nbytes = send(user->socket, to_send, strlen(to_send), 0); 
    pthread_mutex_unlock(&user->lock);

    if (nbytes == -1)
    {
        close(socket);
        destroy_user_and_exit(user, wa);
    }

    return 0;
} 

/*
 * Sends Replies 001 to 004 to specified user upon successful registration
 */
static int send_welcome_messages(struct worker_args *wa, 
                                 struct chirc_user_t *user)
{
    char param_buffer[MAX_MSG_LEN + 1] = {0};
    struct chirc_message_t *msg;
    struct ctx_t *ctx = wa->ctx;

    /* Send RPL_WELCOME: */
    chirc_message_construct(msg, ctx->server_name, RPL_WELCOME);
    chirc_message_add_parameter(msg, user->nickname, false);
    sprintf(param_buffer, ":Welcome to the Internet Relay Network %s!%s@%s",
            user->nickname, user->username, user->hostname); 
    chirc_message_add_parameter(msg, param_buffer, false);
    send_message(msg, user, wa); 
    chirc_message_destroy(msg);

    /* Send RPL_YOURHOST: */
    chirc_message_construct(msg, ctx->server_name, RPL_YOURHOST);
    chirc_message_add_parameter(msg, user->nickname, false);
    sprintf(param_buffer, ":Your host is %s, running version %s", 
            ctx->server_name, IRC_VERSION);
    chirc_message_add_parameter(msg, param_buffer, false); 
    send_message(msg, user, wa); 
    chirc_message_destroy(msg);

    /* Send RPL_CREATED: */
    chirc_message_construct(msg, ctx->server_name, RPL_CREATED);
    chirc_message_add_parameter(msg, user->nickname, false);
    sprintf(param_buffer, ":This server was created %s", "NEED TO RECORD TIME");
    send_message(msg, user, wa); 
    chirc_message_destroy(msg);

    /* Send RPL_MYINFO: */ 


    return 0;
} 

int handle_NICK(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_user_t *user)
{
    char[MAX_NICK_LEN + 1] nick; 
    struct chirc_user_t *found_user;
    struct chirc_message_t *reply_msg;

    if (msg->nparams < 1)  // No nickname given 
    {
        chirc_message_construct(reply_msg, ctx->server_name, 
                                ERR_NONICKNAMEGIVEN);
        chirc_message_add_parameter(reply_msg, user->nickname, false);
        chirc_message_add_parameter(reply_msg, ":No nickname given", false);
        send_message(reply_msg, user, wa); 
    }

    strcpy(nick, msg->params[0]);

    HASH_FIND_STR(ctx->users, nick, found_user);

    if (found_user)  // Nickname already in use
    {
        chirc_message_construct(reply_msg, ctx->server_name, 
                                ERR_NICKNAMEINUSE);  
        chirc_message_add_parameter(reply_msg, user->nickname, false);
        chirc_message_add_parameter(reply_msg, nick, false);  
        chirc_message_add_parameter(reply_msg, ":Nickname is already in use", 
                                    false);
        send_message(reply_msg, user, wa);
    }
    else if (user->is_registered)
    {
        
    }
    else  // User not registered
    {
        strcpy(user->nickname, nick);

        if (*user->username)  // Registration complete
        {
            user->is_registered = true;
            pthread_mutex_lock(&ctx->users_lock);
            HASH_ADD_STR(ctx->users, user->nickname, user);
            pthread_mutex_unlock(&ctx->users_lock);
            send_welcome_messages(ctx, user);
        } 
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
