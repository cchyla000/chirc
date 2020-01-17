#ifndef CHIRC_HANDLER_H
#define CHIRC_HANDLER_H

#include "message.h"
#include "user.h"
#include "ctx.h"

int handle_NICK(ctx_t *ctx, chirc_message_t *msg, chirc_user_t *user);
int handle_USER(ctx_t *ctx, chirc_message_t *msg, chirc_user_t *user);
int handle_QUIT(ctx_t *ctx, chirc_message_t *msg, chirc_user_t *user);
int handle_PRIVMSG(ctx_t *ctx, chirc_message_t *msg, chirc_user_t *user);
int handle_NOTICE(ctx_t *ctx, chirc_message_t *msg, chirc_user_t *user);
int handle_PING(ctx_t *ctx, chirc_message_t *msg, chirc_user_t *user);
int handle_PONG(ctx_t *ctx, chirc_message_t *msg, chirc_user_t *user);
int handle_LUSERS(ctx_t *ctx, chirc_message_t *msg, chirc_user_t *user);
int handle_WHOIS(ctx_t *ctx, chirc_message_t *msg, chirc_user_t *user);
int handle_JOIN(ctx_t *ctx, chirc_message_t *msg, chirc_user_t *user);
int handle_PART(ctx_t *ctx, chirc_message_t *msg, chirc_user_t *user);
int handle_PART(ctx_t *ctx, chirc_message_t *msg, chirc_user_t *user);
int handle_MODE(ctx_t *ctx, chirc_message_t *msg, chirc_user_t *user);
int handle_LIST(ctx_t *ctx, chirc_message_t *msg, chirc_user_t *user);
int handle_OPER(ctx_t *ctx, chirc_message_t *msg, chirc_user_t *user);

#endif /* CHIRC_HANDLER_H */
