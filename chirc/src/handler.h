#ifndef CHIRC_HANDLER_H
#define CHIRC_HANDLER_H

#include "message.h"
#include "user.h"
#include "ctx.h"

int handle_NICK(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_user_t *user);
int handle_USER(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_user_t *user);
int handle_QUIT(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_user_t *user);
int handle_PRIVMSG(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_user_t *user);
int handle_NOTICE(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_user_t *user);
int handle_PING(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_user_t *user);
int handle_PONG(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_user_t *user);
int handle_LUSERS(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_user_t *user);
int handle_WHOIS(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_user_t *user);
int handle_JOIN(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_user_t *user);
int handle_PART(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_user_t *user);
int handle_PART(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_user_t *user);
int handle_MODE(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_user_t *user);
int handle_LIST(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_user_t *user);
int handle_OPER(struct ctx_t *ctx, struct chirc_message_t *msg, struct chirc_user_t *user);

#endif /* CHIRC_HANDLER_H */
