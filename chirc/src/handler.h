#include "message.h"

#ifndef CHIRC_HANDLER_H
#define CHIRC_HANDLER_H

int handle_NICK(server_ctx *ctx, chirc_message_t *msg, user_t *user);
int handle_USER(server_ctx *ctx, chirc_message_t *msg, user_t *user);
int handle_QUIT(server_ctx *ctx, chirc_message_t *msg, user_t *user);
int handle_PRIVMSG(server_ctx *ctx, chirc_message_t *msg, user_t *user);
int handle_NOTICE(server_ctx *ctx, chirc_message_t *msg, user_t *user);
int handle_PING(server_ctx *ctx, chirc_message_t *msg, user_t *user);
int handle_PONG(server_ctx *ctx, chirc_message_t *msg, user_t *user);
int handle_LUSERS(server_ctx *ctx, chirc_message_t *msg, user_t *user);
int handle_WHOIS(server_ctx *ctx, chirc_message_t *msg, user_t *user);
int handle_JOIN(server_ctx *ctx, chirc_message_t *msg, user_t *user);
int handle_PART(server_ctx *ctx, chirc_message_t *msg, user_t *user);
int handle_PART(server_ctx *ctx, chirc_message_t *msg, user_t *user);
int handle_MODE(server_ctx *ctx, chirc_message_t *msg, user_t *user);
int handle_LIST(server_ctx *ctx, chirc_message_t *msg, user_t *user);
int handle_OPER(server_ctx *ctx, chirc_message_t *msg, user_t *user);

#endif /* CHIRC_HANDLER_H */
