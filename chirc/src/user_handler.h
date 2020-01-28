#ifndef CHIRC_USER_HANDLER_H
#define CHIRC_USER_HANDLER_H

#include "message.h"
#include "connection.h"
#include "ctx.h"

/* These functions handle incoming messages of their respective commands,
 * sending messages to other users and replying as specified */
int handle_NICK_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_user_t *user);
int handle_USER_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_user_t *user);
int handle_QUIT_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_user_t *user);
int handle_PRIVMSG_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_user_t *user);
int handle_NOTICE_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_user_t *user);
int handle_PING_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_user_t *user);
int handle_PONG_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_user_t *user);
int handle_LUSERS_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_user_t *user);
int handle_WHOIS_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_user_t *user);
int handle_JOIN_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_user_t *user);
int handle_MODE_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_user_t *user);
int handle_LIST_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_user_t *user);
int handle_OPER_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_user_t *user);
int handle_PART_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_user_t *user);
#endif /* CHIRC_USER_HANDLER_H */
