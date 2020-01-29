#ifndef CHIRC_SERVER_HANDLER_H
#define CHIRC_SERVER_HANDLER_H

#include "message.h"
#include "connection.h"
#include "ctx.h"

int handle_NICK_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_server_t *server);
int handle_USER_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_server_t *server);
int handle_QUIT_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_server_t *server);
int handle_PRIVMSG_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_server_t *server);
int handle_NOTICE_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_server_t *server);
int handle_PING_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_server_t *server);
int handle_PONG_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_server_t *server);
int handle_LUSERS_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_server_t *server);
int handle_WHOIS_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_server_t *server);
int handle_JOIN_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_server_t *server);
int handle_MODE_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_server_t *server);
int handle_LIST_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_server_t *server);
int handle_OPER_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_server_t *server);
int handle_PART_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_server_t *server);
int handle_PASS_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_server_t *server);
int handle_SERVER_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_server_t *server);

#endif /* CHIRC_SERVER_HANDLER_H */
