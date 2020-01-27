#ifndef CHIRC_HANDLER_H
#define CHIRC_HANDLER_H

#include "message.h"
#include "connection.h"
#include "ctx.h"

/* These functions handle incoming messages of their respective commands,
 * sending messages to other users and replying as specified */
int handle_NICK_UNKNOWN(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_connection_t *connection);
int handle_USER_UNKNOWN(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_connection_t *connection);
int handle_PRIVMSG_UNKNOWN(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_connection_t *connection);
int handle_NOTICE_UNKNOWN(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_connection_t *connection);
int handle_PING_UNKNOWN(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_connection_t *connection);
int handle_PONG_UNKNOWN(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_connection_t *connection);
int handle_LUSERS_UNKNOWN(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_connection_t *connection);
int handle_WHOIS_UNKNOWN(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_connection_t *connection);
int handle_JOIN_UNKNOWN(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_connection_t *connection);
int handle_MODE_UNKNOWN(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_connection_t *connection);
int handle_LIST_UNKNOWN(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_connection_t *connection);
int handle_OPER_UNKNOWN(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_connection_t *connection);
int handle_PASS_UNKNOWN(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_connection_t *connection);
int handle_SERVER_UNKNOWN(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_connection_t *connection);
int handle_CONNECT_UNKNOWN(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_connection_t *connection);
int handle_NICK_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_connection_t *connection);
int handle_USER_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_connection_t *connection);
int handle_PRIVMSG_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_connection_t *connection);
int handle_NOTICE_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_connection_t *connection);
int handle_PING_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_connection_t *connection);
int handle_PONG_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_connection_t *connection);
int handle_LUSERS_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_connection_t *connection);
int handle_WHOIS_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_connection_t *connection);
int handle_JOIN_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_connection_t *connection);
int handle_MODE_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_connection_t *connection);
int handle_LIST_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_connection_t *connection);
int handle_OPER_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_connection_t *connection);
int handle_PASS_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_connection_t *connection);
int handle_SERVER_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_connection_t *connection);
int handle_CONNECT_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_connection_t *connection);
int handle_NICK_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_connection_t *connection);
int handle_USER_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_connection_t *connection);
int handle_PRIVMSG_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_connection_t *connection);
int handle_NOTICE_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_connection_t *connection);
int handle_PING_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_connection_t *connection);
int handle_PONG_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_connection_t *connection);
int handle_LUSERS_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_connection_t *connection);
int handle_WHOIS_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_connection_t *connection);
int handle_JOIN_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_connection_t *connection);
int handle_MODE_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_connection_t *connection);
int handle_LIST_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_connection_t *connection);
int handle_OPER_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_connection_t *connection);
int handle_PASS_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_connection_t *connection);
int handle_SERVER_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_connection_t *connection);
int handle_CONNECT_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_connection_t *connection);

#endif /* CHIRC_HANDLER_H */
