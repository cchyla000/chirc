#ifndef CHIRC_SERVER_HANDLER_H
#define CHIRC_SERVER_HANDLER_H

#include "message.h"
#include "connection.h"
#include "ctx.h"

/* NAMES: handle_(command)_SERVER
 *
 * DESCRIPTION: These functions handle recieved messages sent to the server by
 * a server of their given command.
 *
 * PARAMETERS:
 *  ctx - context for this server
 *  msg - message that was recieved with the given command
 *  server - server that sent message
 *
 * RETURN: 0 upon succesful completion, any other integer if error with sending
 */
int handle_NICK_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                                struct chirc_server_t *server);
int handle_QUIT_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                                struct chirc_server_t *server);
int handle_PRIVMSG_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                                struct chirc_server_t *server);
int handle_JOIN_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                                struct chirc_server_t *server);
int handle_PASS_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                                struct chirc_server_t *server);
int handle_SERVER_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                                struct chirc_server_t *server);

#endif /* CHIRC_SERVER_HANDLER_H */
