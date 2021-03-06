/*
 *  FILENAME: user_handler.h
 *  DESCRIPTION: Functions for handling recieved messages sent to the server by
 *  a user
 *  AUTHORS: Cameron Chyla and Artur Genser (acknowledgement to CMSC 23320)
 *  LAST DATE MODIFIED: January 30th, 2020
 */

#ifndef CHIRC_USER_HANDLER_H
#define CHIRC_USER_HANDLER_H

#include "message.h"
#include "connection.h"
#include "ctx.h"

/* NAMES: handle_(command)_USER
 *
 * DESCRIPTION: These functions handle recieved messages sent to the server by
 * a user of their given command.
 *
 * PARAMETERS:
 *  ctx - context for this server
 *  msg - message that was recieved with the given command
 *  user - user that sent message
 *
 * RETURN: 0 upon succesful completion, any other integer if error with sending
 */
int handle_NICK_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                                    struct chirc_user_t *user);
int handle_USER_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                                    struct chirc_user_t *user);
int handle_QUIT_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                                    struct chirc_user_t *user);
int handle_PRIVMSG_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
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
int handle_CONNECT_USER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                                    struct chirc_user_t *user);
#endif /* CHIRC_USER_HANDLER_H */
