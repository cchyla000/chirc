#ifndef CHIRC_CONNECTION_H
#define CHIRC_CONNECTION_H

#include <stdbool.h>

#include "../lib/uthash.h"
#include "message.h"
#include "channel.h"
#include "ctx.h"

#define MAX_NICK_LEN 9
#define MAX_HOST_LEN 63
#define MAX_USER_LEN 9
#define MAX_SERVER_LEN 255
#defien MAX_CONNECTION_LEN 7 // UNKNOWN is longest

/* Struct to accommadate uthash's inability to have the same pointer in more
 * than one hash. This is the struct contained in the channel's hash of users.
 * This also tells the user if they are an operator of the channel or not. */
struct chirc_user_cont_t {
    char nickname[MAX_NICK_LEN + 1];
    bool on_this_server;
    chirc_user_t *user; // is NULL if user not on this server
    chirc_server_t *server; // is NULL if user on this server
    bool is_channel_operator;
    UT_hash_handle hh;
};

/* Struct to keep track of an individual user's informaion and its connection */
struct chirc_user_t {
    char nickname[MAX_NICK_LEN + 1];
    char username[MAX_USER_LEN + 1];
    char hostname[MAX_HOST_LEN + 1];
    /* Host name limited to 63 chars in specifications, so
       real user name can realistically be similarly truncated: */
    char realusername[MAX_HOST_LEN + 1];
    int socket;
    struct chirc_channel_cont_t *channels; // Hash of channels user is a part of
    bool is_registered;
    bool is_irc_operator;
    pthread_mutex_t lock;
    UT_hash_handle hh;
};

/* Struct to keep track of an individual user's informaion and its connection */
struct chirc_server_t {
    char servername[MAX_SERVER_LEN + 1];
    int socket;
    pthread_mutex_t lock;
    UT_hash_handle hh;
};

struct chirc_connection_t {
    char connection_type[MAX_CONNECTION_LEN + 1]; // "UNKNOWN", "USER", or "SERVER"
    int socket;
    chirc_user_t *user; // is NULL if not user
    chirc_server_t *server; // is NULL if not server
}

/* Function that is used to run the thread when a new connection is recieved.
 * Parses the incoming messages and sends them to the appropriate message
 * handler using a dispath table. */
void *service_connection(void *args);

/*
 * Removes user from all of its channels and frees the
 * user struct associated with the thread handling this user,
 */
void destroy_user(struct chirc_user_t *user, struct ctx_t *ctx);

#endif /* CHIRC_CONNECTION_H */
