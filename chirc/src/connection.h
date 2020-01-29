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
#define MAX_PASSWORD_LEN 63
#define MAX_PORT_LEN 5

enum connection_type { UNKNOWN, USER, SERVER };

struct chirc_server_t {
    char servername[MAX_SERVER_LEN + 1];
    char password[MAX_PASSWORD_LEN + 1];
    char hostname[MAX_HOST_LEN + 1];
    char oper_password[MAX_PASSWORD_LEN + 1];
    char port[MAX_PORT_LEN + 1];
    int socket;
    bool is_registered;
    pthread_mutex_t lock;
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
    /* Hash of channels user is a part of */
    struct chirc_channel_cont_t *channels;
    int socket;
    bool is_on_server;
    bool is_irc_operator;
    bool is_registered;
    pthread_mutex_t lock;
    UT_hash_handle hh;
    struct chirc_server_t *server;  // The server the user is on. NULL if on this server
};

/* Struct to accommadate uthash's inability to have the same pointer in more
 * than one hash. This is the struct contained in the channel's hash of users.
 * This also tells the user if they are an operator of the channel or not. */
struct chirc_user_cont_t {
    char nickname[MAX_NICK_LEN + 1];
    struct chirc_user_t *user; // is NULL if user not on this server
    bool is_channel_operator;
    UT_hash_handle hh;
};

struct chirc_connection_t {
    enum connection_type type;
    struct chirc_user_t *user; // is NULL if not user
    struct chirc_server_t *server; // is NULL if not server
};


/* Function that is used to run the thread when a new connection is recieved.
 * Parses the incoming messages and sends them to the appropriate message
 * handler using a dispath table. */
void *service_connection(void *args);

void destroy_connection(struct chirc_connection_t *connection, struct ctx_t *ctx);

#endif /* CHIRC_CONNECTION_H */
