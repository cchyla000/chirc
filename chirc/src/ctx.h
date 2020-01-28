#ifndef CHIRC_CTX_H
#define CHIRC_CTX_H

#include <pthread.h>
#include <netdb.h>

#include "../lib/uthash.h"
#include "connection.h"
#include "channel.h"

#define MAX_MSG_LEN 512
/* Need 20 chars to hold date of format: yyyy-mm-dd hh:mm:ss\0 */
#define DATE_LEN 20
#define MAX_HOST_LEN 63

struct ctx_t
{
    /*  Hash of user containers that say which server the user is on and
     *  either points to a user or the server they are on
     */
    struct chirc_user_t *users;
    struct chirc_channel_t *channels;
    struct chirc_server_t *servers;  // Servers connected to this server
    struct chirc_server_t *this_server;
    char date_created[DATE_LEN];
    int num_clients;
    int unknown_clients;
    int connected_clients;
    int num_operators;
    pthread_mutex_t users_lock;
    pthread_mutex_t channels_lock;
    pthread_mutex_t servers_lock;
};

/* The set of variables that each thread will receive */
struct worker_args
{
    int socket;
    /* Used with getnameinfo() to get client hostname, which is the
       IP address if hostname cannot be resolved, as IRC specs require */
    struct sockaddr *client_addr;
    struct ctx_t *ctx;
};

#endif /* CHIRC_CTX_H */
