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
#define PORT_LEN 5

/* The data to be shared about the channel among all threads. Contains two
 * locks: one for the hash of channels, one for the hash of users and the number
 * of each type of user. */
struct ctx_t
{
    /*  Hash of user containers that say which server the user is on and
     *  either points to a user or the server they are on
     */
    struct chirc_user_cont_t *users;
    struct chirc_channel_t *channels;
    struct chirc_server_t *servers;
    char server_name[MAX_HOST_LEN + 1];
    char server_hostname[MAX_HOST_LEN + 1];
    char date_created[DATE_LEN];
    char password[MAX_MSG_LEN];
    char port[PORT_LEN];
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
