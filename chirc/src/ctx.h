#ifndef CHIRC_CTX_H
#define CHIRC_CTX_H

#include <pthread.h>
#include "../lib/uthash.h"
#include "user.h"
#include "channel.h"
#include <netdb.h>

#define MAX_MSG_LEN 512
/* Need 20 chars to hold date of format: yyyy-mm-dd hh:mm:ss\0 */
#define DATE_LEN 20 
#define MAX_HOST_LEN 63

struct ctx_t 
{
    struct chirc_user_t *users;
    struct chirc_channel_t *channels;
    char server_name[MAX_HOST_LEN + 1];
    char date_created[DATE_LEN];  
    char password[MAX_MSG_LEN];
    int unknown_clients;
    int connected_clients;
    int num_operators;
    pthread_mutex_t users_lock;
    pthread_mutex_t channels_lock;
};

struct worker_args
{
    int socket;
    /* Used with getnameinfo() to get client hostname, which is the  
       IP address if hostname cannot be resolved, as IRC specs require */
    struct sockaddr *client_addr; 
    struct ctx_t *ctx;
};

#endif /* CHIRC_CTX_H */
