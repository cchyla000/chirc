#ifndef CHIRC_CTX_H
#define CHIRC_CTX_H

#include <pthread.h>
#include "../lib/uthash.h"
#include "user.h"
#include "channel.h"

#define MAX_MSG_LEN 512

struct ctx_t 
{
    struct chirc_user_t *users;
    struct chirc_channel_t *channels;
    char *server_name;
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
