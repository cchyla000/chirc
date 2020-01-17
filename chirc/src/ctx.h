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
    pthread_mutex_t users_lock;
    pthread_mutex_t channels_lock;
};

struct worker_args
{
    int socket;
    /* ADDED: We need to pass the server context to the worker thread */
    struct ctx_t *ctx;
};

#endif /* CHIRC_CTX_H */
