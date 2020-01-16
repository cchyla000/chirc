#include <pthread.h>
#include "uthash.h"
#include "user.h"
#include "channel.h"

#ifndef CHIRC_MAIN_H
#define CHIRC_MAIN_H

typedef struct server_ctx
{
    chirc_user_t *users;
    chirc_channel_t *channels;
    bool users_lock_enabled;
    pthread_mutex_t users_lock;
    bool channels_lock_enabled;
    pthread_mutex_t channels_lock;
} ctx_t;

struct worker_args
{
    int socket;
    /* ADDED: We need to pass the server context to the worker thread */
    ctx_t *ctx;
};

#endif /* CHIRC_MAIN_H */
