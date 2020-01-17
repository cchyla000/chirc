#ifndef CHIRC_CTX_H
#define CHIRC_CTX_H

#include <pthread.h>
#include "../lib/uthash.h"
#include "user.h"
#include "channel.h"

#define MAX_MSG_LEN 512

typedef struct server_ctx
{
    chirc_user_t *users;
    chirc_channel_t *channels;
    pthread_mutex_t users_lock;
    pthread_mutex_t channels_lock;
} ctx_t;

struct worker_args
{
    int socket;
    /* ADDED: We need to pass the server context to the worker thread */
    ctx_t *ctx;
};

#endif /* CHIRC_CTX_H */
