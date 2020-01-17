#ifndef CHIRC_CHANNEL_H
#define CHIRC_CHANNEL_H

#include <pthread.h>
#include "../lib/uthash.h"
#include "user.h"
#include "ctx.h"

typedef struct {
   char channel_name[50];
   chirc_user_t *users; // hash of users in channel
   bool lock_enabled;
   pthread_mutex_t lock;
   UT_hash_handle hh;
} chirc_channel_t;

chirc_channel_t *create_channel(ctx_t *ctx, char *channel_name);
int add_user_to_channel(chirc_channel_t *channel, chirc_user_t *user);
int remove_user_from_channel(chirc_channel_t *channel, chirc_user_t *user);
int destroy_channel(ctx_t *ctx, chirc_channel_t *channel);

#endif /* CHIRC_CHANNEL_H */
