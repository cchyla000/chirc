#ifndef CHIRC_CHANNEL_H
#define CHIRC_CHANNEL_H

#include <pthread.h>
#include "../lib/uthash.h"
#include "user.h"
#include "ctx.h"

struct chirc_channel_t {
   char channel_name[50];
   struct chirc_user_t *users; // hash of users in channel
   bool lock_enabled;
   pthread_mutex_t lock;
   UT_hash_handle hh;
};

struct chirc_channel_t *create_channel(struct ctx_t *ctx, char *channel_name);
int add_user_to_channel(struct chirc_channel_t *channel, struct chirc_user_t *user);
int remove_user_from_channel(struct chirc_channel_t *channel, struct chirc_user_t *user);
int destroy_channel(struct ctx_t *ctx, struct chirc_channel_t *channel);

#endif /* CHIRC_CHANNEL_H */
