#include <pthread.h>
#include "uthash.h"
#include "user.h"

#ifndef CHIRC_CHANNEL_H
#define CHIRC_CHANNEL_H

typedef struct {
   char channel_name[50];
   chirc_user_t *users; // hash of users in channel
   bool lock_enabled;
   pthread_mutex_t lock;
   UT_hash_handle hh;
} chirc_channel_t;

int *create_channel(ctx_t *ctx);
int *add_user_to_channel(chirc_channel_t *channel, chirc_user_t *user);
int *remove_user_from_channel(chirc_channel_t *channel, chirc_user_t *user);
int *update_user_nick_in_channel(chirc_channel_t *channel, char *old_nick,
                                                              char *new_nick);
int *destroy_channel(ctx_t *ctx, chirc_channel_t *channel);

#endif /* CHIRC_CHANNEL_H */
