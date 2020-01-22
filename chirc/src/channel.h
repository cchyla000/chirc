#ifndef CHIRC_CHANNEL_H
#define CHIRC_CHANNEL_H

#include <pthread.h>
#include "../lib/uthash.h"
#include "user.h"
#include "ctx.h"

#define MAX_CHANNEL_NAME_LEN 50
#define MAX_NICK_LEN 9

struct chirc_channel_cont_t {
    char channel_name[MAX_CHANNEL_NAME_LEN + 1];
    UT_hash_handle hh;
};

struct chirc_user_cont_t {
    char nickname[MAX_NICK_LEN + 1];
    bool is_channel_operator;
    UT_hash_handle hh;
};

struct chirc_channel_t {
   char channel_name[MAX_CHANNEL_NAME_LEN + 1];
   struct chirc_user_cont_t *users; // hash of users in channel
   unsigned int nusers;
   pthread_mutex_t lock;
   UT_hash_handle hh;
};

struct chirc_channel_t *create_channel(struct ctx_t *ctx, char *channel_name);

struct chirc_user_cont_t *add_user_to_channel(struct chirc_channel_t *channel, struct chirc_user_t *user);

int remove_user_from_channel(struct chirc_channel_t *channel, struct chirc_user_t *user);
int destroy_channel(struct ctx_t *ctx, struct chirc_channel_t *channel);

struct chirc_channel_t *find_channel_in_user(struct ctx_t *ctx, struct chirc_user_t *user, char *channel_name);

struct chirc_user_t *find_user_in_channel(struct ctx_t *ctx, struct chirc_channel_t *channel, char *nickname);

#endif /* CHIRC_CHANNEL_H */
