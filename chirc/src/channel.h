#ifndef CHIRC_CHANNEL_H
#define CHIRC_CHANNEL_H

#include <pthread.h>

#include "../lib/uthash.h"
#include "user.h"
#include "ctx.h"

#define MAX_CHANNEL_NAME_LEN 50
#define MAX_NICK_LEN 9

/* Struct to accommadate uthash's inability to have the same pointer in more
 * than one hash. This is the struct contained in the user's hash of channels */
struct chirc_channel_cont_t {
    char channel_name[MAX_CHANNEL_NAME_LEN + 1];
    UT_hash_handle hh;
};

/* Struct to keep track of an individual channel and which users are in it */
struct chirc_channel_t {
   char channel_name[MAX_CHANNEL_NAME_LEN + 1];
   struct chirc_user_cont_t *users; // hash of users in channel
   unsigned int nusers;
   pthread_mutex_t lock;
   UT_hash_handle hh;
};

/* Creates and allocates memory for a channel of a given name and adds it to
 * the context */
struct chirc_channel_t *create_channel(struct ctx_t *ctx, char *channel_name);

/* Adds a user to the hash of users in the channel, and adds the channel to
 * the hash of channels in the user */
struct chirc_user_cont_t *add_user_to_channel(struct chirc_channel_t *channel, struct chirc_user_t *user);

/* Removes a user from the hash of users in the channel, and removes the channel
 * from the hash of channels in the user */
int remove_user_from_channel(struct chirc_channel_t *channel, struct chirc_user_t *user);

/* Removes a channel from the context and then frees the allocated memory */
int destroy_channel(struct ctx_t *ctx, struct chirc_channel_t *channel);

/* Returns a pointer to a channel if the given user is a member of a channel
 * of the given name. Returns NULL if either the channel does not exist or the
 * user is not a member */
struct chirc_channel_t *find_channel_in_user(struct ctx_t *ctx, struct chirc_user_t *user, char *channel_name);

/* Returns a pointer to a user if the given channel has a member of the given
 * nickname. Returns NULL if there is no member of that given nickname */
struct chirc_user_t *find_user_in_channel(struct ctx_t *ctx, struct chirc_channel_t *channel, char *nickname);

#endif /* CHIRC_CHANNEL_H */
