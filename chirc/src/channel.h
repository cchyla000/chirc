/*
 *  FILENAME: channel.h
 *  DESCRIPTION: Structs and functions for handling channels
 *  AUTHORS: Cameron Chyla and Artur Genser (acknowledgement to CMSC 23320)
 *  LAST DATE MODIFIED: January 30th, 2020
 */

#ifndef CHIRC_CHANNEL_H
#define CHIRC_CHANNEL_H

#include <pthread.h>

#include "../lib/uthash.h"

#define MAX_CHANNEL_NAME_LEN 50
#define MAX_NICK_LEN 9

/*
 * Forward declarations so we don't have to include connection.h,
 * ctx.h, and channel.h in each others' header files:
 */
struct chirc_user_cont_t;
struct chirc_user_t;
struct ctx_t;

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

/* NAME: create_channel
*
* DESCRIPTION: Creates and allocates memory for a channel of a given name and
* adds it to the context.
*
* PARAMETERS:
*  ctx - context of the server
*  channel_name - name of the channel to be created
*
* RETURN: the created channel
*/
struct chirc_channel_t *create_channel(struct ctx_t *ctx, char *channel_name);

/* NAME: add_user_to_channel
*
* DESCRIPTION: Adds a user to the hash of users in the channel, and adds
* the channel to the hash of channels in the user. Increments number of users
* on the channel.
*
* PARAMETERS:
*  channel - channel user should be added to
*  user - user being added to the channel
*
* RETURN: the container of the user created when adding the user to the channel
*/
struct chirc_user_cont_t *add_user_to_channel(struct chirc_channel_t *channel,
                                                    struct chirc_user_t *user);

/* NAME: add_user_to_channel
*
* DESCRIPTION: Removes a user from the hash of users in the channel, and
* removes the channel from the hash of channels in the user. Decrements number
* of users on the channel.
*
* PARAMETERS:
*  channel - channel user should be removed from
*  user - user being removed from the channel
*
* RETURN: 0 always
*/
int remove_user_from_channel(struct chirc_channel_t *channel,
                                                    struct chirc_user_t *user);

/* NAME: destroy_channel
*
* DESCRIPTION: Removes a channel from the context and then frees the allocated
* memory.
*
* PARAMETERS:
*  ctx - context of the server
*  channel - channel to be destroyed
*
* RETURN: 0 always
*/
int destroy_channel(struct ctx_t *ctx, struct chirc_channel_t *channel);

/* NAME: find_channel_in_user
*
* DESCRIPTION: Finds a given channel that a user is a member of
*
* PARAMETERS:
*  ctx - context of the server
*  user - the user where we search for the channel
*  channel_name - name of the channel to find
*
* RETURN: NULL if the channel does not exist or user is not a member, otherwise
* returns the channel
*/
struct chirc_channel_t *find_channel_in_user(struct ctx_t *ctx,
                                struct chirc_user_t *user, char *channel_name);

/* NAME: find_user_in_channel
*
* DESCRIPTION: Finds a given user in a channel
*
* PARAMETERS:
*  ctx - context of the server
*  channel - the channel where we search for the user
*  nickname - the nickname of the user we try to find
*
* RETURN: NULL if the user does not exist or is not on the channel, otherwise
* returns the user
*/
struct chirc_user_t *find_user_in_channel(struct ctx_t *ctx,
                              struct chirc_channel_t *channel, char *nickname);

#endif /* CHIRC_CHANNEL_H */
