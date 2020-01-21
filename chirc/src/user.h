#ifndef CHIRC_USER_H
#define CHIRC_USER_H

#include <stdbool.h>
#include "../lib/uthash.h"
#include "message.h"
#include "channel.h"
#include "ctx.h"

#define MAX_NICK_LEN 9
#define MAX_HOST_LEN 63
#define MAX_USER_LEN 9 

struct chirc_user_t {
    char nickname[MAX_NICK_LEN + 1];
    char username[MAX_USER_LEN + 1];
    char hostname[MAX_HOST_LEN + 1];
    /* Host name limited to 63 chars in specifications, so 
       real user name can realistically be similarly truncated: */ 
    char realusername[MAX_HOST_LEN + 1];  
    int socket;
    struct chirc_channel_t *channels; // Hash of channels user is a part of
    bool is_registered;
    pthread_mutex_t lock;
    UT_hash_handle hh;
};

void *service_user(void *args);

/*
 * Removes user from all of its channels and frees the 
 * user struct associated with the thread handling this user,
 */
void destroy_user(struct chirc_user_t *user, struct ctx_t *ctx);

#endif /* CHIRC_USER_H */
