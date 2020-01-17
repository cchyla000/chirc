#ifndef CHIRC_USER_H
#define CHIRC_USER_H

#include "../lib/uthash.h"
#include "message.h"
#include "channel.h"

struct chirc_user_t {
    char nick[50];
    char *user;
    int socket;
    struct chirc_channel_t *channels; // hash of channels user is a part of
    bool is_registered;
    UT_hash_handle hh;
};

void *service_user(void *args);

#endif /* CHIRC_USER_H */
