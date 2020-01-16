#include "uthash.h"
#include "message.h"

#ifndef CHIRC_USER_H
#define CHIRC_USER_H

typedef struct {
    char *nick;
    char *user;
    int socket;
    bool is_registered;   
    UT_hash_handle hh;
} chirc_user_t;

void *service_user(void *args);

#endif /* CHIRC_USER_H */
