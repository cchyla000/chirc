#include <stdlib.h>

#include "channel.h"
#include "user.h"
#include "ctx.h"
#include "log.h"


struct chirc_channel_t *create_channel(struct ctx_t *ctx, char *channel_name)
{
    struct chirc_channel_t *channel;
    channel = calloc(1, sizeof(struct chirc_channel_t));
    strcpy(channel->channel_name, channel_name);
    channel->users = NULL;
    pthread_mutex_init(&channel->lock, NULL);

    pthread_mutex_lock(&ctx->channels_lock);
    HASH_ADD_STR(ctx->channels, channel_name, channel);
    pthread_mutex_unlock(&ctx->channels_lock);

    return channel;
}

struct chirc_user_cont_t *
add_user_to_channel(struct chirc_channel_t *channel, struct chirc_user_t *user)
{
    struct chirc_user_cont_t *user_container;
    user_container = calloc(1, sizeof(struct chirc_user_cont_t));
    strcpy(user_container->nickname, user->nickname);
    struct chirc_channel_cont_t *channel_container;
    channel_container = calloc(1, sizeof(struct chirc_channel_cont_t));
    strcpy(channel_container->channel_name, channel->channel_name);

    pthread_mutex_lock(&channel->lock);
    pthread_mutex_lock(&user->lock);
    HASH_ADD_STR(channel->users, nickname, user_container);
    HASH_ADD_STR(user->channels, channel_name, channel_container);
    channel->nusers++;
    pthread_mutex_unlock(&user->lock);
    pthread_mutex_unlock(&channel->lock);

    return user_container;
}

int remove_user_from_channel(struct chirc_channel_t *channel,
                                                      struct chirc_user_t *user)
{
    struct chirc_user_cont_t *user_container;
    struct chirc_channel_cont_t *channel_container;

    pthread_mutex_lock(&channel->lock);
    pthread_mutex_lock(&user->lock);

    HASH_FIND_STR(channel->users, user->nickname, user_container);
    HASH_FIND_STR(user->channels, channel->channel_name, channel_container);
    HASH_DEL(channel->users, user_container);
    HASH_DEL(user->channels, channel_container);
    channel->nusers--;
    pthread_mutex_unlock(&user->lock);
    pthread_mutex_unlock(&channel->lock);

    return 0;
}

int destroy_channel(struct ctx_t *ctx, struct chirc_channel_t *channel)
{
    pthread_mutex_lock(&ctx->channels_lock);
    HASH_DEL(ctx->channels, channel);
    pthread_mutex_unlock(&ctx->channels_lock);
    pthread_mutex_destroy(&channel->lock);
    free(channel);

    return 0;
}

struct chirc_channel_t *find_channel_in_user(struct ctx_t *ctx, struct chirc_user_t *user, char *channel_name)
{
    struct chirc_channel_cont_t *channel_container;
    struct chirc_channel_t *channel;

    pthread_mutex_lock(&user->lock);
    HASH_FIND_STR(user->channels, channel_name, channel_container);
    pthread_mutex_unlock(&user->lock);
    if (channel_container)
    {
        pthread_mutex_lock(&ctx->channels_lock);
        HASH_FIND_STR(ctx->channels, channel_name, channel);
        pthread_mutex_unlock(&ctx->channels_lock);
        return channel;
    }

    return NULL;
}

struct chirc_user_t *find_user_in_channel(struct ctx_t *ctx, struct chirc_channel_t *channel, char *nickname)
{
    struct chirc_user_cont_t *user_container;
    struct chirc_user_t *user;

    pthread_mutex_lock(&channel->lock);
    HASH_FIND_STR(channel->users, nickname, user_container);
    pthread_mutex_unlock(&channel->lock);
    if (user_container)
    {
        pthread_mutex_lock(&ctx->users_lock);
        HASH_FIND_STR(ctx->users, nickname, user);
        pthread_mutex_unlock(&ctx->users_lock);
        return user;
    }

    return NULL;
}
