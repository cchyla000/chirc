#include <stdlib.h>
#include "channel.h"
#include "user.h"
#include "ctx.h"

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

int add_user_to_channel(struct chirc_channel_t *channel, struct chirc_user_t *user)
{
    pthread_mutex_lock(&channel->lock);
    pthread_mutex_lock(&user->lock);
    HASH_ADD_STR(channel->users, nickname, user);
    HASH_ADD_STR(user->channels, channel_name, channel);
    channel->nusers++;
    pthread_mutex_unlock(&user->lock);
    pthread_mutex_unlock(&channel->lock);
    return 0;
}

int remove_user_from_channel(struct chirc_channel_t *channel, struct chirc_user_t *user)
{
    pthread_mutex_lock(&channel->lock);
    pthread_mutex_lock(&user->lock);
    HASH_DEL(channel->users, user);
    HASH_DEL(user->channels, channel);
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
