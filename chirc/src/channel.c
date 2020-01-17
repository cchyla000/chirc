#include <stdlib.h>
#include "channel.h"
#include "user.h"

chirc_channel_t *create_channel(ctx_t *ctx, char *channel_name)
{
    chirc_channel_t *channel;
    channel = calloc(1, sizeof(channel));
    strcpy(channel->channel_name, channel_name);
    channel->users = NULL;
    pthread_mutex_init(&channel->lock, NULL);

    pthread_mutex_lock(&ctx->channels_lock);

    HASH_ADD_INT(&ctx->channels, channel_name, channel);

    pthread_mutex_unlock(&ctx->channels_lock);

    return channel;
}

int add_user_to_channel(chirc_channel_t *channel, chirc_user_t *user)
{
    pthread_mutex_lock(&channel->lock);
    HASH_ADD_INT(channel->users, user->nick, user);
    HASH_ADD_INT(user->channels, channel->channel_name, channel);
    pthread_mutex_unlock(&channel->lock);
    return 0;
}

int remove_user_from_channel(chirc_channel_t *channel, chirc_user_t *user)
{
    pthread_mutex_lock(&channel->lock);
    HASH_DEL(channel->users, user->nick);
    HASH_DEL(user->channels, channel->channel_name);
    pthread_mutex_unlock(&channel->lock);
    return 0;
}

int destroy_channel(ctx_t *ctx, chirc_channel_t *channel)
{
    pthread_mutex_lock(&ctx->channels_lock);

    HASH_DEL(&ctx->channels, channel->channel_name);

    pthread_mutex_unlock(&ctx->channels_lock);
    pthread_mutex_destroy(&channel->lock);
    free(channel);
    return 0;
}
