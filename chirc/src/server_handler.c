#include "server_handler.h"
#include "reply.h"
#include <stdio.h>
#include "log.h"

static int send_message_to_server(struct chirc_message_t *msg, struct chirc_server_t *server)
{
    int nbytes;
    char to_send[MAX_MSG_LEN + 1] = {0};
    chirc_message_to_string(msg, to_send);

    pthread_mutex_lock(&server->lock);
    nbytes = send(server->socket, to_send, strlen(to_send), 0);
    pthread_mutex_unlock(&server->lock);

    if (nbytes == -1)
    {
        return -1;
    }

    return 0;
}

static int handle_not_registered(struct ctx_t *ctx, struct chirc_server_t *server)
{
    int error;
    struct chirc_message_t reply_msg;
    chirc_message_clear(&reply_msg);
    struct chirc_server_t *this_server = ctx->this_server;

    if (!server->is_registered)
    {
        chirc_message_construct(&reply_msg, this_server->servername,
                                ERR_NOTREGISTERED);
        chirc_message_add_parameter(&reply_msg, server->servername, false);
        chirc_message_add_parameter(&reply_msg, "You have not registered",
                                    true);
        error = send_message_to_server(&reply_msg, server);
        if (error)
        {
            return -1;
        }
        else
        {
            return 1;
        }
    }
    return 0;
}

static int handle_not_enough_parameters(struct ctx_t *ctx,
            struct chirc_message_t *msg, struct chirc_server_t *server, int nparams)
{
    struct chirc_message_t reply_msg;
    int error = 0;
    struct chirc_server_t *this_server = ctx->this_server;

    if (msg->nparams < nparams)  // Not enough parameters
    {
        chirc_message_construct(&reply_msg, this_server->servername,
                                ERR_NEEDMOREPARAMS);
        chirc_message_add_parameter(&reply_msg, server->servername, false);
        chirc_message_add_parameter(&reply_msg, msg->cmd, false);
        chirc_message_add_parameter(&reply_msg,
                                    "Not enough parameters", true);
        error = send_message_to_server(&reply_msg, server);
        if (error)
        {
            return -1;
        }
        else
        {
            return 1;
        }
    }
    return error;
}

static int server_complete_registration(struct ctx_t *ctx,
             struct chirc_message_t *msg, struct chirc_server_t *server)
{
    chilog(DEBUG, "server completing registration");
    char param_buffer[MAX_MSG_LEN + 1] = {0};
    struct chirc_server_t *network_server = NULL;
    struct chirc_server_t *this_server = ctx->this_server;
    int error;
    struct chirc_message_t reply_msg;
    chirc_message_clear(&reply_msg);

    chilog(DEBUG, "Expected:");
    chilog(DEBUG, this_server->password);
    chilog(DEBUG, "Got: ");
    chilog(DEBUG, server->password);
    if (strcmp(this_server->password, server->password))
    {
        chilog(DEBUG, "incorrect password");
        /* Incorrect password */
        server->is_registered = true;
        chirc_message_construct(&reply_msg, this_server->servername,
                                "ERROR");
        chirc_message_add_parameter(&reply_msg, "Bad password", true);
        error = send_message_to_server(&reply_msg, server);
        return error;
    }

    HASH_FIND_STR(ctx->servers, server->servername, network_server);

    if (!network_server)
    {
      /* Server not in network specification file */
      chilog(DEBUG, "server not in network file");
      chirc_message_construct(&reply_msg, this_server->servername,
                              "ERROR");
      chirc_message_add_parameter(&reply_msg,
                                  "Server not configured here", true);
      error = send_message_to_server(&reply_msg, server);
    }
    else if (network_server->is_registered)
    {
      /* Server already registered */
      chilog(DEBUG, "server already registered");
      chirc_message_construct(&reply_msg, this_server->servername,
                              "ERROR");
      sprintf(param_buffer, "ID \"%s\" already registered", server->servername);
      chirc_message_add_parameter(&reply_msg, param_buffer, true);
      error = send_message_to_server(&reply_msg, server);
    }
    else
    {
        chilog(DEBUG, "Sending PASS and SERVER replies");
        network_server->is_registered = true;
        chirc_message_construct(&reply_msg, this_server->servername,
                                "PASS");
        chirc_message_add_parameter(&reply_msg, network_server->password, false);
        chirc_message_add_parameter(&reply_msg, "0210", false);
        chirc_message_add_parameter(&reply_msg, "chirc|0.5.1", false);
        error = send_message_to_server(&reply_msg, server);

        chirc_message_construct(&reply_msg, this_server->servername,
                                "SERVER");
        chirc_message_add_parameter(&reply_msg, this_server->servername, false);
        chirc_message_add_parameter(&reply_msg, "1", false);
        chirc_message_add_parameter(&reply_msg, "chirc server", true);
        error = send_message_to_server(&reply_msg, server);
        chilog(DEBUG, "Sent PASS and SERVER replies");

        server->is_registered = true;
        strncpy(server->password, network_server->password, MAX_PASSWORD_LEN);
        strncpy(server->port, network_server->port, MAX_PORT_LEN);

        HASH_DEL(ctx->servers, network_server);
        HASH_ADD_STR(ctx->servers, servername, server);
    }
    return error;
}

int handle_NICK_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_server_t *server)
{
    return 0;
}

int handle_USER_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_server_t *server)
{
    return 0;
}

int handle_QUIT_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_server_t *server)
{
    return 0;
}

int handle_PRIVMSG_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_server_t *server)
{
    return 0;
}

int handle_NOTICE_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_server_t *server)
{
    return 0;
}

int handle_PING_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_server_t *server)
{
    return 0;
}

int handle_PONG_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_server_t *server)
{
    return 0;
}

int handle_LUSERS_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_server_t *server)
{
    return 0;
}

int handle_WHOIS_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_server_t *server)
{
    return 0;
}

int handle_JOIN_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_server_t *server)
{
    return 0;
}

int handle_MODE_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_server_t *server)
{
    return 0;
}

int handle_LIST_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_server_t *server)
{
    return 0;
}

int handle_OPER_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_server_t *server)
{
    return 0;
}

int handle_PART_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_server_t *server)
{
    return 0;
}

int handle_PASS_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_server_t *server)
{
    int error;
    struct chirc_message_t reply_msg;
    chirc_message_clear(&reply_msg);
    struct chirc_server_t *this_server = ctx->this_server;

    if ((error = handle_not_enough_parameters(ctx, msg, server, 3)))
    {
        return error;
    }
    else if (server->is_registered)
    {
        chirc_message_construct(&reply_msg, this_server->servername,
                                ERR_ALREADYREGISTERED);
        chirc_message_add_parameter(&reply_msg, server->servername, false);
        chirc_message_add_parameter(&reply_msg, "Unauthorized command "
                                    "(already registered)", true);
        error = send_message_to_server(&reply_msg, server);
    }
    else
    {
        chilog(DEBUG, "About to set password");
        strncpy(server->password, msg->params[0], MAX_PASSWORD_LEN);

        /* Complete Registration */
        if (*server->servername != '\0')
        {
            server_complete_registration(ctx, msg, server);
        }
    }
}

int handle_SERVER_SERVER(struct ctx_t *ctx, struct chirc_message_t *msg,
                                         struct chirc_server_t *server)
{
    int error;
    struct chirc_message_t reply_msg;
    chirc_message_clear(&reply_msg);
    struct chirc_server_t *this_server = ctx->this_server;

    if (server->is_registered)
    {
        chirc_message_construct(&reply_msg, this_server->servername,
                                ERR_ALREADYREGISTERED);
        chirc_message_add_parameter(&reply_msg, server->servername, false);
        chirc_message_add_parameter(&reply_msg, "Unauthorized command "
                                  "(already registered)", true);
        error = send_message_to_server(&reply_msg, server);
    }
    else if (msg->params[0] != NULL)
    {
        chilog(DEBUG, "About to set servername");
        strncpy(server->servername, msg->params[0], MAX_SERVER_LEN);
        if (*server->password != '\0')
        {
            server_complete_registration(ctx, msg, server);
        }

    }
    return 0;
}
