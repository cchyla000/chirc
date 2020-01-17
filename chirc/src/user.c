#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <time.h>

#include "user.h"
#include "handler.h"

/*
 * Worst case scenario is if we cannot parse a first message of
 * MAX_MSG_LENGTH because the last '\n' does not come in until
 * a call to recv() that also returns a 2nd message of length
 * MAX_MSG_LENGTH - 1; therefore, we need a buffer the size of 2
 * messages
 */
#define MAX_MSG_LEN 512
#define BUFFER_LEN ((2 * MAX_MSG_LEN) + 1)

typedef int (*handler_function)(struct ctx_t *ctx, struct chirc_message_t *msg,
                                struct chirc_user_t *user);

struct handler_entry
{
    char *name;
    handler_function func;
};

#define HANDLER_ENTRY(NAME) { #NAME, handle_ ## NAME}

struct handler_entry handlers[] = {
                                     HANDLER_ENTRY(NICK),
                                     HANDLER_ENTRY(USER),
                                     HANDLER_ENTRY(QUIT),
                                     HANDLER_ENTRY(PRIVMSG),
                                     HANDLER_ENTRY(NOTICE),
                                     HANDLER_ENTRY(PING),
                                     HANDLER_ENTRY(PONG),
                                     HANDLER_ENTRY(LUSERS),
                                     HANDLER_ENTRY(WHOIS),
                                     HANDLER_ENTRY(JOIN),
                                     HANDLER_ENTRY(PART),
                                     HANDLER_ENTRY(PART),
                                     HANDLER_ENTRY(MODE),
                                     HANDLER_ENTRY(LIST),
                                     HANDLER_ENTRY(OPER)
                                  };

int num_handlers = sizeof(handlers) / sizeof(struct handler_entry);

void *service_user(void *args)
{
    struct worker_args *wa;
    int client_socket, nbytes, i;
    struct ctx_t *ctx;
    struct chirc_user_t *user;

    char buffer[BUFFER_LEN + 1];  // + 1 for extra '\0' at end
    char tosend[MAX_MSG_LEN];
    char *tmp;
    int bytes_in_buffer = 0;
    wa = (struct worker_args*) args;
    user = calloc(1, sizeof(struct chirc_user_t *));
    client_socket = wa->socket;
    memset(user, 0, sizeof (struct chirc_user_t));
    user->socket = client_socket;
    ctx = wa->ctx;

    struct chirc_message_t msg;
    char *cmd;

    /*
     * Tells the pthread library that no other thread is going to
     * join() this thread, so we can free its resources at termination
     */
    pthread_detach(pthread_self());

    while(1)
    {
        nbytes = recv(client_socket, &buffer[bytes_in_buffer],
                     (BUFFER_LEN - bytes_in_buffer), 0);

        if (nbytes == 0)
        {
            close(client_socket);
            free(wa);
            pthread_exit(NULL);
        }
        bytes_in_buffer += nbytes;

        tmp = buffer;
        while (strstr(tmp, "\r\n") != NULL)
        {
            memset(&msg, 0, sizeof(msg));
            nbytes = chirc_message_from_string(&msg, tmp);

            /* Point to beginning of next msg if present. */
            tmp += (nbytes + 1);

            /* Send msg to handler */
            char *cmd = msg.cmd;
            for(i=0; i<num_handlers; i++)
                if (!strcmp(handlers[i].name, cmd))
                {
                    handlers[i].func(ctx, &msg, user);
                    break;
                }

            if(i == num_handlers)
            {
                /* not a known command */
            }
        }

        /* Clear Buffer */
        if (*tmp == '\0')  // No next message, so reset buffer
        {
            memset(buffer, '\0', BUFFER_LEN);
            bytes_in_buffer = 0;
        }
        else
        {
            /* Another message already started in buffer,
               so move it to the front of the buffer. */
            strcpy(buffer, tmp);
            bytes_in_buffer = bytes_in_buffer - (tmp - buffer);
            memset(&buffer[bytes_in_buffer], '\0',
                  (BUFFER_LEN - bytes_in_buffer));
        }

    }

}
