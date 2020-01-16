#include <stdio.h>
#include <stdlib.h>
#include "user.h"

void *service_user(void *args)
{
    struct worker_args *wa;
    int client_socket, nbytes;
    char buffer[MAX_MSG_LENGTH];
    char tosend[MAX_MSG_LENGTH];

    wa = (struct worker_args*) args;
    client_socket = wa->socket;

    /*
     * Tells the pthread library that no other thread is going to
     * join() this thread, so we can free its resources at termination 
     */
    pthread_detach(pthread_self());

    while(1)
    {
        nbytes = recv(client_socket, buffer, MAX_MSG_LENGTH, 0);

        if (nbytes == 0)
        {
            close(client_socket);
            free(wa);
            pthread_exit(NULL);
        }
 
    }
 
}

