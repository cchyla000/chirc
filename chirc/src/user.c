#include <stdio.h>
#include <stdlib.h>
#include "user.h"

/* 
 * Worst case scenario is if we cannot parse a first message of
 * MAX_MSG_LENGTH because the last '\n' does not come in until 
 * a call to recv() that also returns a 2nd message of length 
 * MAX_MSG_LENGTH - 1; therefore, we need a buffer the size of 2
 * messages 
 */ 
#define BUFFER_LEN ((2 * MAX_MSG_LEN) + 1)

void *service_user(void *args)
{
    struct worker_args *wa;
    int client_socket, nbytes;

    char buffer[BUFFER_LEN + 1];  // + 1 for extra '\0' at end 
    char tosend[MAX_MSG_LEN];
    char *tmp;
    int bytes_in_buffer = 0;
    wa = (struct worker_args*) args;
    client_socket = wa->socket;

    chirc_message_t msg;

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
            // ...
            // ...
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

