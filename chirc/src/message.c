#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "message.h"

int chirc_message_from_string(struct chirc_message_t *msg, char *s)
{
    char *rest;
    char *token = NULL;
    unsigned int i; 
    rest = s;
   
    /* Parse prefix if present; no whitespace before allowed. */ 
    if (*rest == ':')  
    {
        rest++;
        token = strtok_r(rest, " ", &rest);
        msg->prefix = token;      
    }

    /* Parse command */
    token = strtok_r(rest, " ", &rest);
    msg->cmd = token;    

    /* Continue parsing until MAX_PARAMS exceeded,  
       end of message, or no more parameters detected */
    for (i=0; i < MAX_PARAMS && (*rest != '\n') && 
        (token = strtok_r(rest, " \r", &rest)); i++)
    {
        msg->params[i] = token;
    }
    
    msg->nparams = i;

    /* Must move pointer to end of message if we haven't already */
    if (i == MAX_PARAMS && (*rest != '\n'))
    {
        strtok_r(rest, "\r", &rest);    
    }

    return (rest - s); 
}

int chirc_message_to_string(struct chirc_message_t *msg, char *s)
{
    char *tmp = s;
    int i;
 
    if (msg->prefix)
    {
        *tmp = ':';
        tmp++;
        strcpy(tmp, msg->prefix);
        tmp += strlen(msg->prefix);
        tmp++;  // Whitespace 
    }

    strcpy(tmp, msg->cmd);
    tmp += strlen(msg->cmd); 

    for (i = 0; i < msg->nparams; i++)
    {
        tmp++;  // Whitespace
        strcpy(tmp, msg->params[i]);
        tmp += strlen(msg->params[i]);
    }    

    strcpy(tmp, "\r\n"); 
    return 0;
    
}

int chirc_message_construct(struct chirc_message_t *msg, char *prefix, char *cmd)
{
    msg->prefix = prefix;
    msg->cmd = cmd;
    msg->nparams = 0;
    return 0;
}

int chirc_message_add_parameter(struct chirc_message_t *msg, char *param, bool longlast)
{
    if (msg->nparams < MAX_PARAMS)
    {
        if (*param == '\0')  // No parameter specified, use wildcard
        {
            msg->params[msg->nparams] = "*";
        }
        else 
        {
            msg->params[msg->nparams] = param;
        }
        msg->nparams++;
        msg->longlast = longlast;
    }
    else 
    {
        return 1;
    }
}

int chirc_message_destroy(struct chirc_message_t *msg)
{
    memset(msg, 0, sizeof (struct chirc_message_t));
}

