/*
 *  FILENAME: message.h
 *  DESCRIPTION: Structures and functions for manipulating IRC messages
 *  AUTHORS: Cameron Chyla and Artur Genser (acknowledgement to CMSC 23320)
 *  LAST DATE MODIFIED: January 30th, 2020
 */

#ifndef CHIRC_MESSAGE_H
#define CHIRC_MESSAGE_H

#include <stdbool.h>

#define MAX_PARAMS 15

/* Struct to contain the prefix, command, and parameters for a given message */
struct chirc_message_t {
    char *prefix;
    char *cmd;
    char *params[MAX_PARAMS];
    unsigned int nparams;
    bool longlast;
};


/* NAME: chirc_message_from_string
 *
 * DESCRIPTION: Given a string ending in "\r\n", parses the string into a
 * chirc_message_t.
 *
 * PARAMETERS:
 *  msg - message struct where parsed string will be stored
 *  s - string to be parsed into a message
 *
 * RETURN: The number of characters parsed
 */
int chirc_message_from_string(struct chirc_message_t *msg, char *s);

/* NAME: chirc_message_to_string
 *
 * DESCRIPTION: Given a message, parses the message into a string
 *
 * PARAMETERS:
 *  msg - message to be converted to string
 *  s - string for converted message to be stored in
 *
 * RETURN: 0 always
 */
int chirc_message_to_string(struct chirc_message_t *msg, char *s);

/* NAME: chirc_message_construct
 *
 * DESCRIPTION: Given a message, sets the prefix and command and number of
 * params to zero. Should be given an empty message.
 *
 * PARAMETERS:
 *  msg - empty message
 *  prefix - the desired prefix for the message (NULL for no prefix)
 *  cmd - the desired command (e.g. "NICK")
 *
 * RETURN: 0 always
 */
int chirc_message_construct(struct chirc_message_t *msg, char *prefix, char *cmd);

/* NAME: chirc_message_add_parameter
 *
 * DESCRIPTION: Adds given parameter to a given message
 *
 * PARAMETERS:
 *  msg - message to add parameter to
 *  param - string to add as parameter
 *  longlast - saves if the last parameter should be treated as long
 *
 * RETURN: 0 if succesful, 1 if tried to add parameter to message that had
 * maximum number of parameters already.
 */
int chirc_message_add_parameter(struct chirc_message_t *msg, char *param,
                                                                bool longlast);

/* NAME: chirc_message_clear
 *
 * DESCRIPTION: Given a message, sets all of the memory to zeros. Used commonly
 * before message construct.
 *
 * PARAMETERS:
 *  msg - message to be cleared
 *
 * RETURN: 0 always
 */
int chirc_message_clear(struct chirc_message_t *msg);

#endif /* CHIRC_MESSAGE_H */
