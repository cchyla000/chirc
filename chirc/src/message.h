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

/* Given a string ending in "\r\n", parses the string into a chirc_message_t.
 * Returns the number of characters parsed */
int chirc_message_from_string(struct chirc_message_t *msg, char *s);

/* Given a message, returns the string that parses to that message */
int chirc_message_to_string(struct chirc_message_t *msg, char *s);

/* Given a message, sets the prefix and command and number of params to zero.
 * Should be given an empty message. */
int chirc_message_construct(struct chirc_message_t *msg, char *prefix, char *cmd);

/* Given a message and a string, adds the string as a parameter and indicates
 * if the parameter should be treated as a longlast parameter. */
int chirc_message_add_parameter(struct chirc_message_t *msg, char *param, bool longlast);

/* Given a message, sets all of the memory to zeros. */
int chirc_message_clear(struct chirc_message_t *msg);

#endif /* CHIRC_MESSAGE_H */
