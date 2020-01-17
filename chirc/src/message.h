#ifndef CHIRC_MESSAGE_H
#define CHIRC_MESSAGE_H

#include <stdbool.h>

#define MAX_PARAMS 15

struct chirc_message_t {
    char *prefix;
    char *cmd;
    char *params[MAX_PARAMS];
    unsigned int nparams;
    bool longlast;
};

/* 
 * Given a string ending in "\r\n", parses the string into a chirc_message_t.
 * Returns the number of characters parsed.
 */
int chirc_message_from_string(struct chirc_message_t *msg, char *s);
int chirc_message_to_string(struct chirc_message_t *msg, char **s);
int chirc_message_construct(struct chirc_message_t *msg, char *prefix, char *cmd);
int chirc_message_add_parameter(struct chirc_message_t *msg, char *param, bool longlast);
int chirc_message_destroy(struct chirc_message_t *msg);

#endif /* CHIRC_MESSAGE_H */
