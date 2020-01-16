#ifndef CHIRC_MESSAGE_H
#define CHIRC_MESSAGE_H

typedef struct {
    char *prefix;
    char *cmd;
    char *params[15];
    unsigned int nparams;
    bool longlast;
} chirc_message_t;

int chirc_message_from_string(chirc_message_t *msg, char *s);
int chirc_message_to_string(chirc_message_t *msg, char **s);
int chirc_message_construct(chirc_message_t *msg, char *prefix, char *cmd);
int chirc_message_add_parameter(chirc_message_t *msg, char *param, bool longlast);
int chirc_message_destroy(chirc_message_t *msg);

#endif /* CHIRC_MESSAGE_H */
