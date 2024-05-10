#ifndef TYPES
#define TYPES

typedef struct sockaddr_in socket_server_address;
typedef struct sockaddr* socket_address_ptr;

typedef enum /* authentication_type */ {login, signup} auth_type;
typedef enum {command, message} request_type;
typedef enum {READ, COMPOSE} command_type;
typedef enum message_type {notification, messaage} msg_t;

typedef struct pub_key{
    char username[256];
    unsigned char p_key[256];
} p_key_t;

typedef struct auth_token{
	auth_type type;
	char username[32];
	char password[32];
}auth_token_t ;

typedef struct command {
	command_type command;
    char argument[32];
} command_t;

typedef struct message {
    enum message_type type;
    char sender[32];
    char recipient[32];
    char message[512];
    unsigned char digest[256];
} message_t;

typedef struct request {
    request_type type;
    command_t command;
    message_t message;
} request_t;


typedef struct message_node{   
    message_t *message;
    struct message_node *next;
} message_node_t;

typedef struct {
    char username[256];
    char password[256];
} user_t;

void set_request(request_t *r, request_type rt, command_t *cmd, message_t* msg) {
    r->type = rt;
    if (cmd) r->command = *cmd;
    if (msg) r->message = *msg;
}
#endif