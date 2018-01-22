/********************************************************
 **  Authors: Alessandro Di Stanislao, alessand.distanislao@studio.unibo.it
 **           Carlo Caini (project supervisor), carlo.caini@unibo.it
 **
 **
 **  Copyright (c) 2017, Alma Mater Studiorum, University of Bologna
 **  All rights reserved.
 ********************************************************/

#ifndef UNIBO_DTKA_TYPES_H_
#define UNIBO_DTKA_TYPES_H_

#include "unibo_dtka_includes.h"

#define PARAMETER_MAX_SIZE 22
#define DTN_TIME_SHIFT 946684760;
#define CLIENT_MODE 0
#define AUTHORITY_MODE 1
#define UNIBO_DTKA_EXIT_STATUS_OK 0
#define UNIBO_DTKA_EXIT_STATUS_CONFIG_FILE_NOT_EXISTS 1
#define UNIBO_DTKA_EXIT_STATUS_READ_ERROR_CONFIG_FILE 2
#define UNIBO_DTKA_EXIT_STATUS_SYNTAX_ERROR 3
#define UNIBO_DTKA_EXIT_STATUS_WRITE_ERROR_CONFIG_FILE 4
#define UNIBO_DTKA_EXIT_STATUS_CRYPTO_LIBRARY_ERROR 5
#define UNIBO_DTKA_EXIT_STATUS_ERASURE_LIBRARY_ERROR 6
#define UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR 7
#define UNIBO_DTKA_EXIT_STATUS_KEY_ALGORITHM_ERROR 8
#define UNIBO_DTKA_EXIT_STATUS_NO_DAEMON_RUNNING 9
#define UNIBO_DTKA_EXIT_STATUS_OPENING_HANDLE_ERROR 10
#define UNIBO_DTKA_EXIT_STATUS_KEY_FILE_NOT_FOUND 11
#define UNIBO_DTKA_EXIT_STATUS_WRITE_ERROR_KEY_FILE 12
#define UNIBO_DTKA_EXIT_STATUS_READ_ERROR_KEY_FILE 13
#define UNIBO_DTKA_EXIT_STATUS_VERIFY_ERROR 14
#define UNIBO_DTKA_EXIT_STATUS_KEY_GENERATION_ERROR 15
#define UNIBO_DTKA_EXIT_STATUS_CONNECTION_ERROR 16
#define UNIBO_DTKA_EXIT_STATUS_PTHREAD_ERROR 17


struct dtka_parameters{
    int information_block_number;
    int number_of_authorities;
    int total_block_number;
    int key_length;
    char *hash_algorithm;
    char *key_algorithm;
    int padding;
    char *padding_type;
    int rsa_exp;
    int rand_length;
    int sign;
    char *public_key_file;
    char *private_key_file;
    char *new_public_key_file;
    char *new_private_key_file;
    char *key_format;
    int expiration_time;
    int number_of_clients;
    int receive_time;
    int bulletin_time;
    int grace_time;
    char *bundle_priority;
    int block_per_authority;
    char **authority_eid;
    char **authority_key_file;
    int *authority_status;
    char **clients_eid;
    char **clients_key_file;
    char *bundle_sign;
    char *bulletin_file;
    char *dtka_output;
    char *log_file;
    int key_publish_interval;
    FILE *fp_log;
    FILE *fp_bulletin;
};

typedef struct dtka_parameters dtka_parameters;

struct dtka_record{
	char *EID;
	unsigned int effective_time;
	char *acknowledged;
	unsigned int assertion_time;
	unsigned int data_length;
	unsigned char *data_value;
};

typedef struct dtka_record dtka_record;

struct record_list{
	dtka_record *record;
	int records;
	struct record_list *next;
};

typedef struct record_list record_list;

struct block_list{
	int index_block;
	unsigned char *block_data;
	int block_length;
    struct block_list *next;
};

typedef struct block_list block_list;

#endif
