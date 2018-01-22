/********************************************************
 **  Authors: Alessandro Di Stanislao, alessand.distanislao@studio.unibo.it
 **           Carlo Caini (project supervisor), carlo.caini@unibo.it
 **
 **
 **  Copyright (c) 2017, Alma Mater Studiorum, University of Bologna
 **  All rights reserved.
 ********************************************************/

#ifndef UNIBO_DTKA_FUNCTION_H_
#define UNIBO_DTKA_FUNCTION_H_

#include "unibo_dtka_includes.h"
#include "unibo_dtka_types.h"
#include "connection_wrapper.h"
#include "crypto_utils.h"
#include "fec_utils.h"

/* Detects which type of OS is running. */
/* Returns: 1 for Windows based OS, 0 for Unix based OS.
 */

int detect_windows_OS();

int configure_defaults();
void *sending_key_thread_client();
void *update_keys();
int configure_application(const char *filename);
int do_connection_test();
int generate_key_pairs(const char *filename);
int prepare_key_message();
void *receive_bulletin();
void reconstruct_bulletin();
int serialize_record(unsigned char *serialized_records);
int find_my_index(connection_wrapper_t *connection,int mode,char *ep_service);
int create_bulletin(unsigned char *bulletin);
int write_config_to_file(const dtka_parameters *parameters,const char *filename);
/* Clears the stdin buffer.
 */

void clear_stdin();

/* Reads parameters from a text file.
 * All parameters are stored in a dtka_parameters struct.
 */

void read_parameters_from_file(const char *filename,dtka_parameters *parameters);

/* Performs a test on the cryptographic libraries.
 * Return 1 if all tests is passed.
 */

int do_cryptographic_tests();

/* Performs a test on the erasure libraries.
 * Return 1 if all tests is passed.
 */

int do_erasure_test();

/* Initializes the application and starts client or authority threads.
 */

void init_application(dtka_parameters *parameters,const char* filename,int mode);

/* Returns the index of the next block.
 */

int get_next_block_index(int current,int max);

/* Serializes the message for the sending thread.
 * Returns 1 if all is ok, -1 otherwise.
 */

int serialize_message(unsigned char *serialized_message,unsigned short EID_length,unsigned char *EID,unsigned int effective_time,unsigned int assertion_time,unsigned int data_length,unsigned char*data);

/* Deserializes the message for the receiving thread.
 * Return 1 if all is ok, -1 otherwise.
 */
int deserialize_message(unsigned char *serialized_message,unsigned short *EID_length,unsigned char *EID,unsigned int *effective_time,unsigned int *assertion_time,unsigned int *data_length,unsigned char *data);
void unibo_dtka_error_handler(int exit_status);

#endif
