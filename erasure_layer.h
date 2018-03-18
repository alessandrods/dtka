/********************************************************
 **  Authors: Alessandro Di Stanislao, alessand.distanislao@studio.unibo.it
 **           Carlo Caini (project supervisor), carlo.caini@unibo.it
 **
 **
 **  Copyright (c) 2018, Alma Mater Studiorum, University of Bologna
 **  All rights reserved.
 ********************************************************/

#ifndef ERASURE_LAYER_H_
#define ERASURE_LAYER_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "zfec/fec.h"

struct fec_encoded_data{
    int M;
    int K;
    int block_size;
    unsigned char **primary_blocks;
    unsigned char **secondary_blocks;
    unsigned int *secondary_blocks_numbers;
};

typedef struct fec_encoded_data fec_encoded_data;

struct fec_received_data{
    int M;
    int K;
    int block_size;
    unsigned char **input_blocks;
    unsigned char **output_blocks;
    unsigned int *index_blocks;

};

typedef struct fec_received_data fec_received_data;

/* This functions creates N blocks of a message data: K information blocks i.e. primary blocks.
                                                      M redundancy blocks i.e. secondary blocks.
                                                      N is the total number of blocks.
   K blocks are needed for reconstruct the message.
   Returns: a fec_encoded_data structure which contains primary and secondary blocks. */

fec_encoded_data* el_encode_blocks(int K,int N, const unsigned char *message,int message_length);

/* This functions recreates a complete message from K blocks of data
 * Parameters: a fec_received_data that contains information and redundancy blocks.
 *             each information blocks must be stored in its index position.
 *             redundancy blocks can be placed everywhere.
 * Returns: a char pointer with the decoded message. */

int el_decode_blocks(fec_received_data *data,unsigned char* message);

#endif
