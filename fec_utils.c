/********************************************************
 **  Authors: Alessandro Di Stanislao, alessand.distanislao@studio.unibo.it
 **           Carlo Caini (project supervisor), carlo.caini@unibo.it
 **
 **
 **  Copyright (c) 2017, Alma Mater Studiorum, University of Bologna
 **  All rights reserved.
 ********************************************************/

#include "fec_utils.h"

fec_encoded_data* encode_blocks(int K,int N, const unsigned char *message,int message_length){
	
    int i,block_size;
    unsigned char **primary_blocks;
    unsigned char **secondary_blocks;
    unsigned int *secondary_blocks_numbers;
    fec_encoded_data *result = NULL;
    fec_t *fec_parameters;

#ifdef DEBUG
    printf("\n\nOriginal message: \n%s",message);
#endif

    block_size = message_length/K;
    if(message_length%K!=0)
       block_size++;

#ifdef DEBUG
    printf("\nAllocating memory for information blocks");
#endif
    primary_blocks = malloc(sizeof(unsigned char*)*K);
    for(i=0; i<K; i++){
       primary_blocks[i] = calloc(block_size,sizeof(unsigned char));
       if(primary_blocks[i]==NULL){
#ifdef DEBUG
          printf("\n\nNot enough memory.\n");
#endif
          return result;
       }
    }

#ifdef DEBUG
    printf("\nAllocating memory for redundancy blocks");
#endif
    secondary_blocks = calloc((N-K),sizeof(unsigned char*));
    if(secondary_blocks == NULL){
#ifdef DEBUG
       printf("\n\nNot enough memory.\n");
#endif
       return result;
    }

    for(i=0;i<(N-K); i++){
       secondary_blocks[i] = calloc(block_size,sizeof(unsigned char));
       if(secondary_blocks[i] == NULL){
#ifdef DEBUG
          printf("\n\nNot enough memory.\n");
#endif
          return result;
       }
    }

    secondary_blocks_numbers = calloc((N-K),sizeof(unsigned int));
    if(secondary_blocks == NULL){
#ifdef DEBUG
       printf("\n\nNot enough memory.\n");
#endif
       return result;
    }

    for(i=0; i<K; i++){	
       memmove(primary_blocks[i],message+i*block_size,block_size);
       if(strlen((char *)primary_blocks[i])>block_size)
          memset(primary_blocks[i]+block_size,0,strlen((char*)primary_blocks[i])-block_size);
    }

#ifdef DEBUG
    printf("\n\nCreating fec decoder with K = %d and N = %d",K,N);
#endif
    fec_parameters = fec_new(K,N);
    if(fec_parameters == NULL){
#ifdef DEBUG
       printf("\n\nNot enough memory.\n");
#endif
       return result;
    }
	
#ifdef DEBUG
    printf("\n\nEncoding message....");
#endif
	
    for(i=0; i<N-K; i++)
       secondary_blocks_numbers[i] = K+i;

#ifdef DEBUG
    printf("\n\nInformation blocks:");
    for(i=0; i<K; i++)
       printf("\n\nInformation block %d\n%s",i,primary_blocks[i]);

#endif

    fec_encode(fec_parameters,primary_blocks,secondary_blocks,secondary_blocks_numbers,(N-K),block_size);

#ifdef DEBUG
    printf("\n\nRedundancy blocks:");
#endif

    for(i=0; i<N-K; i++){
       if(strlen((char*)secondary_blocks[i])>block_size)
          memset(secondary_blocks[i]+block_size,0,strlen((char*)secondary_blocks[i])-block_size);
#ifdef DEBUG
       printf("\n\nRedundancy block %d\n%s",i,secondary_blocks[i]);
#endif
    }
	
    result = calloc(1,sizeof(fec_encoded_data));
    if(result == NULL){
#ifdef DEBUG
       printf("\n\nNot enough memory.\n");
#endif
       exit(7);
    }
	
    result->M = N;
    result->K = K;
    result->primary_blocks = primary_blocks;
    result->secondary_blocks = secondary_blocks;
    result->secondary_blocks_numbers = secondary_blocks_numbers;
    result->block_size = block_size;
    	
    return result;
}   

int decode_blocks(fec_received_data *data,unsigned char *message){
	
    int i;
    int j;
    fec_t *fec_parameters;

#ifdef DEBUG
    printf("\n\nRecontructing original blocks...");
    for(i=0; i<data->K; i++)
       if(data->index_blocks[i] >= data->K )
          printf("\n\nInput block: %d Redundancy Block\n%s",i,data->input_blocks[i]);
       else
          printf("\n\nInput block: %d Information Block\n%s",i,data->input_blocks[i]);
#endif

    data->output_blocks = calloc(data->K,sizeof(unsigned char*));
    if(data->output_blocks == NULL){
#ifdef DEBUG
       printf("\n\nNot enough memory.\n");
#endif
       return -1;
    }

    for(i=0; i<data->K; i++){
       data->output_blocks[i] = malloc(sizeof(unsigned char)*data->block_size);
       if(data->output_blocks[i] == NULL){
#ifdef DEBUG
          printf("\n\nNot enough memory.\n");
#endif
          return -1;
       }
       memset(data->output_blocks[i],0,data->block_size);
    }
	
    fec_parameters = fec_new(data->K,data->M);

    fec_decode(fec_parameters,data->input_blocks,data->output_blocks,data->index_blocks,data->block_size);
	
    for(i=0; i<data->K; i++)
       if(strlen((char*)data->output_blocks[i])>data->block_size)
          memset(data->output_blocks[i]+data->block_size,0,strlen((char*)data->output_blocks[i])-data->block_size);	
	  
    for(i=0,j=0; i<data->K; i++)
       if(data->index_blocks[i] == data->K)
          memcpy(message+i*data->block_size,data->output_blocks[j++],data->block_size);
       else
          memcpy(message+i*data->block_size,data->input_blocks[i],data->block_size);

#ifdef DEBUG
    printf("\n\nReconstructed message: \n%s",message);
#endif
	
    return 0;
		
}
