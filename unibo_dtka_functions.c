/********************************************************
 **  Authors: Alessandro Di Stanislao, alessand.distanislao@studio.unibo.it
 **           Carlo Caini (project supervisor), carlo.caini@unibo.it
 **
 **
 **  Copyright (c) 2017, Alma Mater Studiorum, University of Bologna
 **  All rights reserved.
 ********************************************************/

#include "unibo_dtka_includes.h"
#include "connection_wrapper.h"
#include "crypto_utils.h"
#include "fec_utils.h"
#include "unibo_dtka_types.h"
#include "unibo_dtka_client.h"
#include "unibo_dtka_authority.h"
#include "unibo_dtka_functions.h"

extern struct dtka_parameters parameters;
extern struct record_list rec_list;
extern connection_wrapper_t sending_key_connection;
extern connection_wrapper_t receive_bulletin_connection;
extern unsigned char* _bulletin;
extern int _length;
int transmitted = 0;
int ok = 0;

int detect_windows_OS(){

    #if defined _WIN32 || defined _WIN64
    return 1;
    #endif

    #if defined __unix__
    return 0;
    #endif

    return -1;
}

void *sending_key_thread_client(){

	dtka_parameters *p;
	p = &parameters;

	connection_wrapper_t *connection;

	unsigned char *key;
	unsigned char *buffer;
	int buffer_length;
	int key_length;
    unsigned short eid_length;
	unsigned int data_length;
    char *temp;

	struct timeval now;
    int i;

    connection = &sending_key_connection;

	for(;;){

       key_length = prepare_key_message(NULL);
	   key = calloc(key_length+1,sizeof(char));
	   if(key == NULL)
		  unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);
	   key_length = prepare_key_message(key);

       data_length = (unsigned int)key_length;
       eid_length = (unsigned short)strlen(connection->local_eid.uri);

       gettimeofday(&now,NULL);

       buffer_length = serialize_message(NULL,eid_length,(unsigned char*)connection->local_eid.uri,now.tv_sec,(unsigned int)p->expiration_time,data_length,key);
       buffer = calloc(buffer_length,sizeof(char));
   	   if(buffer == NULL)
   	      unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

       buffer_length = serialize_message(buffer,eid_length,(unsigned char*)connection->local_eid.uri,now.tv_sec,(unsigned int)p->expiration_time+now.tv_sec,data_length,key);
       if(buffer_length < 0)
    	  continue;

       for(i=0;i<p->number_of_authorities; i++){

    	  temp = calloc(127,sizeof(char));
    	  temp = strcat(temp,p->authority_eid[i]);
    	  temp = strcat(temp,"/dtka");
          wrapper_send(connection,buffer,buffer_length,temp);
          fprintf(p->fp_log,"\nUnibo-DTKA Client: Public key sent to %s",p->authority_eid[i]);
          fflush(p->fp_log);
          free(temp);

       }

       free(key);
   	   free(buffer);

       sleep(p->key_publish_interval);

	}

	return (void*)0;
}

void clear_stdin(){

    char c;

    for(;;){     // Clear the stdin buffer consuming all of the input characters.
       c = getchar();
       if(c == '\n' || c == EOF)
          break;
    }    
    
}

int generate_key_pairs(const char *filename){

	dtka_parameters *p;
	int result;

	p = malloc(sizeof(dtka_parameters));
	read_parameters_from_file(filename,p);


	result = -1;

	if(strcmp(p->key_algorithm,"DSA")==0 && strcmp(p->key_format,"PEM")==0)
	   result = generate_DSA_key_pair_files(p->key_length,p->rand_length,p->private_key_file,p->public_key_file,PEM_FORMAT);

	if(strcmp(p->key_algorithm,"DSA")==0 && strcmp(p->key_format,"DER")==0)
	   result = generate_DSA_key_pair_files(p->key_length,p->rand_length,p->private_key_file,p->public_key_file,DER_FORMAT);

	if(strcmp(p->key_algorithm,"RSA")==0 && strcmp(p->key_format,"PEM")==0)
       result = generate_RSA_key_pair_files(p->key_length,p->rsa_exp,p->private_key_file,p->public_key_file,PEM_FORMAT);

	if(strcmp(p->key_algorithm,"RSA")==0 && strcmp(p->key_format,"DER")==0)
       result = generate_RSA_key_pair_files(p->key_length,p->rsa_exp,p->private_key_file,p->public_key_file,DER_FORMAT);

	return result;
}

int configure_application(const char *filename){

	dtka_parameters *p;
    int result;
    int i;
    FILE *fp;
    char response;

    p = &parameters;

    p->dtka_output = malloc(sizeof(char)*6);
    if(p->dtka_output == NULL)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

    p->log_file = malloc(sizeof(char)*255);
    if(p->log_file == NULL)
    	unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

    p->hash_algorithm = malloc(sizeof(char)*9);
    if(p->hash_algorithm == NULL)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

    p->key_algorithm = malloc(sizeof(char)*3);
    if(p->key_algorithm == NULL)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

    p->padding_type = malloc(sizeof(char)*22);
    if(p->padding_type == NULL)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

    p->public_key_file = malloc(sizeof(char)*255);
    if(p->public_key_file == NULL)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

    p->private_key_file = malloc(sizeof(char)*255);
    if(p->private_key_file == NULL)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

    p->new_public_key_file = malloc(sizeof(char)*255);
    if(p->new_public_key_file == NULL)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

    p->new_private_key_file = malloc(sizeof(char)*255);
    if(p->new_private_key_file == NULL)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

    p->key_format = malloc(sizeof(char)*3);
    if(p->key_format == NULL)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

    p->bundle_priority = malloc(sizeof(char)*9);
    if(p->bundle_priority == NULL)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

    p->bundle_sign = malloc(sizeof(char)*4);
    if(p->bundle_sign == NULL)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

	printf("\nUnibo-DTKA: Configuration Settings...");
    fflush(stdout);

    fp = fopen(filename,"r");

    if(fp != NULL)
    	for(;;){
    	   printf("\nThe file %s already exists. Overwrite? (Y/N): ",filename);
    	   printf("\n-> ");
    	   result = scanf("%c",&response);
    	   fflush(stdout);
    	   clear_stdin();
    	   if(result > 0 && response == 'N'){
    		  fclose(fp);
    		  exit(UNIBO_DTKA_EXIT_STATUS_OK);
    	   }
    	   if(result >0 && response == 'Y'){
    		  fclose(fp);
    		  break;
    	   }
    	}

    for(;;){
       printf("\nDo you want the output redirected to a log file? (Y/N): ");
       printf("\n-> ");
       fflush(stdout);
       result = scanf("%c",&response);
       clear_stdin();
       if(result > 0 && response == 'N'){
    	   strcpy(p->dtka_output,"STDOUT");
    	   strcpy(p->log_file,"NONE");
    	   break;
       }
       if(result > 0 && response == 'Y'){
    	   strcpy(p->dtka_output,"FILE");
    	   for(;;){
    		   printf("\nPlease enter the log filename: ");
    		   printf("\n-> ");
    		   fflush(stdout);
    		   result = scanf("%s",p->log_file);
    		   clear_stdin();
    		   if(result > 0)
    			   break;
    	   }
    	   break;
       }
    }

	for(;;){
	   printf("\nPlease enter the number of total blocks of bulletin [Secondary blocks]: ");
	   printf("\n-> ");
	   fflush(stdout);
	   result = scanf("%d",&p->total_block_number);
	   clear_stdin();
       if(result > 0 && p->total_block_number > 0)
    	  break;
       else
    	  printf("\nThe number of the blocks must be positive.");
	}

	for(;;){
	   printf("\nPlease enter the number of the information blocks of bulletin [Primary blocks]: ");
	   printf("\n-> ");
	   fflush(stdout);
	   result = scanf("%d",&p->information_block_number);
	   clear_stdin();
       if(result > 0 && p->information_block_number > 0)
    	  break;
       else
    	  printf("\nThe number of the blocks must be positive.");
	}

	for(;;){
	   printf("\nPlease enter the number of blocks transmitted by an authority: ");
	   printf("\n-> ");
	   fflush(stdout);
	   result = scanf("%d",&p->block_per_authority);
	   clear_stdin();
	   if(result > 0 && p->block_per_authority > 0)
  	      break;
	   else
		  printf("\nThe number of the blocks transmitted must be positive.");
	}

	for(;;){
	   printf("\nPlease enter the name of the hash algorithm for bulletin (MD4, MD5, RIPEMD160, SHA224, SHA256, SHA384, SHA512): ");
	   printf("\n-> ");
	   fflush(stdout);
	   result = scanf("%s",p->hash_algorithm);
	   clear_stdin();
	   if(result > 0 ){
		  if(strcmp(p->hash_algorithm,"MD4")==0 || strcmp(p->hash_algorithm,"MD5")==0 || strcmp(p->hash_algorithm,"RIPEMD160")==0 || strcmp(p->hash_algorithm,"SHA224")==0 || strcmp(p->hash_algorithm,"SHA256")==0 || strcmp(p->hash_algorithm,"SHA384")==0 || strcmp(p->hash_algorithm,"SHA512")==0)
			 break;
		  else
			 printf("\nUnknown algorithm.");
	   }
	}

	for(;;){
	   printf("\nPlease enter the public key algorithm used for sign bundles (DSA, RSA): ");
	   printf("\n-> ");
	   fflush(stdout);
	   result = scanf("%s",p->key_algorithm);
	   clear_stdin();
	   if(result > 0){
		   if(strcmp(p->key_algorithm,"DSA")==0 || strcmp(p->key_algorithm,"RSA")==0)
			  break;
		   else
			  printf("\nUnknown algorithm.");
	   }
	}

	for(;;){
	   printf("\nPlease enter the public key length: ");
	   printf("\n-> ");
	   fflush(stdout);
	   result = scanf("%d",&p->key_length);
       clear_stdin();
       if(result > 0 && p->key_length > 0)
    	  break;
       else
    	  printf("\nThe key length must be positive.");
	}

	for(;;){
	   printf("\nPlease enter the padding type for RSA algorithm (RSA_PKCS1_PADDING, RSA_PKSC1_OAEP_PADDING, RSA_SSLV23_PADDING, RSA_SSLV23_PADDING, RSA_NO_PADDING): ");
	   printf("\n-> ");
	   fflush(stdout);
	   result = scanf("%s",p->padding_type);
       clear_stdin();
       if(result > 0){
    	   if(strcmp(p->padding_type,"RSA_PKCS1_PADDING")==0 || strcmp(p->padding_type,"RSA_PKSC1_OAEP_PADDING")==0 || strcmp(p->padding_type,"RSA_SSLV23_PADDING")==0 || strcmp(p->padding_type,"RSA_NO_PADDING")==0)
              break;
    	   else
    		  printf("\nUnknown padding type.");
       }
	}

	for(;;){
	   printf("\nPlease enter the RSA exponent for the key generator: ");
	   printf("\n-> ");
	   fflush(stdout);
	   result = scanf("%d",&p->rsa_exp);
	   clear_stdin();
	   if(result > 0 && p->rsa_exp > 0)
		  break;
	   else
		  printf("\nThe RSA exponent must be positive.");
	}

	for(;;){
	   printf("\nPlease enter the length of the random bytes needed for DSA key generator: ");
	   printf("\n-> ");
	   fflush(stdout);
	   result = scanf("%d",&p->padding);
       clear_stdin();
	   if(result > 0 && p->padding > 0)
		  break;
	   else
		  printf("\nThe DSA padding length must be positive.");
	}

	for(;;){
	   printf("\nPlease enter the format of the public and private keys (PEM, DER): ");
	   printf("\n-> ");
	   fflush(stdout);
	   result = scanf("%s",p->key_format);
	   clear_stdin();
	   if(result > 0){
		  if(strcmp(p->key_format,"PEM")==0 || strcmp(p->key_format,"DER")==0)
			 break;
		  else
			 printf("\nUnknown format.");
	   }
	}

	for(;;){
	   printf("\nPlease enter the own public key file: ");
	   printf("\n-> ");
	   fflush(stdout);
	   result = scanf("%s",p->public_key_file);
	   clear_stdin();
	   if(result > 0)
         break;
	}

	for(;;){
	   printf("\nPlease enter the own private key file: ");
	   printf("\n-> ");
	   fflush(stdout);
	   result = scanf("%s",p->private_key_file);
       clear_stdin();
       if(result > 0)
    	 break;
	}

	for(;;){
	   printf("\nPlease enter the time of the key expiration: ");
	   printf("\n-> ");
	   fflush(stdout);
	   result = scanf("%d",&p->expiration_time);
       clear_stdin();
       if(result > 0 && p->expiration_time > 0)
    	  break;
       else
    	  printf("\nThe expiration time must be positive.");
	}

	for(;;){
	   printf("\nPlease enter the time for publish bulletin: ");
	   printf("\n-> ");
	   fflush(stdout);
	   result = scanf("%d",&p->bulletin_time);
       clear_stdin();
	   if(result > 0 && p->bulletin_time > 0)
		  break;
	   else
		  printf("\nThe publish time must be positive:");
	}

	for(;;){
	   printf("\nPlease enter the time for the grace time: ");
	   printf("\n-> ");
	   fflush(stdout);
	   result = scanf("%d",&p->grace_time);
       clear_stdin();
	   if(result > 0 && p->grace_time > 0)
		  break;
	   else
		  printf("\nThe publish time must be positive:");
	}

	for(;;){
	   printf("\nPlease enter the time for the key publish interval: ");
	   printf("\n-> ");
	   fflush(stdout);
	   result = scanf("%d",&p->key_publish_interval);
       clear_stdin();
	   if(result > 0 && p->key_publish_interval > 0)
		  break;
	   else
		  printf("\nThe publish time must be positive:");
	}

	for(;;){
	   printf("\nPlease enter the bundle receiving timeout (-1 for no timeout) ");
	   printf("\n-> ");
	   fflush(stdout);
	   result = scanf("%d",&p->receive_time);
       clear_stdin();
       if(result > 0 && p->receive_time > -2)
    	  break;
       else
    	  printf("\nThe receiving timeout must be higher than -2.");
	}

	for(;;){
	   printf("\nPlease enter the bundle priority (BULK, NORMAL, EXPEDITED): ");
	   printf("\n-> ");
	   fflush(stdout);
	   result = scanf("%s",p->bundle_priority);
       clear_stdin();
       if(result > 0){
    	  if(strcmp(p->bundle_priority,"BULK")==0 || strcmp(p->bundle_priority,"NORMAL")==0 || strcmp(p->bundle_priority,"EXPEDITED")==0)
             break;
    	  else
    		 printf("\nUnknown priority type.");
       }
	}

	for(;;){
	   printf("\nDo you want to sign bundle? (YES, NO): ");
	   printf("\n-> ");
	   fflush(stdout);
	   result = scanf("%s",p->bundle_sign);
	   clear_stdin();
	   if(result > 0){
		  if(strcmp(p->bundle_sign,"YES")==0 || strcmp(p->bundle_sign,"NO")==0)
			 break;
		  else
			 printf("\nUnknown response.");
	   }
	}

	for(;;){
	   printf("\nPlease enter the file to save bulletins: ");
	   printf("\n-> ");
	   fflush(stdout);
	   result = scanf("%s",p->bulletin_file);
	   clear_stdin();
	   if(result > 0)
		  break;
	   else
			 printf("\nUnknown response.");
	}

	for(;;){
	   printf("\nPlease enter the number of the authorities: ");
	   printf("\n-> ");
	   fflush(stdout);
	   result = scanf("%d",&p->number_of_authorities);
       clear_stdin();
	   if(result > 0 && p->number_of_authorities > 0)
		  break;
	   else
		  printf("\nThe number of authorities must be positive.");
	}

	p->authority_eid = malloc(sizeof(char*)*p->number_of_authorities);
	if(p->authority_eid == NULL)
	   unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

	p->authority_key_file = malloc(sizeof(char*)*p->number_of_authorities);
    if(p->authority_key_file == NULL)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

	for(i=0; i<p->number_of_authorities; i++){
		p->authority_eid[i] = malloc(sizeof(char)*127);
		if(p->authority_eid[i] == NULL)
		   unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

	    p->authority_key_file[i] = malloc(sizeof(char)*255);
	    if(p->authority_key_file[i] == NULL)
	       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);
	}

	for(i=0; i<p->number_of_authorities; i++)
	   for(;;){
	     printf("\nPlease enter the authority EID%d: ",i);
	     printf("\n-> ");
	     fflush(stdout);
	     result = scanf("%s",p->authority_eid[i]);
	     clear_stdin();
	     if(result > 0)
	    	break;
	   }


	for(i=0; i<p->number_of_authorities; i++)
 	   for(;;){
 		 printf("\nPlease enter %s public key file: ",p->authority_eid[i]);
 		 printf("\n-> ");
 		 fflush(stdout);
         result = scanf("%s",p->authority_key_file[i]);
         clear_stdin();
         if(result > 0)
    	    break;
 	   }

	for(;;){
	   printf("\nPlease enter the number of clients: ");
	   printf("\n-> ");
	   fflush(stdout);
	   result = scanf("%d",&p->number_of_clients);
	   clear_stdin();
	   if(result > 0 && p->number_of_clients > 0)
		  break;
	   else
		  printf("\nThe number of nodes must be positive.");
	}

	p->clients_eid = malloc(sizeof(char*)*p->number_of_clients);
	if(p->clients_eid == NULL)
	   unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

	p->clients_key_file = malloc(sizeof(char*)*p->number_of_clients);
	if(p->clients_key_file == NULL)
	   unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

	for(i=0; i<p->number_of_clients; i++){
		p->clients_eid[i] = malloc(sizeof(char)*127);
		if(p->clients_eid[i] == NULL)
		   unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);
	    p->clients_key_file[i] = malloc(sizeof(char)*255);
	    if(p->clients_key_file[i] == NULL)
	       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);
	}

	for(i=0; i<p->number_of_clients; i++)
	  for(;;){
	     printf("\nPlease enter the node EID%d: ",i);
	     printf("\n-> ");
	     fflush(stdout);
	     result = scanf("%s",p->clients_eid[i]);
	     clear_stdin();
	     if(result > 0)
	    	break;
	  }


	for(i=0; i<p->number_of_clients; i++)
      for(;;){
	    printf("\nPlease enter %s public key file: ",p->clients_eid[i]);
	    printf("\n-> ");
	    fflush(stdout);
        result = scanf("%s",p->clients_key_file[i]);
        clear_stdin();
        if(result > 0)
           break;
	}

    result = write_config_to_file(p,filename);

    return result;

}

int configure_defaults(){
	return configure_application("defaults.conf");
}

int write_config_to_file(const dtka_parameters *parameters,const char *filename){

    FILE *fp;
    int result;
    int i;

    fp = fopen(filename,"w");
    if(fp == NULL)
       return -1;

    result = fprintf(fp,"#DTKA DEFAULT CONFIGURATION FILE\n"
                        "#DTKA OUTPUT: FILE,STDOUT\n"
                        "DTKA_OUTPUT %s\n"
                        "#LOG FILE\n"
                        "LOG_FILE %s\n"
    		            "#NUMBER OF NEEDED BLOCKS\n"
    		            "FEC_INFO_BLOCKS %d\n"
                        "#NUMBER OF TOTAL BLOCKS\n"
                        "FEC_BLOCK_NUMBER %d\n"
                        "#NUMBER OF BLOCKS TRANSMITTED BY AN AUTHORITY\n"
                        "BLOCK_PER_AUTHORITY %d\n"
                        "#HASH ALGORITHM: MD4 , MD5, RIPEMD160, SHA224, SHA256, SHA384, SHA512\n"
                        "HASH_ALGORITHM %s\n"
                        "#PUBLIC KEY ALGORITHM: RSA, DSA\n"
                        "PUBLIC_KEY_ALGORITHM %s\n"
                        "#KEY LENGTH\n"
                        "KEY_LENGTH %d\n"
                        "#RSA_PADDING: RSA_PKCS1_PADDING, RSA_PKCS1_OAEP_PADDING, RSA_SSLV23_PADDING, RSA_NO_PADDING\n"
                        "RSA_PADDING %s\n"
                        "#NUMBER FOR THE RSA KEY GENERATION: 3, 17, 65537\n"
                        "RSA_EXP %d\n"
                        "#LENGTH OF THE RANDOM BYTES ARRAY FOR THE DSA KEY GENERATION\n"
                        "DSA_RAND_LEN %d\n"
                        "#FORMAT OF PUBLIC AND PRIVATE KEY: PEM, DER\n"
                        "KEY_FORMAT %s\n"
                        "#OWN PUBLIC KEY FILE \n"
                        "PUBLIC_KEY_FILE %s\n"
                        "#OWN PRIVATE KEY FILE \n"
                        "PRIVATE_KEY_FILE %s\n"
                        "#OWN NEW PUBLIC KEY FILE\n"
                        "NEW_PUBLIC_KEY_FILE %s\n"
                        "#OWN NEW PRIVATE KEY FILE\n"
                        "NEW_PRIVATE_KEY_FILE %s\n"
                        "#TIME IN SECS OF THE KEY EXPIRATION\n"
                        "EXPIRATION_TIME %d\n"
                        "#TIME IN SECS FOR PUBLISHING BULLETIN\n"
    		            "BULLETIN_TIME %d\n"
    		            "#TIME IN SECS FOR PUBLISHING PUBLIC KEY\n"
    		            "KEY_TIME %d\n"
    		            "#GRACE PERIOD BEFORE PUBLISHING BULLETIN"
    		            "GRACE_TIME %d\n"
    		            "#RECEIVING TIMEOUT (-1 = BLOCKING RECEIVE)\n"
    		            "RECEIVING_TIME %d\n"
    		            "#BUNDLE_PRIORITY: BULK, NORMAL, EXPEDITED\n"
    		            "BUNDLE_PRIORITY %s\n"
    		            "#BUNDLE SIGN: YES, NO\n"
    		            "BUNDLE_SIGN %s\n"
    		            "#BULLETIN SAVE FILE\n"
    		            "BULLETIN_SAVE_FILE %s\n",
    		            parameters->dtka_output,
                        parameters->log_file,
    		            parameters->information_block_number,
    		            (parameters->total_block_number+parameters->information_block_number),
    		            parameters->block_per_authority,
    		            parameters->hash_algorithm,
    		            parameters->key_algorithm,
    		            parameters->key_length,
    		            parameters->padding_type,
    		            parameters->rsa_exp,
    		            parameters->rand_length,
    		            parameters->key_format,
    		            parameters->public_key_file,
    		            parameters->private_key_file,
    		            parameters->new_public_key_file,
    		            parameters->new_private_key_file,
    		            parameters->expiration_time,
    		            parameters->bulletin_time,
    		            parameters->grace_time,
    		            parameters->key_publish_interval,
    		            parameters->receive_time,
    		            parameters->bundle_priority,
    		            parameters->bundle_sign,
    		            parameters->bulletin_file);

    if(result < 0){
       fclose(fp);
       return -1;
    }

    result = fprintf(fp,"#NUMBER OF AUTHORITIES\n"
    		            "NUMBER_OF_AUTHORITIES %d\n",parameters->number_of_authorities);
    if(result < 0){
       fclose(fp);
       return -1;
    }

    for(i=0; i<parameters->number_of_authorities; i++){
    	result = fprintf(fp,"AUTH_EID %s\n"
    			            "AUTH_KEY_FILE %s\n",parameters->authority_eid[i],parameters->authority_key_file[i]);
    	if(result < 0){
    	   fclose(fp);
    	   return -1;
    	}
    }

    result = fprintf(fp,"#NUMBER OF CLIENTS\n"
    		            "NUMBER_OF_CLIENTS %d\n",parameters->number_of_clients);
    if(result < 0){
       fclose(fp);
       return -1;
    }

    for(i=0; i<parameters->number_of_clients; i++){
    	result = fprintf(fp,"CLIENTS_EID %s\n"
    			            "CLIENTS_KEY_FILE %s\n",parameters->clients_eid[i],parameters->clients_key_file[i]);
    	if(result < 0){
    	   fclose(fp);
    	   return -1;
    	}
    }

    fclose(fp);
    return 1;
}

int write_config_to_default_file(const dtka_parameters *parameters){

    return write_config_to_file(parameters,"defaults.conf");
}

void read_parameters_from_file(const char *filename,dtka_parameters *parameters){
	  
    int i;
    int c;
	  
    FILE *defaults;
	
    char parameter_string[PARAMETER_MAX_SIZE];
	char *temp;

    memset(parameters,0,sizeof(dtka_parameters));

    parameters->dtka_output = malloc(sizeof(char)*6+1);
    if(parameters->dtka_output == NULL)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

    parameters->log_file = malloc(sizeof(char)*255);
    if(parameters->log_file == NULL)
    	unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

    parameters->hash_algorithm = malloc(sizeof(char)*9);
    if(parameters->hash_algorithm == NULL)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

    parameters->key_algorithm = malloc(sizeof(char)*3+1);
    if(parameters->key_algorithm == NULL)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

    parameters->padding_type = malloc(sizeof(char)*22);
    if(parameters->padding_type == NULL)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

    parameters->public_key_file = malloc(sizeof(char)*255);
    if(parameters->public_key_file == NULL)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

    parameters->private_key_file = malloc(sizeof(char)*255);
    if(parameters->private_key_file == NULL)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

    parameters->new_public_key_file = malloc(sizeof(char)*255);
    if(parameters->new_public_key_file == NULL)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

    parameters->new_private_key_file = malloc(sizeof(char)*255);
    if(parameters->new_private_key_file == NULL)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

    parameters->key_format = malloc(sizeof(char)*3+1);
    if(parameters->key_format == NULL)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

    parameters->bundle_priority = malloc(sizeof(char)*9);
    if(parameters->bundle_priority == NULL)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

    parameters->bundle_sign = malloc(sizeof(char)*4);
    if(parameters->bundle_sign == NULL)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

    parameters->bulletin_file = malloc(sizeof(char)*255);
    if(parameters->bulletin_file == NULL)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

	temp = calloc(255,sizeof(char));
	if(temp == NULL)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

    defaults = fopen(filename,"r");
	  
    if(defaults == NULL)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_CONFIG_FILE_NOT_EXISTS);
	  
    memset(parameter_string,0,PARAMETER_MAX_SIZE);
	  
    i = 0;
	   
    parameters->information_block_number = 0;
    parameters->total_block_number = 0;
    parameters->number_of_authorities = 0;
	
    // Parsing parameters.
	
    for(;;){
       c = fgetc(defaults);

       if(c == '#')
          while(c != '\n')
             c = fgetc(defaults);

       parameter_string[i++] = c;
       
       if(strcmp(parameter_string,"DTKA_OUTPUT")==0){
    	  memset(parameter_string,0,PARAMETER_MAX_SIZE);
    	  fscanf(defaults,"%s",parameters->dtka_output);
    	  i=0;
    	  if(strcmp(parameters->dtka_output,"STDOUT")==0)
    		 parameters->fp_log = stdout;
    	  if(strcmp(parameters->dtka_output,"FILE") !=0 && strcmp(parameters->dtka_output,"STDOUT") != 0)
    		 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_READ_ERROR_CONFIG_FILE);
       }

       if(strcmp(parameter_string,"LOG_FILE")==0){
     	  memset(parameter_string,0,PARAMETER_MAX_SIZE);
     	  fscanf(defaults,"%s",parameters->log_file);
     	  i=0;
     	  if(strcmp(parameters->log_file,"NONE")!=0){
     	     parameters->fp_log = fopen(parameters->log_file,"a");
     	  }
       }

       if(strcmp(parameter_string,"NUMBER_OF_AUTHORITIES")==0){
          memset(parameter_string,0,PARAMETER_MAX_SIZE);
          fscanf(defaults,"%d",&parameters->number_of_authorities);
          i=0;
          if(parameters->number_of_authorities < 0)
             unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_READ_ERROR_CONFIG_FILE);

          parameters->authority_status = calloc(parameters->number_of_authorities,sizeof(int));
          if(parameters->authority_status == NULL)
        	 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

          parameters->authority_eid = calloc(parameters->number_of_authorities,sizeof(char*));
          if(parameters->authority_eid == NULL)
        	 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

          parameters->authority_key_file = calloc(parameters->number_of_authorities,sizeof(char*));
          if(parameters->authority_key_file == NULL)
        	 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

          c = fgetc(defaults);
          for(i=0; i<parameters->number_of_authorities; i++){
             parameters->authority_eid[i] = calloc(127,sizeof(char));
             if(parameters->authority_eid[i] == NULL)
            	unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

             parameters->authority_key_file[i] = calloc(255,sizeof(char));
             if(parameters->authority_key_file[i] == NULL)
            	unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

             fscanf(defaults,"AUTH_EID %s",parameters->authority_eid[i]);
             c = fgetc(defaults);
             fscanf(defaults,"AUTH_KEY_FILE %s",parameters->authority_key_file[i]);
             c = fgetc(defaults);
             parameters->authority_status[i] = 1;
          }			   
       }

       if(strcmp(parameter_string,"NUMBER_OF_CLIENTS")==0){
          memset(parameter_string,0,PARAMETER_MAX_SIZE);
          fscanf(defaults,"%d",&parameters->number_of_clients);
          i=0;
          if(parameters->number_of_clients < 0)
        	 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_READ_ERROR_CONFIG_FILE);

          parameters->clients_eid = calloc(parameters->number_of_clients,sizeof(char*));
          if(parameters->clients_eid == NULL)
        	 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

          parameters->clients_key_file = calloc(parameters->number_of_clients,sizeof(char*));
          if(parameters->clients_key_file == NULL)
        	 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

          c = fgetc(defaults);
          for(i=0; i<parameters->number_of_clients; i++){
             parameters->clients_eid[i] = calloc(127,sizeof(char));
             if(parameters->clients_eid[i] == NULL)
            	unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

             parameters->clients_key_file[i] = calloc(255,sizeof(char));
             if(parameters->clients_key_file[i] == NULL)
            	unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

             fscanf(defaults,"CLIENT_EID %s",parameters->clients_eid[i]);
             c = fgetc(defaults);
             fscanf(defaults,"CLIENT_KEY_FILE %s",parameters->clients_key_file[i]);
             c = fgetc(defaults);
          }
       }

       if(strcmp(parameter_string,"FEC_INFO_BLOCKS")==0){
          memset(parameter_string,0,PARAMETER_MAX_SIZE);
          fscanf(defaults,"%d",&parameters->information_block_number);
          i=0;
          if(parameters->information_block_number < 0)
        	 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_READ_ERROR_CONFIG_FILE);
       }
		   
       if(strcmp(parameter_string,"FEC_BLOCK_NUMBER")==0){
          memset(parameter_string,0,PARAMETER_MAX_SIZE);
          fscanf(defaults,"%d",&parameters->total_block_number);
          i=0;	
          if(parameters->total_block_number < parameters->information_block_number)
        	 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_READ_ERROR_CONFIG_FILE);
       }
 
       if(strcmp(parameter_string,"HASH_ALGORITHM")==0){
          memset(parameter_string,0,PARAMETER_MAX_SIZE);
          fscanf(defaults,"%s",parameters->hash_algorithm);
          i=0;
          if(strcmp(parameters->hash_algorithm,"MD4")!=0 && strcmp(parameters->hash_algorithm,"MD5")!=0 && strcmp(parameters->hash_algorithm,"RIPMED160")!=0 && strcmp(parameters->hash_algorithm,"SHA224")!=0 && strcmp(parameters->hash_algorithm,"SHA256")!=0 && strcmp(parameters->hash_algorithm,"SHA384")!=0 && strcmp(parameters->hash_algorithm,"SHA512")!=0)
        	 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_READ_ERROR_CONFIG_FILE);
       }

       if(strcmp(parameter_string,"DTKA_OUTPUT")==0){
          memset(parameter_string,0,PARAMETER_MAX_SIZE);
          fscanf(defaults,"%s",parameters->dtka_output);
          i=0;
          if(strcmp(parameters->dtka_output,"STDOUT")!=0 && strcmp(parameters->dtka_output,"FILE")!=0)
        	 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_READ_ERROR_CONFIG_FILE);
       }

       if(strcmp(parameter_string,"PUBLIC_KEY_ALGORITHM")==0){
          memset(parameter_string,0,PARAMETER_MAX_SIZE);
          fscanf(defaults,"%s",parameters->key_algorithm);
          i=0;
          if(strcmp(parameters->key_algorithm,"RSA")!=0 && strcmp(parameters->key_algorithm,"DSA")!=0)
        	 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_READ_ERROR_CONFIG_FILE);
       }

       if(strcmp(parameter_string,"KEY_LENGTH")==0){
          memset(parameter_string,0,PARAMETER_MAX_SIZE);
          fscanf(defaults,"%d",&parameters->key_length);
          i=0;
          if(parameters->key_length < 0)
        	 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_READ_ERROR_CONFIG_FILE);
       }
	   
       if(strcmp(parameter_string,"RSA_PADDING")==0){
          memset(parameter_string,0,PARAMETER_MAX_SIZE);
          fscanf(defaults,"%s",parameters->padding_type);
          parameters->padding = -1;
          if(strcmp(parameters->padding_type,"RSA_PKCS1_PADDING")==0)
             parameters->padding = RSA_PKCS1_PADDING;
          if(strcmp(parameters->padding_type,"RSA_PKCS1_OAEP_PADDING")==0)
             parameters->padding = RSA_PKCS1_OAEP_PADDING;
          if(strcmp(parameters->padding_type,"RSA_SSLV23_PADDING")==0)
             parameters->padding = RSA_SSLV23_PADDING;
          if(strcmp(parameters->padding_type,"RSA_NO_PADDING")==0)
             parameters->padding = RSA_NO_PADDING;
          if(parameters->padding == -1)
        	 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_READ_ERROR_CONFIG_FILE);

	   i=0;

       }	  
	   
       if(strcmp(parameter_string,"RSA_EXP")==0){
          memset(parameter_string,0,PARAMETER_MAX_SIZE);
          fscanf(defaults,"%d",&parameters->rsa_exp);
          i=0;
          if(parameters->rsa_exp < 0)
        	 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_READ_ERROR_CONFIG_FILE);
       }

       if(strcmp(parameter_string,"PUBLIC_KEY_FILE")==0){
         memset(parameter_string,0,PARAMETER_MAX_SIZE);
         fscanf(defaults,"%s",parameters->public_key_file);
         i=0;
         if(strstr(parameters->public_key_file,".pem")==NULL && strstr(parameters->public_key_file,".der")==NULL)
        	unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_READ_ERROR_CONFIG_FILE);
       }	   

       if(strcmp(parameter_string,"PRIVATE_KEY_FILE")==0){
          memset(parameter_string,0,PARAMETER_MAX_SIZE);
          fscanf(defaults,"%s",parameters->private_key_file);
          i=0;
          if(strstr(parameters->private_key_file,".pem")==NULL && strstr(parameters->private_key_file,".der")==NULL)
        	 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_READ_ERROR_CONFIG_FILE);
        }
	   
       if(strcmp(parameter_string,"KEY_FORMAT")==0){
          memset(parameter_string,0,PARAMETER_MAX_SIZE);
          fscanf(defaults,"%s",parameters->key_format);
          i=0;
          if(strcmp(parameters->key_format,"PEM")!=0 && strcmp(parameters->key_format,"DER")!=0)
        	 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_READ_ERROR_CONFIG_FILE);
       }
	   
       if(strcmp(parameter_string,"EXPIRATION_TIME")==0){
          memset(parameter_string,0,PARAMETER_MAX_SIZE);
          fscanf(defaults,"%d",&parameters->expiration_time);
          i=0;
          if(parameters->expiration_time < 0)
        	 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_READ_ERROR_CONFIG_FILE);
       }

       if(strcmp(parameter_string,"BULLETIN_TIME")==0){
          memset(parameter_string,0,PARAMETER_MAX_SIZE);
          fscanf(defaults,"%d",&parameters->bulletin_time);
          i=0;
          if(parameters->bulletin_time < 0)
        	 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_READ_ERROR_CONFIG_FILE);
       }

       if(strcmp(parameter_string,"KEY_TIME")==0){
          memset(parameter_string,0,PARAMETER_MAX_SIZE);
          fscanf(defaults,"%d",&parameters->key_publish_interval);
          i=0;
          if(parameters->key_publish_interval < 0)
        	 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_READ_ERROR_CONFIG_FILE);
       }

       if(strcmp(parameter_string,"GRACE_TIME")==0){
          memset(parameter_string,0,PARAMETER_MAX_SIZE);
          fscanf(defaults,"%d",&parameters->grace_time);
          i=0;
          if(parameters->grace_time < 0)
        	 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_READ_ERROR_CONFIG_FILE);
       }

       if(strcmp(parameter_string,"RECEIVING_TIME")==0){
          memset(parameter_string,0,PARAMETER_MAX_SIZE);
          fscanf(defaults,"%d",&parameters->receive_time);
          i=0;
          if(parameters->receive_time < -1)
        	 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_READ_ERROR_CONFIG_FILE);
       } 

       if(strcmp(parameter_string,"BUNDLE_PRIORITY")==0){
          memset(parameter_string,0,PARAMETER_MAX_SIZE);
          fscanf(defaults,"%s",parameters->bundle_priority);
          i=0;
          if(strcmp(parameters->bundle_priority,"BULK")!=0 && strcmp(parameters->bundle_priority,"NORMAL")!=0 && strcmp(parameters->bundle_priority,"EXPEDITED")!=0 && strcmp(parameters->bundle_priority,"RESERVED")!=0 )
        	 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_READ_ERROR_CONFIG_FILE);
       }

       if(strcmp(parameter_string,"BLOCK_PER_AUTHORITY")==0){
          memset(parameter_string,0,PARAMETER_MAX_SIZE);
          fscanf(defaults,"%d",&parameters->block_per_authority);
          i=0;
          if(parameters->block_per_authority < 1)
        	 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_READ_ERROR_CONFIG_FILE);
       }

       if(strcmp(parameter_string,"BUNDLE_SIGN")==0){
          memset(parameter_string,0,PARAMETER_MAX_SIZE);
          fscanf(defaults,"%s",temp);
          i=0;
          if(strcmp(temp,"NO")==0)
        	 parameters->sign = 0;

          if(strcmp(temp,"YES")==0)
        	 parameters->sign = 1;

          if(strcmp(temp,"YES")!=0 && strcmp(temp,"NO")!=0 )
        	 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_READ_ERROR_CONFIG_FILE);
       }

       if(strcmp(parameter_string,"BULLETIN_SAVE_FILE")==0){
     	  memset(parameter_string,0,PARAMETER_MAX_SIZE);
     	  fscanf(defaults,"%s",parameters->bulletin_file);
     	  i=0;
     	  parameters->fp_bulletin = fopen(parameters->bulletin_file,"a");

       }

       if(strcmp(parameter_string,"DSA_RAND_LEN")==0){
          memset(parameter_string,0,PARAMETER_MAX_SIZE);
          fscanf(defaults,"%d",&parameters->rand_length);
          i=0;
          if(parameters->rand_length < 1)
        	 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_READ_ERROR_CONFIG_FILE);
       }

       if(strcmp(parameter_string,"NEW_PUBLIC_KEY_FILE")==0){
          memset(parameter_string,0,PARAMETER_MAX_SIZE);
          fscanf(defaults,"%s",parameters->new_public_key_file);
          i=0;
          if(strstr(parameters->public_key_file,".pem")==NULL && strstr(parameters->public_key_file,".der")==NULL)
        	 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_READ_ERROR_CONFIG_FILE);
       }

       if(strcmp(parameter_string,"NEW_PRIVATE_KEY_FILE")==0){
          memset(parameter_string,0,PARAMETER_MAX_SIZE);
          fscanf(defaults,"%s",parameters->new_private_key_file);
          i=0;
          if(strstr(parameters->private_key_file,".pem")==NULL && strstr(parameters->private_key_file,".der")==NULL)
        	 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_READ_ERROR_CONFIG_FILE);
       }

       if(i==PARAMETER_MAX_SIZE || c=='\n')
          i=0;
		   
       if(c == EOF)
          break;			   
    }
    
    fclose(defaults);	
      	
}

int do_cryptographic_tests(){

    char *test;
    int length;
    int res;

    float start_time;

    float dsa_512_time;
    float dsa_1024_time;
    float dsa_2048_time;
    float dsa_4096_time;

    float rsa_512_time;
    float rsa_1024_time;
    float rsa_2048_time;
    float rsa_4096_time;

    float sha224_time;
    float sha256_time;
    float sha384_time;
    float sha512_time;

    float md4_time;
    float md5_time;

    float ripemd160_time;

    float hmac_sha224_time;
    float hmac_sha256_time;
    float hmac_sha384_time;
    float hmac_sha512_time;

    float hmac_md4_time;
    float hmac_md5_time;

    float hmac_ripemd160_time;

    float signing_dsa_time;
    float verifying_dsa_time;

    float signing_rsa_time;
    float verifying_rsa_time;

    DSA *dsa;
    RSA *rsa;

    unsigned char test_message[]="A MESSAGE TEST FOR SIGNING";
    unsigned char *sign;

    unsigned int sign_length;

    printf("\n\nUnibo-DTKA: Creating a SHA 224 string test......");
    printf("\nUnibo-DTKA: Test String is \"TEST\"");

    test = (char*)malloc(sizeof(char)*((SHA224_DIGEST_LENGTH*2)+1)); 
    if(test == NULL)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

    printf("\nUnibo-DTKA: Hashing Result.....");

    start_time = (float)clock()/CLOCKS_PER_SEC;
    length = hash_message_text("TEST",test,SHA224HASH);
    if(length < 0)
       return -1;
    sha224_time = (float)clock()/CLOCKS_PER_SEC - start_time;

    printf("\nHash:%s",test);

    if(strcmp("917ECCA24F3E6CEAF52375D8083381F1F80A21E6E49FBADC40AFEB8E",test)!=0){
       printf("\n\nUnibo-DTKA: Cryptographic test is failed.\n");
       return -1;
    }

    free(test);
	
    printf("\n\nUnibo-DTKA: Creating a SHA 256 string test......");
    printf("\nUnibo-DTKA: Test String is \"TEST\"");

    test = (char*)malloc(sizeof(char)*((SHA256_DIGEST_LENGTH*2)+1)); // Hash String in text format. 
    if(test == NULL)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

    printf("\nUnibo-DTKA: Hashing Result.....");

    start_time = (float)clock()/CLOCKS_PER_SEC;
    length = hash_message_text("TEST",test,SHA256HASH);
    if(length < 0)
       return -1;
    sha256_time = (float)clock()/CLOCKS_PER_SEC - start_time;

    printf("\nHash:%s",test);
    if(strcmp("94EE059335E587E501CC4BF90613E0814F00A7B08BC7C648FD865A2AF6A22CC2",test)!=0){
       printf("\n\nUnibo-DTKA: Cryptographic test is failed.\n");
       return -1;
    }

    free(test);
	
    printf("\n\nUnibo-DTKA: Creating a SHA 384 string test......");
    printf("\nUnibo-DTKA: Test String is \"TEST\"");

    test = (char*)malloc(sizeof(char)*((SHA384_DIGEST_LENGTH*2)+1));   // Hash String in text format. 
    if(test == NULL)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

    printf("\nUnibo-DTKA: Hashing Result.....");

    start_time = (float)clock()/CLOCKS_PER_SEC;
    length = hash_message_text("TEST",test,SHA384HASH);
    if(length < 0)
       return -1;
    sha384_time = (float)clock()/CLOCKS_PER_SEC - start_time;

    printf("\nHash:%s",test);
    if(strcmp("4F37C49C0024445F91977DBC47BD4DA9C4DE8D173D03379EE19C2BB15435C2C7E624EA42F7CC1689961CB7ACA50C7D17",test)!=0){
       printf("\n\nUnibo-DTKA: Cryptographic test is failed.\n");
       return -1;
    }
    free(test);
	
    printf("\n\nUnibo-DTKA: Creating a SHA 512 string test......");
    printf("\nUnibo-DTKA: Test String is \"TEST\"");

    test = (char*)malloc(sizeof(char)*((SHA512_DIGEST_LENGTH*2)+1));   // Hash String in text format. 
    if(test == NULL)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

    printf("\n\nUnibo-DTKA: Hashing Result.....");

    start_time = (float)clock()/CLOCKS_PER_SEC;
    length = hash_message_text("TEST",test,SHA512HASH);
    if(length < 0)
       return -1;
    sha512_time = (float)clock()/CLOCKS_PER_SEC - start_time;

    printf("\nHash:%s",test);
    if(strcmp("7BFA95A688924C47C7D22381F20CC926F524BEACB13F84E203D4BD8CB6BA2FCE81C57A5F059BF3D509926487BDE925B3BCEE0635E4F7BAEBA054E5DBA696B2BF",test)!=0){
       printf("\n\nUnibo-DTKA: Cryptographic test is failed.\n");
       return -1;
    }
    free(test);
	
    printf("\n\nUnibo-DTKA: Creating a MD5 string test......");
    printf("\nUnibo-DTKA: Test String is \"TEST\"");

    test = (char*)malloc(sizeof(char)*((MD5_DIGEST_LENGTH*2)+1));   // Hash String in text format. 
    if(test == NULL)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

    printf("\n\nUnibo-DTKA: Hashing Result.....");

    start_time = (float)clock()/CLOCKS_PER_SEC;
    length = hash_message_text("TEST",test,MD5HASH);
    if(length < 0)
       return -1;
    md5_time = (float)clock()/CLOCKS_PER_SEC - start_time;

    printf("\nHash:%s",test);
    if(strcmp("033BD94B1168D7E4F0D644C3C95E35BF",test)!=0){
       printf("\n\nUnibo-DTKA: Cryptographic test is failed.\n");
       return -1;
    }
    free(test); 
	
    printf("\n\nUnibo-DTKA: Creating a MD4 string test......");
    printf("\nUnibo-DTKA: Test String is \"TEST\"");

    test = (char*)malloc(sizeof(char)*((MD4_DIGEST_LENGTH*2)+1));    // Hash String in text format. 
    if(test == NULL)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

    printf("\n\nUnibo-DTKA: Hashing Result.....");

    start_time = (float)clock()/CLOCKS_PER_SEC;
    length = hash_message_text("TEST",test,MD4HASH);
    if(length < 0)
       return -1;
    md4_time = (float)clock()/CLOCKS_PER_SEC - start_time;

    printf("\nHash:%s",test);
    if(strcmp("D721847324F3C5A30256C521671DC169",test)!=0){
       printf("\n\nUnibo-DTKA: Cryptographic test is failed.\n");
       return -1;
    }
    free(test);
	
    printf("\n\nUnibo-DTKA: Creating a RIPEMD 160 string test......");
    printf("\nUnibo-DTKA: Test String is \"TEST\"");

    test = (char*)malloc(sizeof(char)*((RIPEMD160_DIGEST_LENGTH*2)+1));    // Hash String in text format.
    if(test == NULL)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

    printf("\n\nUnibo-DTKA: Hashing Result.....");

    start_time = (float)clock()/CLOCKS_PER_SEC;
    length = hash_message_text("TEST",test,RIPEMD160HASH);
    if(length < 0)
       return -1;
    ripemd160_time = (float)clock()/CLOCKS_PER_SEC - start_time;

    printf("\nHash:%s",test);
    if(strcmp("317A5CD184CF5AA6EC86F8E0F510C4BB3CCA8658",test)!=0){
       printf("\n\nUnibo-DTKA: Cryptographic test is failed.\n");
       return -1;
    }
    free(test);

    printf("\n\nUnibo-DTKA: Generating HMAC with MD5 Hash function...");
    printf("\nUnibo-DTKA: Test string is \"TEST\"");
    printf("\nUnibo-DTKA: Secret key is \"KEY\"");

    test = (char*)malloc(sizeof(char)*((MD5_DIGEST_LENGTH*2)+1));   // Hash String in text format. 
    if(test == NULL)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

    printf("\n\nUnibo-DTKA: Hashing Result.....");
    start_time = (float)clock()/CLOCKS_PER_SEC;
    hmac_hash("TEST","KEY",MD5HASH,test);
    hmac_md5_time = (float)clock()/CLOCKS_PER_SEC - start_time;

    printf("\nHmac:%s",test);
    if(strcmp("1AEE732E9C1D3FAA20775D1438AF9472",test)!=0){
       printf("\n\nUnibo-DTKA: Cryptographic test is failed.\n");
       return -1;
    }
    free(test);

    printf("\n\nUnibo-DTKA: Generating HMAC with MD4 Hash function...");
    printf("\nUnibo-DTKA: Test string is \"TEST\"");
    printf("\nUnibo-DTKA: Secret key is \"KEY\"");

    test = (char*)malloc(sizeof(char)*((MD4_DIGEST_LENGTH*2)+1));    // Hash String in text format. 
    if(test == NULL)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

    printf("\n\nUnibo-DTKA: Hashing Result.....");
    start_time = (float)clock()/CLOCKS_PER_SEC;
    hmac_hash("TEST","KEY",MD4HASH,test);
    hmac_md4_time = (float)clock()/CLOCKS_PER_SEC - start_time;

    printf("\nHmac:%s",test);
    if(strcmp("50B1478245DB5D220424FDDAB54F315C",test)!=0){
       printf("\n\nUnibo-DTKA: Cryptographic test is failed.\n");
       return -1;
    }
    free(test);
	
    printf("\n\nUnibo-DTKA: Generating HMAC with RIPEMD160 Hash function...");
    printf("\nUnibo-DTKA: Test string is \"TEST\"");
    printf("\nUnibo-DTKA: Secret key is \"KEY\"");

    test = (char*)malloc(sizeof(char)*((RIPEMD160_DIGEST_LENGTH*2)+1));    // Hash String in text format. 
    if(test == NULL)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

    printf("\n\nUnibo-DTKA: Hashing Result.....");
    start_time = (float)clock()/CLOCKS_PER_SEC;
    hmac_hash("TEST","KEY",RIPEMD160HASH,test);
    hmac_ripemd160_time = (float)clock()/CLOCKS_PER_SEC - start_time;

    printf("\nHmac:%s",test);
    if(strcmp("506A8DF051EE0F4E8390F3BC57BE09B6535D9FC3",test)!=0){
       printf("\n\nUnibo-DTKA: Cryptographic test is failed.\n");
       return -1;
    }	
    free(test);

    printf("\n\nUnibo-DTKA: Generating HMAC with SHA-224 Hash function...");
    printf("\nUnibo-DTKA: Test string is \"TEST\"");
    printf("\nUnibo-DTKA: Secret key is \"KEY\"");

    test = (char*)malloc(sizeof(char)*((SHA224_DIGEST_LENGTH*2)+1)); 
    if(test == NULL)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

    printf("\n\nUnibo-DTKA: Hashing Result.....");
    start_time = (float)clock()/CLOCKS_PER_SEC;
    hmac_hash("TEST","KEY",SHA224HASH,test);
    hmac_sha224_time = (float)clock()/CLOCKS_PER_SEC - start_time;

    printf("\nHmac:%s",test);
    if(strcmp("E802B12B9DBFCA2785FB1D93864EB984494E110ACEFE468FEA6A3F79",test)!=0){
       printf("\n\nUnibo-DTKA: Cryptographic test is failed.\n");
       return -1;
    }	
    free(test);

    printf("\n\nUnibo-DTKA: Generating HMAC with SHA-256 Hash function...");
    printf("\nUnibo-DTKA: Test string is \"TEST\"");
    printf("\nUnibo-DTKA: Secret key is \"KEY\"");

    test = (char*)malloc(sizeof(char)*((SHA256_DIGEST_LENGTH*2)+1)); // Hash String in text format. 
    if(test == NULL)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

    printf("\n\nUnibo-DTKA: Hashing Result.....");
    start_time = (float)clock()/CLOCKS_PER_SEC;
    hmac_hash("TEST","KEY",SHA256HASH,test);
    hmac_sha256_time = (float)clock()/CLOCKS_PER_SEC - start_time;

    printf("\nHmac:%s",test);
    if(strcmp("615DAC1C53C9396D8F69A419A0B2D9393A0461D7AD5F7F3D9BEB57264129EF12",test)!=0){
       printf("\n\nUnibo-DTKA: Cryptographic test is failed.\n");
       return -1;
    }	
    free(test);

    printf("\n\nUnibo-DTKA: Generating HMAC with SHA-384 Hash function...");
    printf("\nUnibo-DTKA: Test string is \"TEST\"");
    printf("\nUnibo-DTKA: Secret key is \"KEY\"");

    test = (char*)malloc(sizeof(char)*((SHA384_DIGEST_LENGTH*2)+1));   // Hash String in text format. 
    if(test == NULL)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

    printf("\n\nUnibo-DTKA: Hashing Result.....");
    start_time = (float)clock()/CLOCKS_PER_SEC;
    hmac_hash("TEST","KEY",SHA384HASH,test);
    hmac_sha384_time = (float)clock()/CLOCKS_PER_SEC - start_time;

    printf("\nHmac:%s",test);
    if(strcmp("03AE3F1BA7A6626B24DE55DB51DBAA498C2BAAA58B4A2617F48C8F7EAE58A31E70F2D9F82241E1BBB287D89902F2FE3A",test)!=0){
       printf("\n\nUnibo-DTKA: Cryptographic test is failed.\n");
       return -1;
    }	
    free(test);
    
    printf("\n\nUnibo-DTKA: Generating HMAC with SHA-512 Hash function...");
    printf("\nUnibo-DTKA: Test string is \"TEST\"");
    printf("\nUnibo-DTKA: Secret key is \"KEY\"");

    test = (char*)malloc(sizeof(char)*((SHA512_DIGEST_LENGTH*2)+1));   // Hash String in text format. 
    if(test == NULL)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

    printf("\n\nUnibo-DTKA: Hashing Result.....");
    start_time = (float)clock()/CLOCKS_PER_SEC;
    hmac_hash("TEST","KEY",SHA512HASH,test);
    hmac_sha512_time = (float)clock()/CLOCKS_PER_SEC - start_time;

    printf("\nHmac:%s",test);
    if(strcmp("C0FCB3918E49A7F5AF5AF7881B9B89951EFA39AE1F276237F483D19E0DBC504AAF6FEBE7E3AF4A1DD3BD06BA9DE8737B61B903B584D50B78A549A65FA0806100",test)!=0){
       printf("\n\nUnibo-DTKA: Cryptographic test is failed.\n");
       return -1;
    }	
    free(test);
	
    printf("\n\nUnibo-DTKA: Try to generate DSA key pairs....");
    printf("\nUnibo-DTKA: Generating 512 bit DSA key pair....\n");

    start_time = (float)clock()/CLOCKS_PER_SEC;
    length = generate_and_show_DSA_key_pair(512);
    if(length < 0){
       printf("\n\nUnibo-DTKA: Cryptographic test is failed.\n");
       return -1;
    }
    dsa_512_time = (float)clock()/CLOCKS_PER_SEC - start_time;

    printf("\nUnibo-DTKA: Generating 1024 bit DSA key pair....\n");

    start_time = (float)clock()/CLOCKS_PER_SEC;
    length = generate_and_show_DSA_key_pair(1024);
    if(length < 0){
       printf("\n\nUnibo-DTKA: Cryptographic test is failed.\n");
       return -1;
    }
    dsa_1024_time = (float)clock()/CLOCKS_PER_SEC - start_time;

    printf("\nUnibo-DTKA: Generating 2048 bit DSA key pair....\n");

    start_time = (float)clock()/CLOCKS_PER_SEC;
    length = generate_and_show_DSA_key_pair(2048);
    if(length < 0){
       printf("\n\nUnibo-DTKA: Cryptographic test is failed.\n");
       return -1;
    }
    dsa_2048_time = (float)clock()/CLOCKS_PER_SEC - start_time;

    printf("\nUnibo-DTKA: Generating 4096 bit DSA key pair....\n");

    start_time = (float)clock()/CLOCKS_PER_SEC;
    length = generate_and_show_DSA_key_pair(4096);
    if(length < 0){
       printf("\n\nUnibo-DTKA: Cryptographic test is failed.\n");
       return -1;
    }
    dsa_4096_time = (float)clock()/CLOCKS_PER_SEC - start_time;

    printf("\n\nUnibo-DTKA: Try to generate RSA key pairs....\n");
    printf("\nUnibo-DTKA: Generating 512 bit RSA key pair....\n");

    start_time = (float)clock()/CLOCKS_PER_SEC;
    length = generate_and_show_RSA_key_pair(512);
    if(length < 0){
       printf("\n\nUnibo-DTKA: Cryptographic test is failed.\n");
       return -1;
    }
    rsa_512_time = (float)clock()/CLOCKS_PER_SEC - start_time;

    printf("\nUnibo-DTKA: Generating 1024 bit RSA key pair....\n");

    start_time = (float)clock()/CLOCKS_PER_SEC;
    length = generate_and_show_RSA_key_pair(1024);
    if(length < 0){
       printf("\n\nUnibo-DTKA: Cryptographic test is failed.\n");
       return -1;
    }
    rsa_1024_time = (float)clock()/CLOCKS_PER_SEC - start_time;

    printf("\nUnibo-DTKA: Generating 2048 bit RSA key pair....\n");

    start_time = (float)clock()/CLOCKS_PER_SEC;
    length = generate_and_show_RSA_key_pair(2048);
    if(length < 0){
       printf("\n\nUnibo-DTKA: Cryptographic test is failed.\n");
       return -1;
    }
    rsa_2048_time = (float)clock()/CLOCKS_PER_SEC - start_time;

    printf("\nUnibo-DTKA: Generating 4096 bit RSA key pair....\n");

    start_time = (float)clock()/CLOCKS_PER_SEC;
    length = generate_and_show_RSA_key_pair(4096);
    if(length < 0){
       printf("\n\nUnibo-DTKA: Cryptographic test is failed.\n");
       return -1;
    }
    rsa_4096_time = (float)clock()/CLOCKS_PER_SEC - start_time;

    dsa = DSA_new();
    generate_DSA_key_pair(1024,32,dsa);
    sign = calloc(DSA_size(dsa),sizeof(unsigned char));
    if(sign == NULL)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

    printf("\nUnibo-DTKA: Signing a test message with a 1024 bit DSA public key.");
    printf("\nTest message: %s",test_message);

    start_time = (float)clock()/CLOCKS_PER_SEC;
    res = sign_with_DSA_private_key(dsa,test_message,strlen((char*)test_message),sign,&sign_length);
    if(res < 0){
       printf("\n\nUnibo-DTKA: Cryptographic test is failed.\n");
       return -1;
    }
    signing_dsa_time = (float)clock()/CLOCKS_PER_SEC - start_time;

    printf("\nUnibo-DTKA: Verifying the signed message.");

    start_time = (float)clock()/CLOCKS_PER_SEC;
    res = verify_with_DSA_public_key(dsa,test_message,strlen((char*)test_message),sign,sign_length);
    if(res != 1){
       printf("\n\nUnibo-DTKA: Cryptographic test is failed.\n");
       return -1;
    }
    verifying_dsa_time = (float)clock()/CLOCKS_PER_SEC - start_time;
    printf("\nUnibo-DTKA: Sign Verified.");
    printf("\nUnibo-DTKA: Verifying bogus signature....");
    sign[0] = sign[0]+1;
    res = verify_with_DSA_public_key(dsa,test_message,strlen((char*)test_message),sign,sign_length);
    if(res != -1){
       printf("\n\nUnibo-DTKA: Cryptographic test is failed.\n");
       return -1;
    }
    printf("\nUnibo-DTKA: Bogus message rejected.");

    free(sign);
    DSA_free(dsa);

    rsa = RSA_new();
    generate_RSA_key_pair(1024,17,rsa);
    sign = calloc(RSA_size(rsa),sizeof(unsigned char));
    if(sign == NULL)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

    printf("\n\nUnibo-DTKA: Signing a test message with a 1024 bit RSA public key.");
    printf("\nTest message: %s",test_message);

    start_time = (float)clock()/CLOCKS_PER_SEC;
    res = sign_with_RSA_private_key(rsa,test_message,strlen((char*)test_message),sign,&sign_length);
    if(res < 0){
       printf("\n\nUnibo-DTKA: Cryptographic test is failed.\n");
       return -1;
    }
    signing_rsa_time = (float)clock()/CLOCKS_PER_SEC - start_time;

    printf("\nUnibo-DTKA: Verifying the signed message.");

    start_time = (float)clock()/CLOCKS_PER_SEC;
    res = verify_with_RSA_public_key(rsa,test_message,strlen((char*)test_message),sign,sign_length);
    if(res != 1){
       printf("\n\nUnibo-DTKA: Cryptographic test is failed.\n");
       return -1;
    }
    verifying_rsa_time = (float)clock()/CLOCKS_PER_SEC - start_time;
    printf("\nUnibo-DTKA: Sign Verified.");
    printf("\nUnibo-DTKA: Verifying bogus signature....");
    sign[0] = sign[0]+1;
    res = verify_with_RSA_public_key(rsa,test_message,strlen((char*)test_message),sign,sign_length);
    if(res != 0){
       printf("\n\nUnibo-DTKA: Cryptographic test is failed.\n");
       return -1;
    }
    printf("\nUnibo-DTKA: Bogus message rejected.");

    free(sign);
    RSA_free(rsa);

    printf("\n\nUnibo-DTKA: SHA-224 Hash time: %f seconds.",sha224_time);
    printf("\nUnibo-DTKA: SHA-256 Hash time: %f seconds.",sha256_time);
    printf("\nUnibo-DTKA: SHA-384 Hash time: %f seconds.",sha384_time);
    printf("\nUnibo-DTKA: SHA-512 Hash time: %f seconds.",sha512_time);
    printf("\nUnibo-DTKA: MD5 Hash time: %f seconds.",md5_time);
    printf("\nUnibo-DTKA: MD4 Hash time: %f seconds.",md4_time);
    printf("\nUnibo-DTKA: RIPEMD-160 Hash time: %f seconds.",ripemd160_time);

    printf("\n\nUnibo-DTKA: Hmac SHA-224 time: %f seconds.",hmac_sha224_time);
    printf("\nUnibo-DTKA: Hmac SHA-256 time: %f seconds.",hmac_sha256_time);
    printf("\nUnibo-DTKA: Hmac SHA-384 time: %f seconds.",hmac_sha384_time);
    printf("\nUnibo-DTKA: Hmac SHA-512 time: %f seconds.",hmac_sha512_time);
    printf("\nUnibo-DTKA: Hmac MD5 time: %f seconds.",hmac_md5_time);
    printf("\nUnibo-DTKA: Hmac MD4 time: %f seconds.",hmac_md4_time);
    printf("\nUnibo-DTKA: Hmac RIPEMD-160 time: %f seconds.",hmac_ripemd160_time);

    printf("\n\nUnibo-DTKA: DSA 512 bit key pair generated in %f seconds.",dsa_512_time);
    printf("\nUnibo-DTKA: DSA 1024 bit key pair generated in %f seconds.",dsa_1024_time);
    printf("\nUnibo-DTKA: DSA 2048 bit key pair generated in %f seconds.",dsa_2048_time);
    printf("\nUnibo-DTKA: DSA 4096 bit key pair generated in %f seconds.",dsa_4096_time);

    printf("\n\nUnibo-DTKA: RSA 512 bit key pair generated in %f seconds.",rsa_512_time);
    printf("\nUnibo-DTKA: RSA 1024 bit key pair generated in %f seconds.",rsa_1024_time);
    printf("\nUnibo-DTKA: RSA 2048 bit key pair generated in %f seconds.",rsa_2048_time);
    printf("\nUnibo-DTKA: RSA 4096 bit key pair generated in %f seconds.",rsa_4096_time);

    printf("\n\nUnibo-DTKA: DSA signing time in %f seconds.",signing_dsa_time);
    printf("\nUnibo-DTKA: DSA verifying time in %f seconds.",verifying_dsa_time);
    printf("\n\nUnibo-DTKA: RSA signing time in %f seconds.",signing_rsa_time);
    printf("\nUnibo-DTKA: RSA verifying time in %f seconds.",verifying_rsa_time);

    return 1;

}

int do_erasure_test(){

    fec_encoded_data *encoded_message;
    fec_received_data *received_message;
    char *message = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234";

    float start_time;
    float encode_time;
    float decode_time;

    start_time = (float)clock()/CLOCKS_PER_SEC;
    encoded_message = encode_blocks(5,7,(unsigned char*)message,30);
	encode_time = (float)clock()/CLOCKS_PER_SEC - start_time;

    received_message = calloc(1,sizeof(fec_received_data));
    if(received_message == NULL)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);
	
    received_message->K = encoded_message->K;
    received_message->M = encoded_message->M;
    received_message->block_size = encoded_message->block_size;
	
    received_message->input_blocks = calloc(received_message->K, sizeof(unsigned char*));
    if(received_message == NULL)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);
	
    received_message->input_blocks[0] = encoded_message->secondary_blocks[0];
    received_message->input_blocks[1] = encoded_message->primary_blocks[1];
    received_message->input_blocks[2] = encoded_message->primary_blocks[2];
    received_message->input_blocks[3] = encoded_message->primary_blocks[3];
    received_message->input_blocks[4] = encoded_message->primary_blocks[4];
	
    received_message->index_blocks = calloc(received_message->K, sizeof(int));
    if(received_message == NULL)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);
	
    received_message->index_blocks[0] = 5;
    received_message->index_blocks[1] = 1;
    received_message->index_blocks[2] = 2;
    received_message->index_blocks[3] = 3;
    received_message->index_blocks[4] = 4;
	
    message = calloc(received_message->block_size*received_message->K,sizeof(unsigned char));
    if(message == NULL)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

    start_time = (float)clock()/CLOCKS_PER_SEC;
    decode_blocks(received_message,(unsigned char*)message);
    decode_time = (float)clock()/CLOCKS_PER_SEC - start_time;

    if(strcmp(message,"ABCDEFGHIJKLMNOPQRSTUVWXYZ1234")==0){
       printf("\n\nUnibo-DTKA: Erasure code test is passed.");
       printf("\nUnibo-DTKA: Time for encoding: %f",encode_time);
       printf("\nUnibo-DTKA: Time for decoding: %f",decode_time);
       return 1;
    }else{
       printf("\n\nUnibo-DTKA: Erasure code test is failed.\n");
       return -1;
    }

	return 1;
}

void init_application(dtka_parameters *parameters,const char* filename,int mode){

    int i;
    record_list *list;
    list = &rec_list;

    read_parameters_from_file(filename,parameters);

    fprintf(parameters->fp_log,"\nUnibo-DTKA: Number of Authorities: %d",parameters->number_of_authorities);
    for(i=0; i<parameters->number_of_authorities; i++){
       fprintf(parameters->fp_log,"\nUnibo-DTKA: Authority %d EID: %s",i,parameters->authority_eid[i]);
       fprintf(parameters->fp_log,"\nUnibo-DTKA: Authority %d Key File: %s",i,parameters->authority_key_file[i]);
    }

    fprintf(parameters->fp_log,"\nUnibo-DTKA: Number of Clients: %d",parameters->number_of_clients);
    for(i=0; i<parameters->number_of_clients; i++){
       fprintf(parameters->fp_log,"\nUnibo-DTKA: Client %d EID: %s",i,parameters->clients_eid[i]);
       fprintf(parameters->fp_log,"\nUnibo-DTKA: Client %d Key File: %s",i,parameters->clients_key_file[i]);
    }

    fprintf(parameters->fp_log,"\nUnibo-DTKA: Number of Information Blocks: %d",parameters->information_block_number);
    fprintf(parameters->fp_log,"\nUnibo-DTKA: Number of Total Blocks: %d",parameters->total_block_number);
    fprintf(parameters->fp_log,"\nUnibo-DTKA: Public Key Algorithm: %s",parameters->key_algorithm);
    fprintf(parameters->fp_log,"\nUnibo-DTKA: Key Length: %d",parameters->key_length);
    fprintf(parameters->fp_log,"\nUnibo-DTKA: Hash Algorithm: %s",parameters->hash_algorithm);
    fprintf(parameters->fp_log,"\nUnibo-DTKA: Padding Type: %s",parameters->padding_type);
    fprintf(parameters->fp_log,"\nUnibo-DTKA: RSA Number: %d",parameters->rsa_exp);
    fprintf(parameters->fp_log,"\nUnibo-DTKA: Public Key File: %s",parameters->public_key_file);
    fprintf(parameters->fp_log,"\nUnibo-DTKA: Private Key File: %s",parameters->private_key_file);
    fprintf(parameters->fp_log,"\nUnibo-DTKA: New Public Key File: %s",parameters->new_public_key_file);
    fprintf(parameters->fp_log,"\nUnibo-DTKA: New Private Key File: %s",parameters->new_private_key_file);
    fprintf(parameters->fp_log,"\nUnibo-DTKA: Key Format: %s",parameters->key_format);
    fprintf(parameters->fp_log,"\nUnibo-DTKA: Expiration Time: %d s.",parameters->expiration_time);
    fprintf(parameters->fp_log,"\nUnibo-DTKA: Bulletin Publish Time: %d s.",parameters->bulletin_time);
    fprintf(parameters->fp_log,"\nUnibo-DTKA: Bulletin Save File: %s",parameters->bulletin_file);
    fprintf(parameters->fp_log,"\nUnibo-DTKA: Key Publish Time: %d s.",parameters->key_publish_interval);
    fprintf(parameters->fp_log,"\nUnibo-DTKA: Grace Period : %d s.",parameters->grace_time);
    fprintf(parameters->fp_log,"\nUnibo-DTKA: Receive Time: %d",parameters->receive_time);
    fprintf(parameters->fp_log,"\nUnibo-DTKA: Bundle Priority: %s",parameters->bundle_priority);
    fprintf(parameters->fp_log,"\nUnibo-DTKA: Block per Authority: %d",parameters->block_per_authority);

    if(parameters->sign == 1)
       fprintf(parameters->fp_log,"\nUnibo-DTKA: Bundles are signed with Private Key");

    if(parameters->sign == 0)
       fprintf(parameters->fp_log,"\nUnibo-DTKA: Bundles are sent via BSP");

    if(mode == AUTHORITY_MODE){
       fprintf(parameters->fp_log,"\nInizialing record data base.");
       list->next = NULL;
       list->records = 0;
       list->record = NULL;
       run_authority_mode();
    }

    if(mode == CLIENT_MODE)
       run_client_mode();

}   

int do_connection_test(){

	connection_wrapper_t connection;

	al_bp_bundle_priority_t priority;
    char message[] = "ABC";

	printf("\nPerforming a test connection...");

	priority.priority = BP_PRIORITY_NORMAL;
	printf("\nInitialization of the connection parameters....");
    wrapper_init(&connection, BP_PAYLOAD_MEM, 'N', 30, priority, 30,"dtka","4000");
    printf("\nRegistration to the bundle daemon....");
    register_to_dtn_daemon(&connection);

    printf("\nLocal EID = %s\n", connection.local_eid.uri);
    printf("\nTry to Send bundle to itself...");
    printf("\nMessage: ABC");
    wrapper_send(&connection,(unsigned char*)message,3,connection.local_eid.uri);
    printf("\nTry to Receive bundle....");
    wrapper_receive(&connection);
    printf("\nReceived Message: %s",connection.message);

    if(strcmp((char*)connection.message,"ABC")==0)
       return 1;
    else
       return -1;

}

int get_next_block_index(int current,int max){

    if(current < max)
       return current++;
    else
       return 0;
}

int prepare_key_message(unsigned char *key){

	dtka_parameters *p;
    p = &parameters;

    int key_length;
    int c;
    FILE *fp;

    if(strcmp(p->key_algorithm,"RSA")==0 && strcmp(p->key_format,"PEM")==0)
       generate_RSA_key_pair_files(p->key_length,p->rsa_exp,p->new_private_key_file,p->new_public_key_file,PEM_FORMAT);

    if(strcmp(p->key_algorithm,"RSA")==0 && strcmp(p->key_format,"DER")==0)
       generate_RSA_key_pair_files(p->key_length,p->rsa_exp,p->new_private_key_file,p->new_public_key_file,DER_FORMAT);

    if(strcmp(p->key_algorithm,"DSA")==0 && strcmp(p->key_format,"PEM")==0)
       generate_DSA_key_pair_files(p->key_length,p->rand_length,p->new_private_key_file,p->new_public_key_file,PEM_FORMAT);

    if(strcmp(p->key_algorithm,"DSA")==0 && strcmp(p->key_format,"DER")==0)
       generate_DSA_key_pair_files(p->key_length,p->rand_length,p->new_private_key_file,p->new_public_key_file,DER_FORMAT);

    key_length = 0;
    c = 0;
    fp = fopen(p->new_public_key_file,"r");

    if(key == NULL){
       while(c != EOF){
    	   c = fgetc(fp);
    	   key_length++;
       }
       rewind(fp);
       fclose(fp);
       return key_length;
    }

    while(c != EOF){
       c = fgetc(fp);
       key_length++;
       key[key_length] = (unsigned char)c;
    }

    fclose(fp);

    return key_length;
}

int serialize_message(unsigned char *serialized_message,unsigned short EID_length,unsigned char *EID,unsigned int effective_time,unsigned int assertion_time,unsigned int data_length,unsigned char*data){

	dtka_parameters *p;
	unsigned char *cursor;
	unsigned int howmany;
	unsigned int sign_length;
	unsigned char *buffer_sign;
    unsigned short s_temp;
    unsigned int i_temp;

    RSA *rsa;
    DSA *dsa;
	p = &parameters;

    if(serialized_message == NULL){
    	howmany = sizeof(unsigned short)+EID_length+sizeof(unsigned int)+sizeof(unsigned int)+sizeof(unsigned int)+data_length;
    	if(p->sign == 1){
    	   howmany = howmany + sizeof(unsigned int);
    	   if(strcmp(p->key_algorithm,"RSA")==0){
        	  rsa = RSA_new();
        	  read_RSA_key_from_file(p->public_key_file,PUBLIC_KEY,rsa);
        	  howmany = howmany + RSA_size(rsa);
         	  RSA_free(rsa);
           }
           if(strcmp(p->key_algorithm,"DSA")==0){
        	  dsa = DSA_new();
        	  read_DSA_key_from_file(p->public_key_file,PUBLIC_KEY,dsa);
        	  howmany = howmany + DSA_size(dsa);
        	  DSA_free(dsa);
           }
    	}
        return howmany;
    }

    cursor = serialized_message;
    howmany = 0;

    s_temp = htons(EID_length);
    memcpy(cursor,&s_temp,sizeof(unsigned short));
    howmany = howmany + sizeof(unsigned short);
    cursor = cursor + sizeof(unsigned short);

    memcpy(cursor,EID,EID_length);
    howmany = howmany + EID_length;
    cursor = cursor + EID_length;

    i_temp = htonl(effective_time);
    memcpy(cursor,&i_temp,sizeof(unsigned int));
    howmany = howmany + sizeof(unsigned int);
    cursor = cursor + sizeof(unsigned int);

    i_temp = htonl(assertion_time);
    memcpy(cursor,&i_temp,sizeof(unsigned int));
    howmany = howmany + sizeof(unsigned int);
    cursor = cursor + sizeof(unsigned int);

    i_temp = htonl(data_length);
    memcpy(cursor,&i_temp,sizeof(unsigned int));
    howmany = howmany + sizeof(unsigned int);
    cursor = cursor + sizeof(unsigned int);

    memcpy(cursor,data,data_length);
    howmany = howmany + data_length;

    if(p->sign == 1){
       if(strcmp(p->key_algorithm,"RSA")==0){
    	  rsa = RSA_new();
    	  read_RSA_key_from_file(p->public_key_file,PUBLIC_KEY,rsa);
    	  sign_length = RSA_size(rsa);
    	  buffer_sign = calloc(sign_length,sizeof(unsigned char));
    	  if(buffer_sign == NULL)
    		 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);
    	  RSA_free(rsa);
        }
    	if(strcmp(p->key_algorithm,"DSA")==0){
    	  dsa = DSA_new();
    	  read_DSA_key_from_file(p->public_key_file,PUBLIC_KEY,dsa);
    	  sign_length = DSA_size(dsa);
    	  buffer_sign = calloc(sign_length,sizeof(unsigned char));
    	  if(buffer_sign == NULL)
    		 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);
    	  DSA_free(dsa);
    	}
    	sign_with_private_key_from_file(p->private_key_file,p->key_algorithm,buffer_sign,&sign_length,serialized_message,howmany);
    	cursor = cursor+data_length;
    	i_temp = htonl(sign_length);
    	memcpy(cursor,&i_temp,sizeof(unsigned int));
    	howmany = howmany + sizeof(unsigned int);
    	cursor = cursor + sizeof(unsigned int);
        memcpy(cursor,buffer_sign,sign_length);
        howmany = howmany + sign_length;
    }

    return howmany;

}

int deserialize_message(unsigned char *serialized_message,unsigned short *EID_length,unsigned char *EID,unsigned int *effective_time,unsigned int *assertion_time,unsigned int *data_length,unsigned char *data){

	unsigned char *cursor;
	unsigned int sign_length;
    unsigned int message_length;
    unsigned char *buffer_sign;
    unsigned char *buffer_message;
    int result;

    dtka_parameters *p;
    p = &parameters;

    message_length = 0;
    cursor = serialized_message;

	memcpy(EID_length,cursor,sizeof(unsigned short));
	*EID_length = ntohs(*EID_length);
	cursor = cursor + sizeof(unsigned short);
    message_length = message_length + sizeof(unsigned short);

	memcpy(EID,cursor,*EID_length);
	cursor = cursor + *EID_length;
	message_length = message_length + *EID_length;

	memcpy(effective_time,cursor,sizeof(unsigned int));
	*effective_time = ntohl(*effective_time);
	cursor = cursor + sizeof(unsigned int);
	message_length = message_length + sizeof(unsigned int);

	memcpy(assertion_time,cursor,sizeof(unsigned int));
	*assertion_time = ntohl(*assertion_time);
	cursor = cursor + sizeof(unsigned int);
	message_length = message_length + sizeof(unsigned int);

	memcpy(data_length,cursor,sizeof(unsigned int));
	*data_length = ntohl(*data_length);
	cursor = cursor + sizeof(unsigned int);
    message_length = message_length + sizeof(unsigned int);

	memcpy(data,cursor,*data_length);

	if(p->sign == 1){
		cursor = cursor + *data_length;
		message_length = message_length + *data_length;

		memcpy(&sign_length,cursor,sizeof(unsigned int));
		sign_length = ntohl(sign_length);
        cursor = cursor + sizeof(unsigned int);

	   	buffer_message = calloc(message_length,sizeof(unsigned char));
	   	if(buffer_message == NULL)
	   	   unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

	   	buffer_sign = calloc(sign_length,sizeof(unsigned char));
        if(buffer_sign == NULL)
        	unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

        memcpy(buffer_message,serialized_message,message_length);
        memcpy(buffer_sign,cursor,sign_length);

        result = verify_with_public_key_from_file(p->public_key_file,p->key_algorithm,buffer_sign,sign_length,buffer_message,message_length);

        return result;
	}else
        return 1;
}

int create_bulletin(unsigned char*bulletin){

	dtka_parameters *p;
    record_list *list;
    record_list *first;

    int length;
    int i;
    int temp;

    char *cursor;
    cursor = (char*)bulletin;

    p = &parameters;
    list = &rec_list;
    first = &rec_list;

    if(bulletin == NULL){
       length = strlen("currentCompilationTime = YYYY/MM/DD - HH:MM:SS, ");
       length = length + strlen("nextCompilationTime = YYYY/MM/DD - HH:MM:SS, ");
       length = length + strlen("compilationInterval = ");
       length = length + snprintf(NULL, 0, "%d, ", p->bulletin_time);
       length = length + strlen("consensusInterval = ");
       length = length + snprintf(NULL, 0, "%d ",p->grace_time);
       length = length + strlen("\n---Consensus bulletin report---");
       length = length + strlen("\nAuthorities:\n");
       for(i=0; i<p->number_of_authorities; i++)
    	   length = length + snprintf(NULL,0,"\t%d\t%s\t%d\n",i,p->authority_eid[i],p->authority_status[i]);
       length = length + strlen("\nNumber of record in consensus: ");
       length = length + snprintf(NULL,0,"%d\n",first->records);
       for(i=0; i<first->records; i++){
          length = length + sizeof(int);
          length = length + strlen(list->record->EID);
          length = length + sizeof(int);
          length = length + strlen(list->record->acknowledged);
          length = length + sizeof(unsigned int);
          length = length + sizeof(unsigned int);
          length = length + sizeof(unsigned int);
          length = length + list->record->data_length;
          list = list->next;
       }
       length = length + snprintf(NULL,0,"\n---End of consensus bulletin report---");
       return length;
    }

    length = sprintf(cursor,"currentCompilationTime = YYYY/MM/DD - HH:MM:SS, "
    		                "nextCompilationTime = YYYY/MM/DD - HH:MM:SS, "
    		                "compilationInterval = %d"
    		                "consensusInterval = %d"
    		                "\n---Consensus bulletin report---"
    		                "\nAuthorities:\n",p->bulletin_time,p->grace_time);

    cursor = cursor + length;

    for(i=0; i<p->number_of_authorities; i++){
 	   length = sprintf(cursor,"\t%d\t%s\t%d\n",i,p->authority_eid[i],p->authority_status[i]);
 	   cursor = cursor+length;
    }

    length = sprintf(cursor,"\nNumber of record in consensus: %d\n",first->records);
    cursor = cursor + length;

    for(i=0; i<first->records; i++){
    	temp = strlen(list->record->EID);
        memcpy(cursor,&temp,sizeof(int));
        cursor = cursor + sizeof(int);
        memcpy(cursor,list->record->EID,temp);
        cursor = cursor + temp;

        temp = strlen(list->record->acknowledged);
        memcpy(cursor,&temp,sizeof(int));
        cursor = cursor + sizeof(int);
        memcpy(cursor,list->record->acknowledged,temp);
        cursor = cursor + temp;

        memcpy(cursor,&list->record->assertion_time,sizeof(unsigned int));
        cursor = cursor + sizeof(unsigned int);
        memcpy(cursor,&list->record->effective_time,sizeof(unsigned int));
        cursor = cursor + sizeof(unsigned int);
        memcpy(cursor,&list->record->data_length,sizeof(unsigned int));
        cursor = cursor + sizeof(unsigned int);
        memcpy(cursor,list->record->data_value,list->record->data_length);
        cursor = cursor + list->record->data_length;

    }

    length = sprintf(cursor,"\n---End of consensus bulletin report---");

    return 1;

}

int serialize_record(unsigned char *serialized_records){

    record_list *list;
    record_list *first;
    dtka_parameters *p;

    unsigned char *cursor;

    int i;
    int howmany;

    list = &rec_list;
    first = &rec_list;
    p = &parameters;
    howmany = 0;

    if(serialized_records == NULL){
       howmany = howmany+sizeof(unsigned int)+list->record->data_length+p->number_of_authorities;
       howmany = howmany*first->records;
       return howmany;
    }

    cursor = serialized_records;

    for(i=0; i<first->records; i++){
       memcpy(cursor,&list->record->data_length,sizeof(unsigned int));
       cursor = cursor + sizeof(unsigned int);
       memcpy(cursor,list->record->data_value,list->record->data_length);
       cursor = cursor + list->record->data_length;
       memcpy(cursor,list->record->acknowledged,p->number_of_authorities);
       cursor = cursor + p->number_of_authorities;
       list = list->next;
    }

    list = first;
    return 1;

}

int find_my_index(connection_wrapper_t *connection,int mode,char *ep_service){

	dtka_parameters *p;
	int i;

	char *temp;
	p = &parameters;


	if(mode == AUTHORITY_MODE)
	   for(i=0; i<p->number_of_authorities; i++){
		  temp = calloc(strlen(p->authority_eid[i])+strlen(ep_service),sizeof(char));
		  strcpy(temp,p->authority_eid[i]);
		  strcpy(temp+strlen(p->authority_eid[i]),ep_service);
		  if(strcmp(temp,connection->local_eid.uri)==0)
			 return i;
	   }

	if(mode == CLIENT_MODE)
	   for(i=0; i<p->number_of_clients; i++){
		   temp = calloc(strlen(p->clients_eid[i])+strlen(ep_service),sizeof(char));
		   strcpy(temp,p->clients_eid[i]);
		   strcpy(temp+strlen(p->clients_eid[i]),ep_service);
		   if(strcmp(temp,connection->local_eid.uri)==0)
			   return i;
	   }

    return -1;
}

void unibo_dtka_error_handler(int exit_status){

	FILE *fp = stdout;
    switch(exit_status){

    case 0:
       exit(UNIBO_DTKA_EXIT_STATUS_OK);
    case UNIBO_DTKA_EXIT_STATUS_CONFIG_FILE_NOT_EXISTS:
       fprintf(fp,"\n\nUnibo-DTKA: config file does not exists. \n");
       exit(1);
    case UNIBO_DTKA_EXIT_STATUS_READ_ERROR_CONFIG_FILE:
       fprintf(fp,"\nUnibo-DTKA: Read Error in the config file. \n");
       exit(2);
    case UNIBO_DTKA_EXIT_STATUS_SYNTAX_ERROR:
       fprintf(fp,"\nUnibo-DTKA: Syntax Error. Type Unibo-DTKA --help for help. \n");
       exit(3);
    case UNIBO_DTKA_EXIT_STATUS_WRITE_ERROR_CONFIG_FILE:
       fprintf(fp,"\nUnibo-DTKA: Write error in the config file. \n");
       exit(4);
    case UNIBO_DTKA_EXIT_STATUS_CRYPTO_LIBRARY_ERROR:
       fprintf(fp,"\nUnibo-DTKA: Error in crypthographic library. \n");
       exit(5);
    case UNIBO_DTKA_EXIT_STATUS_ERASURE_LIBRARY_ERROR:
       fprintf(fp,"\nUnibo-DTKA: Error in erasure library. \n");
       exit(6);
    case UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR:
       fprintf(fp,"\nUnibo-DTKA: Not enough memory. \n");
       exit(7);
    case UNIBO_DTKA_EXIT_STATUS_KEY_ALGORITHM_ERROR:
       fprintf(fp,"\nUnibo-DTKA: Key algorithm unknown. \n");
       exit(8);
    case UNIBO_DTKA_EXIT_STATUS_NO_DAEMON_RUNNING:
       fprintf(fp,"\nUnibo-DTKA: No bundle daemon is running or detected. \n");
       exit(9);
    case UNIBO_DTKA_EXIT_STATUS_OPENING_HANDLE_ERROR:
       fprintf(fp,"\nUnibo-DTKA: Error opening Bundle Protocol Handle. \n");
       exit(10);
    case UNIBO_DTKA_EXIT_STATUS_KEY_FILE_NOT_FOUND:
       fprintf(fp,"\nUnibo-DTKA: Public or Private Key file not found. \n");
       exit(11);
    case UNIBO_DTKA_EXIT_STATUS_WRITE_ERROR_KEY_FILE:
       fprintf(fp,"\nUnibo-DTKA: Write error on RSA key file. \n");
       exit(12);
    case UNIBO_DTKA_EXIT_STATUS_READ_ERROR_KEY_FILE:
       fprintf(fp,"\nUnibo-DTKA: Read error on the key file. \n");
       exit(13);
    case UNIBO_DTKA_EXIT_STATUS_VERIFY_ERROR:
       fprintf(fp,"\nUnibo-DTKA: Error on sign verify. \n");
       exit(14);
    case UNIBO_DTKA_EXIT_STATUS_KEY_GENERATION_ERROR:
       fprintf(fp,"\nUnibo-DTKA: Error generating key. \n");
       exit(15);
    default:
       fprintf(fp,"\nUnibo-DTKA: Unknown Error. \n");
       exit(-1);

    }
}

void *receive_bulletin(){

	int i;
	int temp;

	unsigned char *received_hash;
    unsigned char *cursor;

    dtka_parameters *p;

	block_list *list;
	block_list *first;

	p = &parameters;

	list = calloc(1,sizeof(block_list));
	first = list;

	received_hash = calloc(SHA256_DIGEST_LENGTH*2+1,sizeof(char));

	for(;;){
	   wrapper_receive(&receive_bulletin_connection);
	   cursor = receive_bulletin_connection.message;
       transmitted++;
       fprintf(p->fp_log,"\nUnibo-DTKA Client: Received Bulletin from %s",receive_bulletin_connection.bundle_source);
	   if(ok){
	   for(i=0; i<p->block_per_authority; i++){
	      memcpy(received_hash,receive_bulletin_connection.message,(SHA256_DIGEST_LENGTH*2+1));
          cursor = cursor + (SHA256_DIGEST_LENGTH*2+1);

          memcpy(&temp,cursor,sizeof(int));
          cursor = cursor + sizeof(int);
          list->index_block = ntohl(temp);

          memcpy(&temp,cursor,sizeof(int));
          cursor = cursor + sizeof(int);
          list->block_length = ntohl(temp);

          list->block_data = calloc(list->block_length,sizeof(char));

          memcpy(list->block_data,cursor,list->block_length);
          cursor = cursor + list->block_length;

          list->next = calloc(1,sizeof(block_list));
          list = list->next;

       }

	   list = first;
	   i = 0;
	   }else{
		  if(transmitted == p->number_of_authorities-1){
			 reconstruct_bulletin();
	         for(i=0; i<_length; i++)
	    	   fprintf(p->fp_bulletin,"%c",_bulletin[i]);
	      fflush(p->fp_bulletin);
          fprintf(p->fp_log,"\nUnibo-DTKA: Reconstructed Bulletin saved on file %s",p->bulletin_file);
	      fflush(p->fp_log);
	      transmitted = 0;
		  }
	  }
	}
    return (void*)0;
}

void reconstruct_bulletin(){

    fec_received_data *received_message;
    dtka_parameters *p;

    record_list *list;
    record_list *first;
    record_list *current;

    list = &rec_list;
    first = &rec_list;
    current = &rec_list;

    int count_rec;
    int count_idx;
    int i;
    unsigned char *message;

    p=&parameters;

    if(ok){
       received_message = calloc(1,sizeof(fec_received_data));

       received_message->K = p->information_block_number;
       received_message->M = p->total_block_number-p->information_block_number;
       received_message->block_size = rec_list.record->data_length;

       received_message->input_blocks = calloc(received_message->K, sizeof(unsigned char*));
       if(received_message == NULL)
          unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

       received_message->index_blocks = calloc(received_message->K, sizeof(int));
       if(received_message == NULL)
          unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

       message = calloc(received_message->block_size*received_message->K,sizeof(unsigned char));
       if(message == NULL)
          unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

       count_rec = 0;
       count_idx = 0;
       for(i=0; i<first->records; i++){
         for(i=0; i<first->records; i++){
    	    if(memcmp(current->record->data_value,list->record->data_value,list->record->data_length)==0)
    		   count_idx++;
    	    list = list->next;

         }
         if(count_idx > p->number_of_authorities/2+1)
        	count_rec++;
         if(count_rec > p->number_of_authorities/2+1){
            memcpy(list->record->data_value,received_message->input_blocks[i],list->record->data_length);
            received_message->index_blocks[i] = i;
         }
         else{
            memcpy(list->record->data_value,received_message->input_blocks[i],list->record->data_length);
            received_message->index_blocks[i] = p->information_block_number + 1;
         }current = current->next;
       }
       decode_blocks(received_message,message);
    }

}
void *update_keys(){

	dtka_parameters *p;
	p = &parameters;

	for(;;){
	   sleep(p->expiration_time);
	   fprintf(p->fp_log,"\nUnibo-DTKA Client: Updating key pairs...");
	   fflush(p->fp_log);
       remove(p->private_key_file);
       remove(p->public_key_file);
       rename(p->new_private_key_file,p->private_key_file);
       rename(p->new_public_key_file,p->public_key_file);
       fprintf(p->fp_log,"\nUnibo-DTKA Client: Key pair updated.");
       fflush(p->fp_log);
	}

	return (void*)0;
}
