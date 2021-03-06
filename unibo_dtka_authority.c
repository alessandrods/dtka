/********************************************************
 **  Authors: Alessandro Di Stanislao, alessand.distanislao@studio.unibo.it
 **           Carlo Caini (project supervisor), carlo.caini@unibo.it
 **
 **
 **  Copyright (c) 2018, Alma Mater Studiorum, University of Bologna
 **  All rights reserved.
 ********************************************************/

#include "unibo_dtka_includes.h"
#include "connection_wrapper.h"
#include "security_layer.h"
#include "erasure_layer.h"
#include "unibo_dtka_functions.h"
#include "unibo_dtka_types.h"
#include "unibo_dtka_authority.h"

extern struct dtka_parameters parameters;

connection_wrapper_t receiving_key_connection;
connection_wrapper_t sending_key_connection;

connection_wrapper_t receive_consensus_connection;
connection_wrapper_t sending_consensus_connection;

connection_wrapper_t receive_bulletin_connection;
connection_wrapper_t sending_bulletin_connection;

extern struct record_list rec_list;

int receive_status;
int publish_bulletin;
unsigned char *_bulletin;
int _length;

void *publish_bulletin_thread_authority(){

   dtka_parameters *p;
   fec_encoded_data *encoded_message;

   unsigned char *bulletin;
   unsigned char *serialized_blocks;
   unsigned char *cursor;
   unsigned char *bulletin_hash;
   char *url;

   int length;
   int auth_index;
   int i;
   int temp;

   p = &parameters;

   for(;;){
	   if(publish_bulletin == 0)
		  continue;

	   publish_bulletin = 0;
	   length = create_bulletin(NULL);
       _length = length;

	   bulletin = calloc(length,sizeof(char));
       _bulletin = calloc(length,sizeof(char));

	   create_bulletin(bulletin);
       create_bulletin(_bulletin);

	   fprintf(p->fp_log,"\nUnibo-DTKA Authority: Bulletin Created.");

	   encoded_message = el_encode_blocks(p->information_block_number,p->information_block_number+p->total_block_number,bulletin,length);
	   bulletin_hash = (unsigned char*)malloc(sizeof(char)*(SHA256_DIGEST_LENGTH*2+1));
	   sl_hash_message_text((char*)bulletin,(char*)bulletin_hash,SHA256HASH);

	   length = (SHA256_DIGEST_LENGTH*2+1);
	   for(i=0; i<p->block_per_authority; i++)
	      length = length + sizeof(unsigned int)+sizeof(unsigned int)+encoded_message->block_size;

	   serialized_blocks = calloc(length,sizeof(unsigned char));
	   cursor = serialized_blocks;

	   for(auth_index=0; auth_index<p->number_of_authorities; auth_index++)
		   if(strncmp(p->authority_eid[auth_index],sending_bulletin_connection.local_eid.uri,strlen(p->authority_eid[auth_index]))==0)
			   break;

	   memcpy(cursor,bulletin_hash,(SHA256_DIGEST_LENGTH*2+1));
	   cursor = cursor + (SHA256_DIGEST_LENGTH*2+1);

	   for(i=0; i<p->block_per_authority; i++){
		  temp = get_next_block_index(auth_index+i,p->total_block_number-1);

		  temp = htonl(temp);
		  memcpy(cursor,&temp,sizeof(int));
	      cursor = cursor + sizeof(int);

	      temp = encoded_message->block_size;
	      temp = htonl(temp);
	      memcpy(cursor,&temp,sizeof(int));
	      cursor = cursor + sizeof(int);

          temp = get_next_block_index(auth_index+i,p->total_block_number);
	      memcpy(cursor,encoded_message->primary_blocks[temp],encoded_message->block_size);
	      cursor = cursor + encoded_message->block_size;

	      memcpy(&temp,serialized_blocks+(SHA256_DIGEST_LENGTH*2+1)+sizeof(int),sizeof(int));

	  }

	  for(i=0; i<p->number_of_authorities; i++){
		  url = calloc(127,sizeof(char));
		  strcpy(url,p->authority_eid[i]);
		  strcat(url,"/bulletin");
          cw_wrapper_send(&sending_bulletin_connection,serialized_blocks,length,url);
          free(url);
	  }

	  for(i=0; i<p->number_of_clients; i++){
		  url = calloc(127,sizeof(char));
		  strcpy(url,p->clients_eid[i]);
		  strcat(url,"/bulletin");
		  cw_wrapper_send(&sending_bulletin_connection,serialized_blocks,length,url);
		  free(url);
	  }

	  free(bulletin);
   }

   return (void*)0;
}

void *receive_consensus_thread_authority(){

	dtka_parameters *p;

    record_list *list;
    record_list *first;

    unsigned char *cursor;

    int i;
    int auth_index;
    int consensus;
    int data_length;

    p = &parameters;
    first = &rec_list;
    list = &rec_list;

    consensus = 1;

    for(;;){

       cw_wrapper_receive(&receive_consensus_connection);
	   fprintf(p->fp_log,"\nUnibo-DTKA Authority: Consensus Received from %s",receive_consensus_connection.bundle_source);
	   cursor = receive_consensus_connection.message;

	   for(auth_index=0; auth_index<p->number_of_authorities; auth_index++)
		   if(strncmp(p->authority_eid[auth_index],receive_consensus_connection.bundle_source,strlen(p->authority_eid[auth_index]))==0)
			  break;

       for(i=0; i<first->records; i++){
    	  memcpy(&data_length,receive_consensus_connection.message,sizeof(int));
    	  cursor = cursor+sizeof(int);
    	  cursor = cursor+data_length;
    	  list->record->acknowledged[auth_index] = cursor[auth_index];
    	  list = list->next;
    	  cursor = cursor+p->number_of_authorities;
       }

       list = first;
       fflush(stdout);

       consensus++;

       if(consensus == p->number_of_authorities){
    	  consensus = 1;
          publish_bulletin = 1;
       }

    }
	return (void*)0;
}

void *send_consensus_thread_authority(){

	dtka_parameters *p;
    unsigned char *serialized_consensus;
    char *temp;
    int consensus_length;

    int i;

    p = &parameters;

    sleep(p->bulletin_time);
    for(;;){
       consensus_length = serialize_record(NULL);
       serialized_consensus = calloc(consensus_length,sizeof(unsigned char));
       serialize_record(serialized_consensus);

       for(i=0; i<p->number_of_authorities; i++){
    	 if(i == find_my_index(&sending_consensus_connection,AUTHORITY_MODE,"/consensus"))
            continue;
          temp = calloc(127,sizeof(char));
          strcpy(temp,p->authority_eid[i]);
          strcpy(temp+strlen(temp),"/consensus");
          cw_wrapper_send(&sending_consensus_connection,serialized_consensus,consensus_length,temp);
          free(temp);
       }
       receive_status = 1;
       sleep(p->bulletin_time+p->grace_time);
    }

	return (void*)0;
}

void *receiving_key_thread_authority(){

	unsigned short EID_length;
	unsigned char *EID;
	unsigned int effective_time;
	unsigned int assertion_time;
	unsigned int data_length;
	unsigned char *data;

	int res;
    int i;

	dtka_parameters *p;
	record_list *list;
	record_list *first;
	record_list *current;

	p = &parameters;
    list = &rec_list;
    first = &rec_list;
    current = &rec_list;

	for(;;){
	   if(receive_status == 0)
		  continue;
       cw_wrapper_receive(&receiving_key_connection);
       fprintf(p->fp_log,"\nUnibo-DTKA Authority: Key Received from %s",receiving_key_connection.bundle_source);
       EID = calloc(127,sizeof(char));
       if(EID == NULL)
    	  unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

       data = calloc(receiving_key_connection.message_length,sizeof(char));
       if(data == NULL)
    	  unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

       res = deserialize_message(receiving_key_connection.message,&EID_length,EID,&effective_time,&assertion_time,&data_length,data);

       current = list;

       for(;;){
    	   if(list->next == NULL){
    		   list = first;
    		   break;
    	   }
    	   res = 0;
    	   for(i=0; i<p->number_of_authorities; i++)
    		   if(strncmp(p->authority_eid[i],receiving_key_connection.bundle_source,strlen(p->authority_eid[i]))==0){
    			  res = 1;
    			  break;
    		   }
    	   if(res == 0){
    		  list = first;
    		  continue;
    	   }
    	   else{
    		  res = memcmp(data,list->record->data_value,data_length);
    		  if(res == 0){
    		     list = first;
    		   	 continue;
    		  }
    	   }
    	   list = list->next;
       }

       list = current;

       first->records++;

       list->record = calloc(1,sizeof(dtka_record));
       if(list->record == NULL)
    	  unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

       list->record->EID = calloc(EID_length,sizeof(unsigned char));
       if(list->record->EID == NULL)
    	  unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR) ;

       list->record->acknowledged = calloc(p->number_of_authorities,sizeof(char));
       if(list->record->acknowledged == NULL)
    	  unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

       for(i=0; i<p->number_of_authorities; i++)
    	   if(strncmp(p->authority_eid[i],receiving_key_connection.local_eid.uri,strlen(p->authority_eid[i]))==0)
    	      break;

       list->record->acknowledged[i] = res;

       list->record->data_value = calloc(data_length,sizeof(unsigned char));
       if(list->record->data_value == NULL)
    	  unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

       memcpy(list->record->EID,EID,EID_length);
       memcpy(&(list->record->assertion_time),&assertion_time,sizeof(unsigned int));
       memcpy(&(list->record->effective_time),&effective_time,sizeof(unsigned int));
       list->record->data_length = data_length;
       memcpy(list->record->data_value,data,data_length);

       list->next = calloc(1,sizeof(dtka_record));
       if(list->next == NULL)
    	  unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

       list = list->next;

       if(res == 1){
    	  fprintf(p->fp_log,"\nUnibo-DTKA Authority: Key Asserted!");
    	  fflush(p->fp_log);
       }else{
    	   fprintf(p->fp_log,"\nUnibo-DTKA Authority: Consensus Rejected!");
    	   fflush(p->fp_log);
       }
	}

	return (void*)0;
}

void *console_thread(){

	dtka_parameters *p;
	record_list *list;
	record_list *first;

	char *new_eid;
	char *new_public_key;

	char **eids;
	char **key_files;

	int choice;
	int i;
	int j;

	int *authority_status;

	p = &parameters;
	list = &rec_list;

	for(;;){

	   printf("\nUnibo-DTKA Authority Console: ");
	   printf("\n---------------");
	   printf("\n\t1   ---   Show pending record list");
	   printf("\n\t2   ---   Show authority list");
	   printf("\n\t3   ---   Show client node list");
	   printf("\n\t4   ---   Set active an authority");
	   printf("\n\t5   ---   Set unavailable an authority");
	   printf("\n\t6   ---   Add a node to list");
	   printf("\n\t7   ---   Add an authority to list");
	   printf("\n\t8   ---   Remove a node from list");
	   printf("\n\t9   ---   Remove an authority to list");
	   printf("\n\t0   ---   Revoke a key record");
	   printf("\n\tAny ---   Show this menu again.");
	   printf("\n---------------\n");
	   printf("\nPress CTRL+C for exit");
	   printf("\n---------------\n");
	   printf("-> ");
       fflush(stdout);

	   scanf("%d",&choice);
	   clear_stdin();

	   if(choice == 1){
		  printf("\nRecord List:");
		  printf("\n---------------\n");
		  fflush(stdout);
		  first = list;
		  choice = 0;
		  for(;;){
			 if(list->record == NULL && list->next == NULL)
				break;
			 printf("\nRECORD %d\nFrom %s\nEffective time: %d \nAssertion time: %d\n",choice++,list->record->EID,list->record->effective_time,list->record->assertion_time);
			 if(strcmp(list->record->acknowledged,"[revoke]")==0)
				printf("\nTHIS KEY RECORD HAS BEEN REVOKED");
			 printf("\n--------------\n");
			 for(i=0; i < list->record->data_length; i++)
			     printf("%c",list->record->data_value[i]);
			 printf("\n---------------\n");
			 fflush(stdout);
			 if(list->next == NULL)
				break;
			 else
			    list = list->next;
		  }
		  list = first;
		  printf("\nPress return key. \n");
		  fflush(stdout);
		  getchar();
		  continue;
	   }
	   if(choice == 2){
		  printf("\nAuthorities:");
		  printf("\n---------------\n");
	      for(i=0; i<p->number_of_authorities; i++)
	    	  printf("\n\t%d\t%s\t%d",i,p->authority_eid[i],p->authority_status[i]);
	      printf("\n---------------\n");
	      printf("\nPress return key. \n");
		  fflush(stdout);
		  getchar();
		  continue;
	   }
	   if(choice == 3){
		  printf("\nClients:");
		  printf("\n---------------\n");
		  if(p->number_of_clients == 0)
			 printf("\nThere is no client.");
		  for(i=0; i<p->number_of_clients; i++)
			  printf("\n\t%d\t%s",i,p->clients_eid[i]);
		  printf("\n---------------\n");
		  printf("\nPress return key. \n");
		  fflush(stdout);
		  getchar();
		  continue;
	   }
	   if(choice == 4){
		  printf("\nAuthorities:");
		  printf("\n---------------\n");
     	  for(i=0; i<p->number_of_authorities; i++)
		   	  printf("\n\t%d\t%s\t%d",i,p->authority_eid[i],p->authority_status[i]);
		  printf("\n---------------\n");
     	  for(;;){
    		 printf("Please select the index number of the authority to set active:");
    		 printf("\n-> ");
    		 fflush(stdout);
			 scanf("%d",&choice);
			 clear_stdin();
			 if(choice < 0 || choice >= p->number_of_authorities){
				 printf("\nThe index must be between 0 and %d",p->number_of_authorities-1);
				 continue;
			 }else{
				 p->authority_status[choice] = 1;
				 break;
			 }
		  }
     	  printf("\nPress return key. \n");
		  fflush(stdout);
		  getchar();
		  continue;
	   }
	   if(choice == 5){
		  printf("\nAuthorities:");
		  printf("\n---------------\n");
		  for(i=0; i<p->number_of_authorities; i++)
		   	  printf("\n\t%d\t%s\t%d",i,p->authority_eid[i],p->authority_status[i]);
		  printf("\n---------------\n");
     	  for(;;){
    		 printf("Please select the index number of the authority to set unavailable:");
    		 printf("\n-> ");
    		 fflush(stdout);
			 scanf("%d",&choice);
			 clear_stdin();
			 if(choice < 0 || choice >= p->number_of_authorities){
				 printf("\nThe index must be between 0 and %d",p->number_of_authorities-1);
				 continue;
			 }else{
				 p->authority_status[choice] = 0;
				 break;
			 }
		  }
     	  printf("\nPress return key. \n");
		  fflush(stdout);
		  getchar();
		  continue;
	   }
	   if(choice == 6){
		  printf("\nPlease enter the EID of the new node: ");
		  printf("\n-> ");
		  fflush(stdout);

		  new_eid = calloc(127,sizeof(char));
		  if(new_eid==NULL)
			 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

		  scanf("%s",new_eid);
		  clear_stdin();

		  printf("\nPlease enter the public key file of the new node: ");
		  printf("\n-> ");
		  fflush(stdout);

		  new_public_key = calloc(255,sizeof(char));
		  if(new_public_key == NULL)
			 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

		  scanf("%s",new_public_key);
		  clear_stdin();

		  p->number_of_clients++;

		  eids = calloc(p->number_of_clients,sizeof(char*));
		  if(eids == NULL)
			 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

		  key_files = calloc(p->number_of_clients,sizeof(char*));
		  if(key_files == NULL)
			 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

		  for(i=0; i<p->number_of_clients-1; i++){
              eids[i] = calloc(127,sizeof(char));
              if(eids[i] == NULL)
            	 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

              key_files[i] = calloc(255,sizeof(char));
              if(key_files[i] == NULL)
            	 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

              strcpy(eids[i],p->clients_eid[i]);
              strcpy(key_files[i],p->clients_key_file[i]);
              free(p->clients_eid[i]);
              free(p->clients_key_file[i]);
		  }
		  free(p->clients_eid);
		  free(p->clients_key_file);
		  eids[i] = calloc(127,sizeof(char));
		  if(eids[i] == NULL)
			 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

		  key_files[i] = calloc(255,sizeof(char));
		  if(key_files[i] == NULL)
			 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

		  strcpy(eids[i],new_eid);
		  strcpy(key_files[i],new_public_key);
		  free(new_eid);
		  free(new_public_key);

		  p->clients_eid = eids;
		  p->clients_key_file = key_files;
		  printf("\nPress return key. \n");
		  fflush(stdout);
		  getchar();
		  continue;
	   }
	   if(choice == 7){
		  printf("\nPlease enter the EID of the new authority: ");
		  printf("\n-> ");
		  fflush(stdout);

		  new_eid = calloc(127,sizeof(char));
		  if(new_eid == NULL)
			 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

		  scanf("%s",new_eid);
		  clear_stdin();

		  printf("\nPlease enter the public key file of the new authority: ");
		  printf("\n-> ");
		  fflush(stdout);

		  new_public_key = calloc(255,sizeof(char));
		  if(new_public_key == NULL)
			 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

		  scanf("%s",new_public_key);
		  clear_stdin();

		  p->number_of_authorities++;

		  eids = calloc(p->number_of_authorities,sizeof(char*));
		  if(eids == NULL)
			 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

		  key_files = calloc(p->number_of_authorities,sizeof(char*));
		  if(key_files == NULL)
			 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

		  authority_status = calloc(p->number_of_authorities,sizeof(int));
		  if(authority_status == NULL)
			 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

		  for(i=0; i<p->number_of_authorities-1; i++){
			  authority_status[i] = p->authority_status[i];

              eids[i] = calloc(127,sizeof(char));
              if(eids[i] == NULL)
            	 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

              key_files[i] = calloc(255,sizeof(char));
              if(key_files[i] == NULL)
            	 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

              strcpy(eids[i],p->authority_eid[i]);
              strcpy(key_files[i],p->authority_key_file[i]);
              free(p->authority_eid[i]);
              free(p->authority_key_file[i]);
		  }
		  free(p->authority_eid);
		  free(p->authority_key_file);
		  free(p->authority_status);

		  eids[i] = calloc(127,sizeof(char));
		  if(eids[i] == NULL)
			 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

		  key_files[i] = calloc(255,sizeof(char));
		  if(key_files[i] == NULL)
			 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

		  authority_status[i] = 0;

		  strcpy(eids[i],new_eid);
		  strcpy(key_files[i],new_public_key);
		  free(new_eid);
		  free(new_public_key);
		  p->authority_eid = eids;
		  p->authority_key_file = key_files;
		  p->authority_status = authority_status;

		  printf("\nPress return key. \n");
		  fflush(stdout);
		  getchar();
		  continue;
	   }

	   if(choice == 8){
	      printf("\nClients:");
		  printf("\n---------------\n");
		  if(p->number_of_clients == 0){
		     printf("\nThere is no client.");
		     printf("\n---------------\n");
		     continue;
		  }
		  for(i=0; i<p->number_of_clients; i++)
		      printf("\n\t%d\t%s",i,p->clients_eid[i]);

		  printf("\n---------------\n");
		  printf("\nPlease enter the index of the node to remove.");
		  printf("\n-> ");
		  fflush(stdout);

          scanf("%d",&choice);
          clear_stdin();

          if(choice < 0 || choice > p->number_of_clients-1)
        	  printf("\nThe index must be between 0 and %d",p->number_of_clients-1);
          else{

        	  eids = calloc(p->number_of_clients-1,sizeof(char*));
              if(eids == NULL)
            	 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

              key_files = calloc(p->number_of_clients-1,sizeof(char*));
              if(key_files == NULL)
            	 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

              for(i=0,j=0; i<p->number_of_clients; i++){
                  if(i == choice)
                	 continue;
                  else{
                	 eids[j] = calloc(127,sizeof(char));
                	 if(eids[j] == NULL)
                		unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);
                	 key_files[j] = calloc(255,sizeof(char));
                	 if(key_files[j] == NULL)
                		unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);
                	 strcpy(eids[j],p->clients_eid[i]);
                	 strcpy(key_files[j],p->clients_key_file[i]);
                	 j++;
                  }
              }

              free(p->clients_eid);
              free(p->clients_key_file);
              p->clients_eid = eids;
              p->clients_key_file = key_files;
              p->number_of_clients--;
          }

	      printf("\nPress return key. \n");
	      fflush(stdout);
	      getchar();
	      continue;
	   }

	   if(choice == 9){
	      printf("\nAuthorities:");
		  printf("\n---------------\n");
		  if(p->number_of_authorities == 0){
		     printf("\nThere is no authorities.");
		     printf("\n---------------\n");
		     continue;
		  }
		  for(i=0; i<p->number_of_authorities; i++)
		      printf("\n\t%d\t%s",i,p->authority_eid[i]);

		  printf("\n---------------\n");
		  printf("\nPlease enter the index of the authority to remove.");
		  printf("\n-> ");
		  fflush(stdout);

          scanf("%d",&choice);
          clear_stdin();

          if(choice < 0 || choice > p->number_of_authorities-1){
        	  printf("\nThe index must be between 0 and %d",p->number_of_authorities-1);
        	  continue;
          }else{

        	  eids = calloc(p->number_of_authorities-1,sizeof(char*));
              if(eids == NULL)
            	 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

              key_files = calloc(p->number_of_authorities-1,sizeof(char*));
              if(key_files == NULL)
            	 unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);

              authority_status = calloc(p->number_of_authorities-1,sizeof(int));

              for(i=0,j=0; i<p->number_of_authorities; i++){
                  if(i == choice)
                	 continue;
                  else{
                	 eids[j] = calloc(127,sizeof(char));
                	 if(eids[j] == NULL)
                		unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);
                	 key_files[j] = calloc(255,sizeof(char));
                	 if(key_files[j] == NULL)
                		unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);
                	 strcpy(eids[j],p->authority_eid[i]);
                	 strcpy(key_files[j],p->authority_key_file[i]);
                	 authority_status[j] = p->authority_status[i];
                	 j++;
                  }
              }

              free(p->authority_eid);
              free(p->authority_key_file);
              p->authority_eid = eids;
              p->authority_key_file = key_files;
              p->authority_status = authority_status;
              p->number_of_authorities--;
          }

	      printf("\nPress return key. \n");
	      fflush(stdout);
	      getchar();
	      continue;
	   }

	   if(choice == 0){
		  printf("\nRecord List:");
		  printf("\n---------------\n");
		  fflush(stdout);
		  first = list;
		  choice = 0;
		  for(;;){
			 if(list->record == NULL && list->next == NULL)
				break;
			 printf("\nRECORD %d\nFrom: %s\nEffective time: %d \nAssertion time: %d\n",choice++,list->record->EID,list->record->effective_time,list->record->assertion_time);
			 printf("\n--------------\n");
			 for(i=0; i < list->record->data_length; i++)
			     printf("%c",list->record->data_value[i]);
			 printf("\n---------------\n");
			 fflush(stdout);
			 if(list->next == NULL)
				break;
			 else
			    list = list->next;
		  }
		  list = first;
		  if(list->records == 0){
			 printf("\nThere are no records to revoke.");
		  }else{
		     printf("\nPlease enter the index of the record to revoke.");
		     for(;;){
		        scanf("%d",&choice);
		        clear_stdin();
		        if(choice < 0 || choice > list->records-1){
		    	   printf("\nThe index must be between 0 and %d",list->records-1);
		    	   continue;
		        }
		        for(i=0;i<list->records; i++){
		    	   if(i==choice){
		    	      free(list->record->acknowledged);
		    		  list->record->acknowledged = calloc(strlen("[revoke]"),sizeof(char));
		    		  if(list->record->acknowledged == NULL)
		    		     unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_NOT_ENOUGH_MEMORY_ERROR);
		    		  strcpy(list->record->acknowledged,"[revoke]");
		    		  break;
		    	   }else
		    	      list = list->next;
		        }
		        break;
		     }
		     list = first;
		  }
		  printf("\nPress return key. \n");
		  fflush(stdout);
		  getchar();
		  continue;
	   }
	}
	return (void*)0;
}

void run_authority_mode(){

	dtka_parameters *p;
	p = &parameters;
	al_bp_bundle_priority_t priority;
	int res;

	pthread_t receiving_key_thread;
	pthread_t sending_key_thread;

	pthread_t menu_console_thread;

	pthread_t sending_consensus_thread;
	pthread_t receiving_consensus_thread;

	pthread_t sending_bulletin_thread;
	pthread_t receiving_bulletin_thread;

	//pthread_t update_key_thread;

	receive_status = 1;

	fprintf(p->fp_log,"\nUnibo-DTKA Authority: Starting the receiving thread....");
	fflush(p->fp_log);

	fprintf(p->fp_log,"\nPerforming connection...");
	fflush(p->fp_log);

	if(strcmp(p->bundle_priority,"NORMAL")==0)
	   priority.priority = BP_PRIORITY_NORMAL;
	if(strcmp(p->bundle_priority,"BULK")==0)
	   priority.priority = BP_PRIORITY_BULK;
	if(strcmp(p->bundle_priority,"EXPEDITED")==0)
	   priority.priority = BP_PRIORITY_EXPEDITED;

	fprintf(p->fp_log,"\nInitialization of the connection parameters for the key receiver thread....");
	fflush(p->fp_log);

	cw_wrapper_init(&sending_key_connection,BP_PAYLOAD_MEM,'N',-1,priority,30,"dtka","4000");
    cw_wrapper_init(&receiving_key_connection, BP_PAYLOAD_MEM, 'N', -1, priority, 30,"dtka","4000");
    cw_wrapper_init(&sending_consensus_connection, BP_PAYLOAD_MEM, 'N', -1, priority, 30,"consensus","4001");
    cw_wrapper_init(&receive_consensus_connection, BP_PAYLOAD_MEM, 'N', -1, priority, 30,"consensus","4001");
    cw_wrapper_init(&sending_bulletin_connection,BP_PAYLOAD_MEM, 'N', -1,priority,30,"bulletin","4002");
    cw_wrapper_init(&receive_bulletin_connection,BP_PAYLOAD_MEM, 'N', -1,priority,30,"bulletin","4002");

    fprintf(p->fp_log,"\nRegistration to the bundle daemon....");
    fflush(p->fp_log);

    cw_register_to_dtn_daemon(&sending_key_connection);
    cw_register_to_dtn_daemon(&receiving_key_connection);
    cw_register_to_dtn_daemon(&sending_consensus_connection);
    cw_register_to_dtn_daemon(&receive_consensus_connection);
    cw_register_to_dtn_daemon(&sending_bulletin_connection);
    cw_register_to_dtn_daemon(&receive_bulletin_connection);

    fprintf(p->fp_log,"\nLocal EID for Keys = %s", receiving_key_connection.local_eid.uri);
    fprintf(p->fp_log,"\nLocal EID for Consensus = %s", sending_consensus_connection.local_eid.uri);
    fflush(p->fp_log);

    res = pthread_create(&sending_key_thread,NULL,&sending_key_thread_client,NULL);
    if(res < 0)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_PTHREAD_ERROR);

    fprintf(p->fp_log,"\nUnibo-DTKA Authority: Sending key thread created.");
    fflush(p->fp_log);

	res = pthread_create(&receiving_key_thread,NULL,&receiving_key_thread_authority,NULL);
	if(res < 0)
	   unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_PTHREAD_ERROR);

	fprintf(p->fp_log,"\nUnibo-DTKA Authority: Receiving key thread created.");
	fflush(p->fp_log);

	res = pthread_create(&receiving_consensus_thread,NULL,&receive_consensus_thread_authority,NULL);
	if(res < 0)
	   unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_PTHREAD_ERROR);

	fprintf(p->fp_log,"\nUnibo-DTKA Authority: Receiving consensus thread created.");
	fflush(p->fp_log);

	res = pthread_create(&sending_consensus_thread,NULL,&send_consensus_thread_authority,NULL);
	if(res < 0)
	   unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_PTHREAD_ERROR);

	fprintf(p->fp_log,"\nUnibo-DTKA Authority: Sending consensus thread created.");
	fflush(p->fp_log);

    res = pthread_create(&sending_bulletin_thread,NULL,&publish_bulletin_thread_authority,NULL);
    if(res < 0)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_PTHREAD_ERROR);

	fprintf(p->fp_log,"\nUnibo-DTKA Authority: Sending bulletin thread created.");
	fflush(p->fp_log);

	res = pthread_create(&receiving_bulletin_thread,NULL,&receive_bulletin,NULL);
	if(res < 0)
	   unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_PTHREAD_ERROR);

	fprintf(p->fp_log,"\nUnibo-DTKA Authority: Receiving bulletin thread created.");
	fflush(p->fp_log);

	//res = pthread_create(&update_key_thread,NULL,&update_keys,NULL);
	//if(res < 0)
	//   unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_PTHREAD_ERROR);

	//fprintf(p->fp,"\nUnibo-DTKA Authority: Updating key thread created.");
	//fflush(p->fp);

	res = pthread_create(&menu_console_thread,NULL,&console_thread,NULL);
	if(res < 0)
	   unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_PTHREAD_ERROR);

	fprintf(p->fp_log,"\nUnibo-DTKA Authority: Console thread created.");
    fflush(p->fp_log);

	res = pthread_join(receiving_key_thread,NULL);
	if(res < 0)
	   unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_PTHREAD_ERROR);

	res = pthread_join(menu_console_thread,NULL);
	if(res < 0)
	   unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_PTHREAD_ERROR);

	res = pthread_join(sending_key_thread,NULL);
	if(res < 0)
	   unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_PTHREAD_ERROR);

	//res = pthread_join(update_key_thread,NULL);
	//if(res < 0)
	//   unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_PTHREAD_ERROR);


}

