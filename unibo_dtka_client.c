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
#include "unibo_dtka_functions.h"
#include "unibo_dtka_types.h"

extern struct dtka_parameters parameters;
connection_wrapper_t sending_key_connection;
connection_wrapper_t receive_bulletin_connection;

void run_client_mode(){

	dtka_parameters *p;
	p = &parameters;
    int res;

	pthread_t sending_key_thread;
	//pthread_t update_keys_thread;
    pthread_t receiving_bulletin_thread;

	fprintf(p->fp_log,"\nUnibo-DTKA Client: Starting the sending thread....");
	fflush(p->fp_log);

	al_bp_bundle_priority_t priority;

	fprintf(p->fp_log,"\nPerforming connection...");

	if(strcmp(p->bundle_priority,"NORMAL")==0)
	   priority.priority = BP_PRIORITY_NORMAL;
	if(strcmp(p->bundle_priority,"BULK")==0)
	   priority.priority = BP_PRIORITY_BULK;
	if(strcmp(p->bundle_priority,"EXPEDITED")==0)
	   priority.priority = BP_PRIORITY_EXPEDITED;

	fprintf(p->fp_log,"\nInitialization of the connection parameters....");

    wrapper_init(&sending_key_connection, BP_PAYLOAD_MEM, 'N', p->receive_time, priority, 1000,"dtka","4000");
    wrapper_init(&receive_bulletin_connection,BP_PAYLOAD_MEM, 'N', p->receive_time, priority, 1000,"bulletin","4002");

    fprintf(p->fp_log,"\nRegistration to the bundle daemon....");

    register_to_dtn_daemon(&sending_key_connection);
    register_to_dtn_daemon(&receive_bulletin_connection);

    fprintf(p->fp_log,"\nLocal EID = %s\n", sending_key_connection.local_eid.uri);

	res = pthread_create(&sending_key_thread,NULL,&sending_key_thread_client,NULL);
	if(res < 0)
	   unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_PTHREAD_ERROR);

	//res = pthread_create(&update_keys_thread,NULL,&update_keys,NULL);
	//if(res < 0)
	//   unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_PTHREAD_ERROR);

    res = pthread_create(&receiving_bulletin_thread,NULL,&receive_bulletin,NULL);
    if(res < 0)
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_PTHREAD_ERROR);

	fprintf(p->fp_log,"\nUnibo-DTKA Client: Sending thread created.");

	res = pthread_join(sending_key_thread,NULL);
	if(res < 0)
	   unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_PTHREAD_ERROR);

	//pthread_join(update_keys_thread,NULL);
	res = pthread_join(receiving_bulletin_thread,NULL);
	if(res < 0)
	   unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_PTHREAD_ERROR);

}

