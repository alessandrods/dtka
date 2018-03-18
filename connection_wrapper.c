/********************************************************
 **  Authors: Alessandro Di Stanislao, alessand.distanislao@studio.unibo.it
 **           Carlo Caini (project supervisor), carlo.caini@unibo.it
 **
 **
 **  Copyright (c) 2018, Alma Mater Studiorum, University of Bologna
 **  All rights reserved.
 ********************************************************/

#include "connection_wrapper.h"

void cw_wrapper_init(connection_wrapper_t *connection, al_bp_bundle_payload_location_t pl_location, char eid_format, int receive_time, al_bp_bundle_priority_t bundle_priority, al_bp_timeval_t bundle_expiration,char *ep_string,char *ep_num_service){
   
    connection->pl_location = pl_location; 
    connection->handle = NULL; // handle is initializated when the connection is open. 
    connection->eid_format_forced = eid_format;  //the format of the EID: IPN type or DTN type.
    connection->bp_implementation = al_bp_get_implementation(); // Implementation of the bundle protocol.
    connection->receive_time = receive_time; // Time for waiting for receive bundle.
    connection->ipn_local_num = 1;
    connection->bundle_priority = bundle_priority; // Priority of the bundle 
    connection->bundle_expiration = bundle_expiration;  // Time to live for the bundle.
    connection->ep_string = malloc(sizeof(char)*strlen(ep_string));
    connection->ep_num_service = malloc(sizeof(char)*strlen(ep_num_service));
    strcpy(connection->ep_string,ep_string);
    strcpy(connection->ep_num_service,ep_num_service);
}

void cw_register_to_dtn_daemon(connection_wrapper_t* connection){

    al_bp_error_t error; // For error handling of the abstraction layer. 
    char temp[256]; // Temporary buffer. 
    connection->bp_implementation = al_bp_get_implementation();  // For discover the implementation of bundle protocol. 

    if(connection->bp_implementation == BP_NONE){
#ifdef DEBUG
       printf("\nNo bundle daemon is running or is detected.\n");  // Unknow implementation.
#endif
       exit(9);
    }
#ifdef DEBUG
    if(connection->bp_implementation == BP_ION)
       printf("\nION daemon is detected");
 
    if(connection->bp_implementation == BP_IBR)
       printf("\nIBR daemon is detected");

    if(connection->bp_implementation == BP_DTN)
       printf("\nDTN2 daemon is detected");
    
    printf("\nTrying to connect to bundle daemon...");
    printf("\nOpening bundle protocol handler");
#endif
    error = al_bp_open(&(connection->handle)); // Opening the connection handle.
    cw_wrapper_error_handler(error);
        
    if(connection->bp_implementation == BP_ION && (connection->eid_format_forced == 'N' || connection->eid_format_forced == 'I')) // Use ION implementation with standard eid scheme.
       error = al_bp_build_local_eid(connection->handle, &(connection->local_eid), connection->ep_string, CBHE_SCHEME);
    else if(connection->bp_implementation == BP_DTN && (connection->eid_format_forced == 'N' || connection->eid_format_forced == 'D')) // Use DTN2 implementation with standard eid scheme.
       error = al_bp_build_local_eid(connection->handle, &(connection->local_eid), connection->ep_string, DTN_SCHEME);
    else if(connection->bp_implementation == BP_IBR && (connection->eid_format_forced == 'N' || connection->eid_format_forced == 'D')) // Use IBR-DTN implementation with standard eid scheme.
       error = al_bp_build_local_eid(connection->handle, &(connection->local_eid), connection->ep_string, DTN_SCHEME);
    else if(connection->bp_implementation == BP_ION && connection->eid_format_forced == 'D') // Use ION implementation with forced DTN scheme.
       error = al_bp_build_local_eid(connection->handle, &(connection->local_eid), connection->ep_string, DTN_SCHEME);
    else if(connection->bp_implementation == BP_DTN && connection->eid_format_forced == 'I'){ // Use DTN2 implementation with forced IPN scheme.
       sprintf(temp, "%d.%s", connection->ipn_local_num, SERV_EP_NUM_SERVICE); //in this case the api al_bp_build_local_eid() wants ipn_local_number.service_number
       error = al_bp_build_local_eid(connection->handle, &(connection->local_eid), temp, CBHE_SCHEME);
    } else if(connection->bp_implementation == BP_IBR && connection->eid_format_forced == 'I') // Use IBR-DTN implementation with forced IPN scheme.
       error = al_bp_build_local_eid(connection->handle, &(connection->local_eid), connection->ep_num_service, CBHE_SCHEME);

    cw_wrapper_error_handler(error);

#ifdef DEBUG
    printf("\nLocal EID = %s\n", connection->local_eid.uri);  //Show the local eid of the node.

    printf("\nRegistering to local daemon...");
#endif
    memset(&(connection->reginfo), 0, sizeof(connection->reginfo));
    al_bp_copy_eid(&(connection->reginfo.endpoint), &(connection->local_eid));
 
    connection->reginfo.flags = BP_REG_DEFER;
 
    connection->reginfo.regid = BP_REGID_NONE;
 
    connection->reginfo.expiration = 0;

    error = al_bp_register(&(connection->handle), &(connection->reginfo), &(connection->reg_id));  // Registration of the bundle protocol.
 
    cw_wrapper_error_handler(error);
#ifdef DEBUG
    printf("\nRegistration successfull.");
#endif

}

void cw_wrapper_send(connection_wrapper_t *connection,unsigned char *message,int message_length,char *uri){

    al_bp_error_t error;
    al_bp_bundle_object_t bundle_object;
    al_bp_endpoint_id_t e_destination;        
    al_bp_timestamp_t ts;
    struct timeval now;

    gettimeofday(&now,NULL);
    ts.secs = now.tv_sec;
    ts.seqno = 0;

    error = al_bp_bundle_create(&bundle_object);
    cw_wrapper_error_handler(error);
   
    error = al_bp_bundle_set_payload_location(&bundle_object, connection->pl_location);
    cw_wrapper_error_handler(error);

    error = al_bp_bundle_set_payload_mem(&bundle_object, (char*)message, message_length);
    cw_wrapper_error_handler(error);

    error = al_bp_parse_eid_string(&(connection->local_eid),connection->local_eid.uri);
    cw_wrapper_error_handler(error);

    error = al_bp_bundle_set_source(&bundle_object, connection->local_eid);
    cw_wrapper_error_handler(error);

    error = al_bp_parse_eid_string(&e_destination,uri);
    cw_wrapper_error_handler(error);

    error = al_bp_bundle_set_dest(&bundle_object, e_destination);
    cw_wrapper_error_handler(error);

    error = al_bp_bundle_set_replyto(&bundle_object, connection->local_eid);
    cw_wrapper_error_handler(error);

    error = al_bp_bundle_set_priority(&bundle_object, connection->bundle_priority);
    cw_wrapper_error_handler(error);

    bundle_object.spec->priority.ordinal = 0;
    bundle_object.spec->critical = 0;
    bundle_object.spec->flow_label = 0;
    bundle_object.spec->unreliable = 0;

    error = al_bp_bundle_set_creation_timestamp(&bundle_object, ts);

    cw_wrapper_error_handler(error);

    error = al_bp_bundle_set_expiration(&bundle_object, connection->bundle_expiration);
    cw_wrapper_error_handler(error);

    error = al_bp_bundle_set_delivery_opts(&bundle_object, (al_bp_bundle_delivery_opts_t)0);
    cw_wrapper_error_handler(error);
    
    error = al_bp_bundle_send(connection->handle, connection->reg_id, &bundle_object);
    cw_wrapper_error_handler(error);

    error = al_bp_bundle_free(&bundle_object);
    cw_wrapper_error_handler(error);

}

void cw_wrapper_receive(connection_wrapper_t *connection){

    al_bp_error_t error; // For error handling of the abstraction layer. 
    al_bp_bundle_object_t bundle_object;

#ifdef DEBUG
    printf("\nWaiting for bundles...\n");
    fflush(stdout);   // al_bp_bundle_receive in a synchronous and blocking function so we need to flush the stdout buffer. 
#endif

    error = al_bp_bundle_create(&bundle_object);  //Bundle object is used for sending and receiving bundles.
    cw_wrapper_error_handler(error);
    error = al_bp_bundle_receive(connection->handle, bundle_object, connection->pl_location, connection->receive_time); // Receive bundles.

    if(error == BP_ETIMEOUT){
#ifdef DEBUG
       printf("\nTime out receiving bundle. \n");
#endif
       al_bp_bundle_free(&bundle_object);
       return;
    }
    if(error == BP_ERECVINT){
#ifdef DEBUG
       printf("\nApplication interrupted. \n");
#endif
       al_bp_bundle_free(&bundle_object);
       return;
    }
    if(error == BP_SUCCESS){

#ifdef DEBUG
       printf("\nReceving bundle from %s",bundle_object.spec->source.uri);
       printf("\nTimestamp: %d",bundle_object.spec->creation_ts.secs);
#endif
       connection->message = calloc(bundle_object.payload->buf.buf_len,sizeof(char));
       if(connection->message == NULL){
#ifdef DEBUG
          printf("\nNot enough memory.\n");
#endif
          exit(7);
       }
       connection->message_length = bundle_object.payload->buf.buf_len;

       memcpy(connection->message,bundle_object.payload->buf.buf_val,bundle_object.payload->buf.buf_len);
     
       connection->bundle_source = calloc(strlen(bundle_object.spec->source.uri),sizeof(char));
       if(connection->message == NULL){
#ifdef DEBUG
          printf("\nNot enough memory.\n");
#endif
          exit(7);
       }
       strcpy(connection->bundle_source,bundle_object.spec->source.uri);

       al_bp_bundle_free(&bundle_object);

    }
    else{
       fflush(stdout);
       fprintf(stderr, "[BP error] in opening bp handle: %s\n", al_bp_strerror(error));
       al_bp_bundle_free(&bundle_object);
       exit(10);       
    }
    
}

void cw_wrapper_close(connection_wrapper_t* connection){

    al_bp_error_t error;

#ifdef DEBUG
    printf("\nClosing connection....");
#endif

    error = al_bp_close(connection->handle);

    cw_wrapper_error_handler(error);

    if(connection->bp_implementation == BP_ION){
#ifdef DEBUG
       printf("\nUnregistering to the bundle daemon...");
#endif
       error = al_bp_unregister(connection->handle, connection->reg_id, connection->local_eid);
       cw_wrapper_error_handler(error);
    }

#ifdef DEBUG
    printf("\nConnection closed successfully.\n");
#endif

}

void cw_wrapper_error_handler(al_bp_error_t error){

    if (error != BP_SUCCESS){
       fflush(stdout);
       fprintf(stderr, "[BP error] in opening bp handle: %s\n", al_bp_strerror(error));
       exit(10);
    }

}
