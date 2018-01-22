/********************************************************
 **  Authors: Alessandro Di Stanislao, alessand.distanislao@studio.unibo.it
 **           Carlo Caini (project supervisor), carlo.caini@unibo.it
 **
 **
 **  Copyright (c) 2017, Alma Mater Studiorum, University of Bologna
 **  All rights reserved.
 ********************************************************/

 /**
  * @file connection_wrapper.h
  * @author Alessandro Di Stanislao
  * @date Jannuary, 2017
  * @brief This file contains functions for the use of the Abstraction Layer API.
  *  
  */  
 
#ifndef CONNECTION_WRAPPER_H_
#define CONNECTION_WRAPPER_H_

#include <al_bp_api.h>
#include <al_bp_types.h>
#include <al_bp_version.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>

#define SERV_EP_STRING "dtka"
#define SERV_EP_NUM_SERVICE "4000"

struct connection_wrapper_t{
    al_bp_endpoint_id_t local_eid;
    al_bp_bundle_payload_location_t pl_location;
    al_bp_reg_id_t reg_id;
    al_bp_reg_info_t reginfo;
    al_bp_implementation_t bp_implementation;
    int receive_time;
    char eid_format_forced;
    int ipn_local_num;
    al_bp_bundle_priority_t bundle_priority;
    al_bp_timeval_t bundle_expiration;
    unsigned char *message;
    int message_length;
    char *bundle_source;
    al_bp_handle_t handle;
    char *ep_string;
    char *ep_num_service;
};

typedef struct connection_wrapper_t connection_wrapper_t;

/**
 * @name Connection Wrapper Init
 * @brief Initialize the connection parameters.
 * 
 * This function initialize the connection parameters for the DTN daemon.
 *
 * @param [al_bp_connection_t] Data structure containing the parameters for the bundle protocol.
 * @param [al_bp_bundle_payload_location_t] Specify where the payload data are stored.
 * @param [char] Format of the EID names. (Are allowed I for IPN namespace, D for DTN namespace and N for both).
 * @param [int] Wait time for receiving bundles. 
 * @param [al_bp_bundle_priority_t] Bundle priority.
 * @param [al_bp_timeval_t] Time for the bundle expiration.
 * @param [char*] End Point Service Name
 * @param [char*] End Point Service Number
 * 
 * @code 
 * Example usage: wrapper_init(connection, BP_PAYLOAD_MEM, 'N',-1,BP_PRIORITY_NORMAL,2000);
 * @endcode
 * 
 * @retval none.
 * 
*/

void wrapper_init(connection_wrapper_t *connection, al_bp_bundle_payload_location_t pl_location, char eid_format, int receive_time, al_bp_bundle_priority_t bundle_priority, al_bp_timeval_t bundle_expiration,char *ep_string,char *ep_num_service);

/**
 * @name Register to DTN daemon
 * @brief It registers the application to the local DTN daemon and handles the connection to the bundle layer. 
 *
 * @param [connection_wrapper_t] Data structure containing the parameters for the connection to the bundle protocol.
 * 
 * @code 
 * Example usage: register_to_dtn_daemon(connection);
 * @endcode
 * 
 * @retval none.
 * 
*/

void register_to_dtn_daemon(connection_wrapper_t *connection);

/**
 * @name Connection Wrapper Receive
 * @brief API for receiving data from a DTN node.
 *
 * @param [connection_wrapper_t] Data structure containing the parameters for the bundle protocol.
 * 
 * @code 
 * Example usage: wrapper_receive(connection);
 * @endcode
 * 
 * @retval none.
 * 
*/
void wrapper_receive(connection_wrapper_t *connection);

/**
 * @name Connection Wrapper Close
 * @brief API for closing the connection with the DTN daemon.
 *
 * @param [connection_wrapper_t] Data structure containing the parameters for the bundle protocol.
 * 
 * @code 
 * Example usage: wrapper_close(connection);
 * @endcode
 * 
 * @retval none.
 * 
*/

void wrapper_close(connection_wrapper_t *connection);

/**
 * @name Connection Wrapper Error Handler
 * @brief Handles the bundle layer error messages.
 *
 * @param [al_bp_error_t] Data structure containing the error returned from the bundle layer application.
 * 
 * @code 
 * Example usage: wrapper_error_handler(error);
 * @endcode
 * 
 * @retval none.
 * 
*/

void wrapper_error_handler(al_bp_error_t error);

/**
 * @name Connection Wrapper Send
 * @brief API for sending data to a DTN node
 *
 * @param [connection_wrapper_t] Data structure containing the parameters for the bundle protocol.
 * 
 * @code 
 * Example usage: wrapper_send(connection,message_buffer,message_length,authority_eid);
 * @endcode
 * 
 * @retval none.
 * 
*/

void wrapper_send(connection_wrapper_t *connection,unsigned char *message,int message_length, char *uri);

#endif
