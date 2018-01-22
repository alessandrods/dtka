/********************************************************
 **  Authors: Alessandro Di Stanislao, alessand.distanislao@studio.unibo.it
 **           Carlo Caini (project supervisor), carlo.caini@unibo.it
 **
 **
 **  Copyright (c) 2017, Alma Mater Studiorum, University of Bologna
 **  All rights reserved.
 ********************************************************/

#ifndef UNIBO_DTKA_CLIENT_H_
#define UNIBO_DTKA_CLIENT_H_

#include "unibo_dtka_includes.h"

void run_client_mode();

void *sending_thread_client();

void *receiving_thread_client();

#endif
