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
#include "unibo_dtka_functions.h"
#include "unibo_dtka_types.h"

// Main function of Unibo-DTKA Application. 

struct dtka_parameters parameters;
struct record_list rec_list;

int main(int argc,char** argv){

    char filename[255];
    int res;
    int i;

    //Parsing Parameters.
 
    //Parsing no Option.

    if(argc == 1){
       printf("\nUnibo-DTKA: Type --help for help page.\n");
       exit(UNIBO_DTKA_EXIT_STATUS_OK);
    }

    //Parsing single Option.
    if(argc == 2 && (strcmp(argv[1],"--help")==0 || strcmp(argv[1],"--cryptotest")==0 || strcmp(argv[1],"--erasuretest")==0 || strcmp(argv[1],"--client")==0 || strcmp(argv[1],"--authority")==0 || strcmp(argv[1],"--configure")==0 || strcmp(argv[1],"--connectiontest")==0 || strcmp(argv[1],"--keygen")==0 || strcmp(argv[1],"--receivekey")==0)){  //Options --help,
       if(strcmp(argv[1],"--help")==0){ // Printing help page.
          printf("\nUnibo-DTKA Help page..");
          printf("\nParameters...");
          printf("\n\t--help                             for this help page.");
          printf("\n\t--cryptotest                       for testing the cryptographic API of the application.");
          printf("\n\t--erasuretest                      for testing the erasure API of the application.");
          printf("\n\t--connectiontest                   for testing the connection API of the application.");
          printf("\n\t--configure [-f configfile]        for configure the application.");
          printf("\n\t--keygen [-f configfile]           for key pair generation.");
          printf("\n\t--authority [-f configfile]        for start the authority node application.");
	      printf("\n\t--client [-f configfile]           for start the client node application.");
	      printf("\n\t--sendkey -f keyfile authority-EID for sending a key to an authority node.");
	      printf("\n\t--sendkey -keygen authority-EID    for sending a new generated key to an authority node.");
	      printf("\n\t--receivekey                       for receiving a single key from a client node.");
          printf("\n");
          printf("\nReturn values to the Operative System");
          printf("\n\t0  all OK.");
          printf("\n\t1  Config file does not exist.");
          printf("\n\t2  Read Error in the config file.");
          printf("\n\t3  Syntax Error.");
          printf("\n\t4  Write error in the config file.");
          printf("\n\t5  Error in crypthographic library.");
          printf("\n\t6  Error in erasure library.");
          printf("\n\t7  Not enough memory.");
          printf("\n\t8  Key algorithm unknown.");
          printf("\n\t9  No bundle daemon is running or detected.");
          printf("\n\t10 Error opening Bundle Protocol Handle.");
          printf("\n\t11 Public or Private Key file not found.");
	      printf("\n\t12 Write error on RSA key file.");
          printf("\n\t13 Read error on RSA key.");
          printf("\n\t14 Error on verify RSA sign.");
	      printf("\n\t15 Error generating RSA key.");
	      printf("\n\t16 Connection Error.");
	      printf("\n\t17 Thread Error.");
          printf("\n");
          return 0;

       }
       //Option --receivekey, Receive a new key from a client node
       if(strcmp(argv[1],"--receivekey")==0){
          printf("\nUnibo-DTKA: Receiving a key from a client node.");
          receive_key();
       }

       //Option --cryptotest, Testing program API.
       if(strcmp(argv[1],"--cryptotest")==0){
          printf("\nUnibo-DTKA: Testing the application....");
          printf("\n\nUnibo-DTKA: Testing cryptographic openssl API");
          if(do_cryptographic_tests()==-1)
             return UNIBO_DTKA_EXIT_STATUS_CRYPTO_LIBRARY_ERROR;

          printf("\n\nUnibo-DTKA: All test is passed.\n");
             return UNIBO_DTKA_EXIT_STATUS_OK;
       }
       //Option --erasuretest, Testing program API
       if(strcmp(argv[1],"--erasuretest")==0){
          printf("\n\nUnibo-DTKA: Testing erasure code zfec API");
          if(do_erasure_test()==-1)
             return UNIBO_DTKA_EXIT_STATUS_ERASURE_LIBRARY_ERROR;

          printf("\n\nUnibo-DTKA: All test is passed.\n");
             return UNIBO_DTKA_EXIT_STATUS_OK;
       }
       // Option --client, launch Unibo-DTKA in client mode reading default config file.
       if(strcmp(argv[1],"--client")==0){
          strcpy(filename,"defaults.conf");
          init_application(&parameters,filename,CLIENT_MODE);
          fprintf(parameters.fp_log,"\n\nUnibo-DTKA: Reading defaults parameter....\n");
          fprintf(parameters.fp_log,"\nUnibo-DTKA: Starting in client mode.....");
       }
       // Option --authority, launch Unibo-DTKA in authority mode reading default config file.
       if(strcmp(argv[1],"--authority")==0){
          strcpy(filename,"defaults.conf");
          init_application(&parameters,filename,AUTHORITY_MODE);
          fprintf(parameters.fp_log,"\n\nUnibo-DTKA: Reading defaults parameter....\n");
          fprintf(parameters.fp_log,"\nUnibo-DTKA: Starting in authority mode.....");
       }
       if(strcmp(argv[1],"--connectiontest")==0){
    	   if(do_connection_test()==1)
    	      printf("\nConnection test is passed.\n");
    	   else
    	      return UNIBO_DTKA_EXIT_STATUS_CONNECTION_ERROR;
       }
       // Option --configure, launch Unibo-DTKA for configure the application
       if(strcmp(argv[1],"--configure")==0){
    	  configure_application("defaults.conf");
       }
       // Option --keygen, launch Unibo-DTKA for key pair generation
       if(strcmp(argv[1],"--keygen")==0){
          generate_key_pairs("defaults.conf");
       }
    } // Finish Parsing with single option.
    else if(argc == 4){        // Parsing with two options. There are only allowed: Unibo_DTKA -f filename --client
       for(i=0; i<3; i++)                                                      //or Unibo_DTKA --client -f filename                                                     
          if(strcmp(argv[i],"-f")==0){                                          //or Unibo_DTKA --authority -f filename
             res = 1;                                                           //or Unibo_DTKA -f filename --authority
             break;                                                             //or Unibo_DTKA -f filename --configure
          }                                                                     //or Unibo_DTKA --configure -f filename
       if(res == 1)                                                             //or Unibo_DTKA -f filename --keygen
          strcpy(filename,argv[++i]);                                           //or Unibo_DTKA --keygen -f filename
       else
    	  unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_SYNTAX_ERROR);

       res = 0;
       for(i=0; i<4; i++)
          if(strcmp(argv[i],"--authority")==0 || strcmp(argv[i],"--client")==0 || strcmp(argv[i],"--configure")==0 || strcmp(argv[1],"--keygen")==0){
             res = 1;
             break;
          }
       if(res == 1){
          if(strcmp(argv[i],"--client")==0){
             init_application(&parameters,filename,CLIENT_MODE);
             fprintf(parameters.fp_log,"\nUnibo-DTKA: Starting in client mode.....");
             fprintf(parameters.fp_log,"\n\nUnibo-DTKA: Reading parameter from file: %s....\n",filename);
          }
          if(strcmp(argv[i],"--authority")==0){
             init_application(&parameters,filename,AUTHORITY_MODE);
             fprintf(parameters.fp_log,"\nUnibo-DTKA: Starting in authority mode.....");
             fprintf(parameters.fp_log,"\n\nUnibo-DTKA: Reading parameter from file: %s....\n",filename);
          }
          if(strcmp(argv[i],"--configure")==0){
        	  configure_application(filename);
          }
          if(strcmp(argv[i],"--keygen")==0){
        	  configure_application(filename);
          }
       }else
    	  unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_SYNTAX_ERROR);
      
    }else
       unibo_dtka_error_handler(UNIBO_DTKA_EXIT_STATUS_SYNTAX_ERROR);

    	// Finishing parsing

    return UNIBO_DTKA_EXIT_STATUS_OK;

}
