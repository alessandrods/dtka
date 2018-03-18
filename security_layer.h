/********************************************************
 **  Authors: Alessandro Di Stanislao, alessand.distanislao@studio.unibo.it
 **           Carlo Caini (project supervisor), carlo.caini@unibo.it
 **
 **
 **  Copyright (c) 2018, Alma Mater Studiorum, University of Bologna
 **  All rights reserved.
 ********************************************************/

  /**
  * @file security_layer.h
  * @author Alessandro Di Stanislao
  * @date Jannuary, 2017
  * @brief This file contains functions for the use of the cryptographic functions.
  *  
  */  
  
#ifndef SECURITY_LAYER_H_
#define SECURITY_LAYER_H_

#define DER_FORMAT 1
#define PEM_FORMAT 0

#define PUBLIC_KEY 1
#define PRIVATE_KEY 0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/md4.h>
#include <openssl/hmac.h>
#include <openssl/ripemd.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/dsa.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>

enum hash_type{
    MD5HASH,
    MD4HASH,
    RIPEMD160HASH,
    SHA224HASH,
    SHA256HASH,
    SHA384HASH,
    SHA512HASH
};

/**
 * @name Hash Message in Hex Format
 * @brief Hash a byte array in a .
 * 
 * This API initialize the connection parameters for the DTN daemon.
 *
 * @param [al_bp_connection_t] Data structure containing the parameters for the bundle protocol.
 * 
 * @code 
 * Example usage: wrapper_init(connection, BP_PAYLOAD_MEM, 'N',-1,BP_PRIORITY_NORMAL,2000);
 * @endcode
 * 
 * @retval none.
 * 
*/


int sl_hash_message_hex(const char *input,char *output, enum hash_type type);

int sl_hash_message_text(const char *input, char *output, enum hash_type type);

/* This function implements the HMAC with a supported Hash algorithm.
   Supported Algorithm are: MD5, MD4, RIPMED-160, SHA-224, SHA-256, SHA-384, SHA-512.
   Params: message string to hash.
   Return: char pointer to hash string in text format.*/

int sl_hmac_hash(const char *input, const char* key, enum hash_type type,char *output);

/* This function is for test and benchmark purpose only.
   It generate a DSA key pair and display them.
   Params: DSA key size. */

int sl_generate_and_show_DSA_key_pair(int key_size);

/* This function is for test and benchmark purpose only.
   It generate a RSA key pair and display them.
   This keys can be subject to Hearbleed exploit so update openssl library.
   Params: RSA key size. */

int sl_generate_and_show_RSA_key_pair(int key_size);

int sl_generate_DSA_key_pair(int key_size, int random_buffer_length,DSA *dsa);

int sl_generate_RSA_key_pair(int key_size,int exp,RSA *rsa);

int sl_generate_DSA_key_pair_files(int key_size, int random_buffer_length, const char *private_key_filename, const char *public_key_filename, int key_format);

int sl_generate_RSA_key_pair_files(int key_size,int exp, const char *private_key_filename, const char *public_key_filename, int key_format);

int sl_read_DSA_key_from_file(const char* filename,int key_type,DSA *dsa);

int sl_read_RSA_key_from_file(const char* filename,int key_type,RSA *rsa);

int sl_write_DSA_key_to_mem(DSA *dsa,unsigned char *buffer,int key_type,int key_format);

int sl_write_RSA_key_to_mem(RSA *rsa,unsigned char *buffer,int key_type,int key_format);

int sl_write_DSA_key_to_file(DSA *dsa,const char *filename,int key_type,int key_format);

int sl_write_RSA_key_to_file(RSA *rsa,const char *filename,int key_type,int key_format);

int sl_read_DSA_key_from_mem(DSA *dsa,char *buffer,int key_type,int key_format);

int sl_read_RSA_key_from_mem(RSA *rsa,char *buffer,int key_type,int key_format);

int sl_sign_with_DSA_private_key(DSA *dsa, const unsigned char *message, unsigned int message_length, unsigned char *sign,unsigned int *sign_length);

int sl_sign_with_RSA_private_key(RSA *rsa, const unsigned char *message, unsigned int message_length, unsigned char *sign,unsigned int *sign_length);

int sl_sign_with_private_key_from_file(const char *filename, const char *key_type, unsigned char *sign, unsigned int *sign_length, const unsigned char *message,int message_length);

int sl_verify_with_DSA_public_key(DSA *dsa,const unsigned char*message, unsigned int message_length, const unsigned char *sign,unsigned int sign_length);

int sl_verify_with_RSA_public_key(RSA *rsa,const unsigned char*message, unsigned int message_length, const unsigned char *sign,unsigned int sign_length);

/**
 * @name It verifies a sign with a public key from a file.
 * @brief This function is for verifying a sign with a public key.
 *
 * @param [filename]
 * @param [key_type]
 * @param [sign]
 * @param [sign_length]
 * @param [message]
 * @param [message_length]
 *
 * @code
 * Example usage:
 * @endcode
 *
 * @retval
 *
*/

int sl_verify_with_public_key_from_file(const char *filename,const char *key_type,const unsigned char *sign,unsigned int sign_length,const unsigned char *message,int message_length);

/**
 * @name It encrypts a message with a public key from a file
 * @brief This is a function for encrypting data with a public key.
 *
 * @param [filename]
 * @param [key_type]
 * @param [encrypted_message]
 * @param [encrypted_message_length]
 * @param [original_message]
 * @param [padding_type]
 *
 * @code
 * Example usage:
 * @endcode
 *
 * @retval
 *
*/

int sl_encrypt_with_public_key_from_file(const char* filename,const char *key_type,const unsigned char *message,unsigned int message_length,unsigned char *encrypted_message,int padding_type);

/**
 * @name It decrypts a message with a private key from a file
 * @brief This is a function for decrypting data with a private key.
 *
 * @param [filename]
 * @param [key_type]
 * @param [encrypted_message]
 * @param [encrypted_message_length]
 * @param [original_message]
 * @param [padding_type]
 *
 * @code
 * Example usage:
 * @endcode
 *
 * @retval
 *
*/
int sl_decrypt_with_private_key_from_file(const char* filename,const char *key_type,const unsigned char *encrypted_message,unsigned int encrypted_message_length,unsigned char *original_message,int padding_type);

#endif

