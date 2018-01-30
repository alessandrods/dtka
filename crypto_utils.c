/********************************************************
 **  Authors: Alessandro Di Stanislao, alessand.distanislao@studio.unibo.it
 **           Carlo Caini (project supervisor), carlo.caini@unibo.it
 **
 **
 **  Copyright (c) 2017, Alma Mater Studiorum, University of Bologna
 **  All rights reserved.
 ********************************************************/

#include "crypto_utils.h"


int hash_message_hex(const char *input,char *output, enum hash_type type){

    int res;
	
    if(type == SHA256HASH){
       SHA256_CTX sha256;
       res = SHA256_Init(&sha256);
       if(res < 0)
          return -1;

       res = SHA256_Update(&sha256,input,strlen(input));
       if(res < 0)
          return -1;

       res = SHA256_Final((unsigned char*)output,&sha256);
       if(res < 0)
	      return -1;

       return 1;
    }

    if(type == SHA224HASH){
       SHA256_CTX sha224;
       res = SHA224_Init(&sha224);
       if(res < 0)
          return -1;
		  
       res = SHA224_Update(&sha224,input,strlen(input));
       if(res < 0)
          return -1;

       res = SHA224_Final((unsigned char*)output,&sha224);
       if(res < 0)
          return -1;

       return 1;
    }

    if(type == SHA384HASH){
       SHA512_CTX sha384;
       res = SHA384_Init(&sha384);
       if(res < 0)
          return -1;

       res = SHA384_Update(&sha384,input,strlen(input));
       if(res < 0)
          return -1;

       res = SHA384_Final((unsigned char*)output,&sha384);
       if(res < 0)
          return -1;

       return 1;
    }

    if(type == SHA512HASH){
       SHA512_CTX sha512;
       res = SHA512_Init(&sha512);
       if(res < 0)
          return -1;

       res = SHA512_Update(&sha512,input,strlen(input));
       if(res < 0)
          return -1;

       res = SHA512_Final((unsigned char*)output,&sha512);
       if(res < 0)
          return -1;

       return 1;
    }

    if(type == MD5HASH){
       MD5_CTX md5;
       res = MD5_Init(&md5);
       if(res < 0)
          return -1;

       res = MD5_Update(&md5,input,strlen(input));
       if(res < 0)
          return -1;

       res = MD5_Final((unsigned char*)output,&md5);
       if(res < 0)
          return -1;

       return 1;
    }

    if(type == MD4HASH){
       MD4_CTX md4;
       res = MD4_Init(&md4);
       if(res < 0)
          return -1;

	   res = MD4_Update(&md4,input,strlen(input));
       if(res < 0)
          return -1;

       res = MD4_Final((unsigned char*)output,&md4);
       if(res < 0)
          return -1;

       return 1;
    }
	
    if(type == RIPEMD160HASH){
       RIPEMD160_CTX ripemd160;
       res = RIPEMD160_Init(&ripemd160);
       if(res < 0)
          return -1;

       res = RIPEMD160_Update(&ripemd160,input,strlen(input));
       if(res < 0)
          return -1;

       res = RIPEMD160_Final((unsigned char*)output,&ripemd160);
       if(res < 0)
          return -1;

       return 1;
    }

    return -1;
}

int hash_message_text(const char *input, char *output, enum hash_type type){
	
	int i;
	int length=0;
    char temp[64];
	
    memset(temp,0,64);

	if(type == MD5HASH)
	   length = MD5_DIGEST_LENGTH;

	if(type == MD4HASH)
	   length = MD4_DIGEST_LENGTH;
	
	if(type == RIPEMD160HASH)
	   length = RIPEMD160_DIGEST_LENGTH;
	
	if(type == SHA512HASH)
       length = SHA512_DIGEST_LENGTH;

	if(type == SHA384HASH)
       length = SHA384_DIGEST_LENGTH;

	if(type == SHA256HASH)
	   length = SHA256_DIGEST_LENGTH;

	if(type == SHA224HASH)
       length = SHA224_DIGEST_LENGTH;
	
	if(length == 0)
	   return -1;

	i = hash_message_hex(input,temp,type);
	if(i < 0)
	   return i;

    for(i=0; i<length; i++)
       sprintf(output + (i*2),"%02X",(unsigned char)temp[i]);
	
  	return 1;
}

int hmac_hash(const char *input, const char* key, enum hash_type type,char *output){
	
    int i;	
    int hmac_size;    // Lenght of the HMAC string. 
    unsigned char* result = NULL;  // HMAC temporary string in hex format.
     
    if(type == MD5HASH){
       result = HMAC(EVP_md5(), key, strlen(key), (unsigned char*)input, strlen(input), NULL, NULL);  // Writing HMAC String with MD5 Hash.
       if(result == NULL)
          return -1;
       hmac_size = 32; 
    }
  
    if(type == MD4HASH){
       result = HMAC(EVP_md4(), key, strlen(key), (unsigned char*)input, strlen(input), NULL, NULL);  // Writing HMAC String with MD4 Hash.
       if(result == NULL)
          return -1;
       hmac_size = 32;
    }

    if(type == RIPEMD160HASH){
       result = HMAC(EVP_ripemd160(), key, strlen(key), (unsigned char*)input, strlen(input), NULL, NULL);   // Writing HMAC String with RIPMED160 Hash.
       if(result == NULL)
          return -1;
       hmac_size = 40;
    }
  
    if(type == SHA224HASH){
       result = HMAC(EVP_sha224(), key, strlen(key), (unsigned char*)input, strlen(input), NULL, NULL);  // Writing HMAC String with SHA-224 Hash.
       if(result == NULL)
          return -1;
       hmac_size = 56;
    }
  
    if(type == SHA256HASH){
       result = HMAC(EVP_sha256(), key, strlen(key), (unsigned char*)input, strlen(input), NULL, NULL);  // Writing HMAC String with SHA-256 Hash.
       if(result == NULL)
          return -1;
       hmac_size = 64;
    }
  
    if(type == SHA384HASH){
       result = HMAC(EVP_sha384(), key, strlen(key), (unsigned char*)input, strlen(input), NULL, NULL);  // Writing HMAC String with SHA-384 Hash.
       if(result == NULL)
          return -1;
       hmac_size = 96;
    }
  
    if(type == SHA512HASH){
       result = HMAC(EVP_sha512(), key, strlen(key), (unsigned char*)input, strlen(input), NULL, NULL);   // Writing HMAC String with SHA-512 Hash.
       if(result == NULL)
          return -1;
       hmac_size = 128;
    }
  
    for(i=0; i<hmac_size/2; i++){
       sprintf(output + (i*2),"%02X",result[i]);  // Converting the hex string to the text format. 
    }

    return 1;
}

int generate_DSA_key_pair(int key_size, int random_buffer_length,DSA *dsa){

    int res;
    unsigned char *rand_buffer;

    if(dsa == NULL)
       return -1;

    rand_buffer = malloc(sizeof(char)*random_buffer_length);
    if(rand_buffer == NULL){
       DSA_free(dsa);
       return -1;
    }

    res = RAND_bytes(rand_buffer, random_buffer_length);
    if(res != 1){
       DSA_free(dsa);
       free(rand_buffer);
       return -1;
    }

    res = DSA_generate_parameters_ex(dsa,key_size,rand_buffer,random_buffer_length,NULL,NULL, NULL); // Settings for the generation parameters.
    if(res != 1){
       DSA_free(dsa);
       free(rand_buffer);
       return -1;
    }

    res = DSA_generate_key(dsa); // Generate a key pair.
    if(res != 1){
       DSA_free(dsa);
       free(rand_buffer);
       return -1;
    }

    free(rand_buffer);

    return 1;
}

int generate_RSA_key_pair(int key_size,int exp,RSA *rsa){

	BIGNUM *e;
    int res;

    if(rsa == NULL)
       return -1;

    e = BN_new();
    res = BN_set_word(e,exp);
    if(res != 1)
       return -1;

	res = RSA_generate_key_ex(rsa,key_size,e,NULL);
	if(res != 1)
	   return -1;

	res = RSA_check_key(rsa);
	if(res != 1)
	   return -1;

	BN_clear_free(e);

	return 1;
}

int generate_and_show_DSA_key_pair(int key_size){
	
    DSA* dsa;
    int res;

    dsa = DSA_new(); // Create a DSA instance. 
    if(dsa == NULL)
       return -1;

    res = DSA_generate_parameters_ex(dsa,key_size,NULL,0,NULL,NULL, NULL); // Settings for the generation parameters.
    if(res != 1)
       return -1;

    res = DSA_generate_key(dsa); // Generate a key pair.
    if(res != 1)
       return -1;

    res = DSA_print_fp(stdout,dsa,0);	 // Print the key pair.
    if(res < 0)
       return -1;

    DSA_free(dsa);

    return 1;
}

int generate_and_show_RSA_key_pair(int key_size){

	RSA *rsa;
    BIGNUM *e;
    int res;

    e = BN_new();
    res = BN_set_word(e,3);
    if(res != 1)
       return -1;

    rsa = RSA_new();
    if(rsa == NULL)
       return -1;

	res = RSA_generate_key_ex(rsa,key_size,e,NULL);
	if(res != 1)
	   return -1;

	res = RSA_check_key(rsa);
	if(res != 1)
	   return -1;

	res = RSA_print_fp(stdout,rsa,0);
	if(res < 0)
	   return -1;

	RSA_free(rsa);
	BN_clear_free(e);

	return 1;
}

int generate_DSA_key_pair_files(int key_size, int random_buffer_length, const char *private_key_filename, const char *public_key_filename, int key_format){

    DSA* dsa;
    int res;
    int length;
    unsigned char *rand_buffer;
    unsigned char *private_key_buffer;
    unsigned char *public_key_buffer;
    unsigned char *p;
    FILE *private_key_fp;
    FILE *public_key_fp;
    EVP_PKEY *evp_private_key;
    BIO* bw;

    dsa = DSA_new(); // Create a DSA instance.
    if(dsa == NULL)
       return -1;

    rand_buffer = malloc(sizeof(char)*random_buffer_length);
    if(rand_buffer == NULL){
       DSA_free(dsa);
       return -1;
    }

    res = RAND_bytes(rand_buffer, random_buffer_length);
    if(res != 1){
       DSA_free(dsa);
       free(rand_buffer);
       return -1;
    }

    res = DSA_generate_parameters_ex(dsa,key_size,rand_buffer,random_buffer_length,NULL,NULL, NULL); // Settings for the generation parameters.
    if(res != 1){
       DSA_free(dsa);
       free(rand_buffer);
       return -1;
    }

    res = DSA_generate_key(dsa); // Generate a key pair.
    if(res != 1){
       DSA_free(dsa);
       free(rand_buffer);
       return -1;
    }

    free(rand_buffer);

    if(key_format == DER_FORMAT){
       length = i2d_DSA_PUBKEY(dsa,NULL);
       if(length < 0){
    	  DSA_free(dsa);
    	  return -1;
       }

       public_key_buffer = malloc(sizeof(unsigned char)*length);
       if(public_key_buffer == NULL){
    	  DSA_free(dsa);
    	  return -1;
       }

       p = public_key_buffer;
       res = i2d_DSA_PUBKEY(dsa,&p);
       if(res < 0){
    	  DSA_free(dsa);
    	  free(public_key_buffer);
    	  return -1;
       }

       public_key_fp = fopen(public_key_filename,"wb");
       if(public_key_fp == NULL){
    	  DSA_free(dsa);
    	  free(public_key_buffer);
    	  return -1;
       } 

       bw = BIO_new_fp(public_key_fp, BIO_NOCLOSE);
       res = BIO_write(bw,public_key_buffer,length);
       if(res < 0){
    	  DSA_free(dsa);
    	  free(public_key_buffer);
    	  fclose(public_key_fp);
    	  return -1;
       }

       free(public_key_buffer);

       length = i2d_DSAPrivateKey(dsa,NULL);
       if(length < 0){
    	  DSA_free(dsa);
    	  return -1;
       }

       private_key_buffer = malloc(sizeof(unsigned char)*length);
       if(private_key_buffer == NULL){
    	  DSA_free(dsa);
    	  return -1;
       }

       p = private_key_buffer;
       res = i2d_DSAPrivateKey(dsa,&p);
       if(res < 0){
    	  DSA_free(dsa);
    	  free(private_key_buffer);
    	  return -1;
       }

       private_key_fp = fopen(private_key_filename,"wb");
       if(private_key_fp == NULL){
    	  DSA_free(dsa);
    	  free(private_key_buffer);
    	  return -1;
       }

       bw = BIO_new_fp(private_key_fp, BIO_NOCLOSE);
       res = BIO_write(bw,private_key_buffer,length);
       if(res < 0){
    	  DSA_free(dsa);
    	  free(private_key_buffer);
    	  fclose(private_key_fp);
    	  return -1;
       }

       free(private_key_buffer);

       BIO_free_all(bw);
       fclose(private_key_fp);
       fclose(public_key_fp);

    }

    if(key_format == PEM_FORMAT){
       public_key_fp = fopen(public_key_filename,"w");
       if(public_key_fp == NULL){
      	  DSA_free(dsa);
      	  return -1;
       }

       res = PEM_write_DSA_PUBKEY(public_key_fp, dsa);
       if(res < 0){
    	  DSA_free(dsa);
    	  fclose(public_key_fp);
    	  return -1;
       }

       fclose(public_key_fp);

       private_key_fp = fopen(private_key_filename,"w");
       if(private_key_fp == NULL){
    	  DSA_free(dsa);
    	  return -1;
       }

       evp_private_key = EVP_PKEY_new();
       if(evp_private_key == NULL){
    	  DSA_free(dsa);
    	  return -1;
       }

       res = EVP_PKEY_set1_DSA(evp_private_key,dsa);
       if(res != 1){
    	  EVP_PKEY_free(evp_private_key);
    	  DSA_free(dsa);
    	  return -1;
       }

       res = PEM_write_PrivateKey(private_key_fp, evp_private_key, NULL, NULL, 0, 0, NULL);
       if(res < 0){
    	  EVP_PKEY_free(evp_private_key);
    	  DSA_free(dsa);
    	  return -1;
       }

       EVP_PKEY_free(evp_private_key);
       fclose(private_key_fp);

    }

    DSA_free(dsa);

    return 1;

}

int generate_RSA_key_pair_files(int key_size, int exp, const char *private_key_filename, const char *public_key_filename, int key_format){

	RSA *rsa;
    BIGNUM *e;
    int res;
    int length;
    FILE *public_key_fp;
    FILE *private_key_fp;
    unsigned char *private_key_buffer;
    unsigned char *public_key_buffer;
    unsigned char *p;
    BIO* bw;

    e = BN_new();
    res = BN_set_word(e,exp);
    if(res != 1)
       return -1;

    rsa = RSA_new();
    if(rsa == NULL)
       return -1;

	res = RSA_generate_key_ex(rsa,key_size,e,NULL);
	if(res != 1)
	   return -1;

	res = RSA_check_key(rsa);
	if(res != 1)
	   return -1;

	BN_clear_free(e);

    if(key_format == PEM_FORMAT){
       private_key_fp = fopen(private_key_filename,"w");
       if(private_key_fp == NULL){
    	  RSA_free(rsa);
    	  return -1;
       }

       res = PEM_write_RSAPrivateKey(private_key_fp, rsa, NULL, 0, 0, NULL, NULL);
       if(res == 0){
    	  RSA_free(rsa);
    	  fclose(private_key_fp);
    	  return -1;
       }

       fclose(private_key_fp);

       public_key_fp = fopen(public_key_filename,"w");
       if(public_key_fp == NULL){
    	  RSA_free(rsa);
    	  return -1;
       }

       res = PEM_write_RSAPublicKey(public_key_fp, rsa);
       if(res == 0){
    	  RSA_free(rsa);
    	  fclose(public_key_fp);
    	  return -1;
       }

       fclose(public_key_fp);
    }

    if(key_format == DER_FORMAT){
       length = i2d_RSA_PUBKEY(rsa,NULL);
       if(length < 0){
      	  RSA_free(rsa);
      	  return -1;
       }

       public_key_buffer = malloc(sizeof(unsigned char)*length);
       if(public_key_buffer == NULL){
      	  RSA_free(rsa);
      	  return -1;
       }

       p = public_key_buffer;
       res = i2d_RSA_PUBKEY(rsa,&p);
       if(res < 0){
      	  RSA_free(rsa);
      	  free(public_key_buffer);
      	  return -1;
       }

       public_key_fp = fopen(public_key_filename,"wb");
       if(public_key_fp == NULL){
      	  RSA_free(rsa);
      	  free(public_key_buffer);
      	  return -1;
       }

       bw = BIO_new_fp(public_key_fp, BIO_NOCLOSE);
       res = BIO_write(bw,public_key_buffer,length);
       if(res < 0){
      	  RSA_free(rsa);
      	  free(public_key_buffer);
      	  fclose(public_key_fp);
      	  return -1;
       }

       free(public_key_buffer);

       length = i2d_RSAPrivateKey(rsa,NULL);
       if(length < 0){
      	  RSA_free(rsa);
      	  return -1;
       }

       private_key_buffer = malloc(sizeof(unsigned char)*length);
       if(private_key_buffer == NULL){
      	  RSA_free(rsa);
      	  return -1;
       }

       p = private_key_buffer;
       res = i2d_RSAPrivateKey(rsa,&p);
       if(res < 0){
      	  RSA_free(rsa);
      	  free(private_key_buffer);
      	  return -1;
       }

       private_key_fp = fopen(private_key_filename,"wb");
       if(private_key_fp == NULL){
      	  RSA_free(rsa);
      	  free(private_key_buffer);
      	  return -1;
       }

       bw = BIO_new_fp(private_key_fp, BIO_NOCLOSE);
       res = BIO_write(bw,private_key_buffer,length);
       if(res < 0){
      	  RSA_free(rsa);
      	  free(private_key_buffer);
      	  fclose(private_key_fp);
      	  return -1;
       }

       free(private_key_buffer);

	   BIO_free_all(bw);
       fclose(private_key_fp);
       fclose(public_key_fp);
    }

	RSA_free(rsa);

	return 1;
}

int read_DSA_key_from_file(const char* filename,int dsa_key_type,DSA *dsa){

    char *ext_buffer;
    FILE *key_file;
    BIO *key_bio;
    int res;

    ext_buffer = calloc(3,sizeof(char));
    memcpy(ext_buffer,filename+strlen(filename)-3,3);

    if(strcmp(ext_buffer,"PEM")==0 || strcmp(ext_buffer,"pem")==0){
       free(ext_buffer);
	   
   	   key_file = fopen(filename,"r");
       if(key_file == NULL)
    	  return -1;

       if(dsa_key_type == PUBLIC_KEY){
    	  dsa = PEM_read_DSA_PUBKEY(key_file,NULL,NULL,NULL);
    	  if(dsa == NULL){
    	     fclose(key_file);
    		 return -1;
    	  }
       }
       if(dsa_key_type == PRIVATE_KEY){
    	  dsa = PEM_read_DSAPrivateKey(key_file,NULL,NULL,NULL);
    	  if(dsa == NULL){
    		 fclose(key_file);
    		 return -1;
    	  }
       }

       fclose(key_file);

       return 1;
    }

    if(strcmp(ext_buffer,"DER")==0 || strcmp(ext_buffer,"der")==0){
       free(ext_buffer);

       if(dsa_key_type == PRIVATE_KEY){
     	  key_bio = BIO_new(BIO_s_file());
     	  if(key_bio == NULL)
     		 return -1;

     	  res = BIO_read_filename(key_bio,filename);
     	  if(res < 0){
     		 BIO_free(key_bio);
     		 return -1;
     	  }

          dsa = d2i_DSAPrivateKey_bio(key_bio, NULL);
          if(dsa == NULL){
             BIO_free(key_bio);
             return -1;
          }

       }

       if(dsa_key_type == PUBLIC_KEY){
     	  key_bio = BIO_new(BIO_s_file());
     	  if(key_bio == NULL)
     	     return -1;

     	  res = BIO_read_filename(key_bio,filename);
     	  if(res < 0){
     		 BIO_free(key_bio);
     		 return -1;
     	  }

          dsa = d2i_DSA_PUBKEY_bio(key_bio, NULL);
          if(dsa == NULL){
             BIO_free(key_bio);
             return -1;
          }

       }

       BIO_free(key_bio);

       return 1;
    }


	return -1;
}

int read_RSA_key_from_file(const char* filename,int key_type,RSA *rsa){

    char *ext_buffer;
    BIO *key_bio;
    FILE *key_file;
    EVP_PKEY *priv_key;
    int res;


    ext_buffer = calloc(4,sizeof(char));
    memcpy(ext_buffer,filename+strlen(filename)-3,4);

    if(strcmp(ext_buffer,"PEM")==0 || strcmp(ext_buffer,"pem")==0){
       free(ext_buffer);

   	   if(key_type == PUBLIC_KEY){
   	      key_bio = BIO_new_file(filename,"r");
     	  if(key_bio == NULL)
     		 return -1;
			  
     	  rsa = PEM_read_bio_RSAPublicKey(key_bio,&rsa,NULL,NULL);

     	  if(rsa == NULL){
     		 BIO_free(key_bio);
     		 return -1;
     	  }

          BIO_free(key_bio);
       }

       if(key_type == PRIVATE_KEY){
   	      priv_key = EVP_PKEY_new();

    	  if(priv_key == NULL)
    		 return -1;

    	  key_file = fopen(filename, "r");

    	  if(key_file == NULL){
    	     EVP_PKEY_free(priv_key);
    		 return -1;
    	  }

    	  PEM_read_PrivateKey(key_file , &priv_key, NULL, NULL);

    	  fclose(key_file);

    	  rsa = EVP_PKEY_get1_RSA(priv_key);

    	  if(rsa == NULL){
    		 return -1;
    	  }

    	  EVP_PKEY_free(priv_key);
       }

       res = RSA_check_key(rsa);
       if(res != 1)
    	  return -1;

       return 1;
    }

    if(strcmp(ext_buffer,"DER")==0 || strcmp(ext_buffer,"der")==0){
       free(ext_buffer);

       if(key_type == PRIVATE_KEY){
     	  key_bio = BIO_new(BIO_s_file());
     	  if(key_bio == NULL)
     		 return -1;

     	  res = BIO_read_filename(key_bio,filename);
     	  if(res < 0){
     		 BIO_free(key_bio);
     		 return -1;
     	  }

          rsa = d2i_RSAPrivateKey_bio(key_bio, NULL);
          if(rsa == NULL){
             BIO_free(key_bio);
             return -1;
          }
       }

       if(key_type == PUBLIC_KEY){
   	      key_bio = BIO_new(BIO_s_file());
     	  if(key_bio == NULL)
     		 return -1;

     	  res = BIO_read_filename(key_bio,filename);
     	  if(res < 0){
     		 BIO_free(key_bio);
     		 return -1;
     	  }

          rsa = d2i_RSA_PUBKEY_bio(key_bio, NULL);
          if(rsa == NULL){
             BIO_free(key_bio);
             return -1;
          }

       }

       BIO_free(key_bio);

       res = RSA_check_key(rsa);
       if(res != 1)
    	  return -1;

       return 1;
    }

    return -1;
}

int write_DSA_key_to_file(DSA *dsa,const char *filename,int key_type,int format){

    int res;
    int length;
    unsigned char *key_buffer;
    unsigned char *p;
    FILE *filename_fp;
    EVP_PKEY *evp_private_key;
    BIO* bw;

    if(format == DER_FORMAT && key_type == PUBLIC_KEY){
       length = i2d_DSA_PUBKEY(dsa,NULL);
       if(length < 0)
    	  return -1;

       key_buffer = malloc(sizeof(unsigned char)*length);
       if(key_buffer == NULL)
     	  return -1;

       p = key_buffer;
       res = i2d_DSA_PUBKEY(dsa,&p);
       if(res < 0){
    	  free(key_buffer);
    	  return -1;
       }

       filename_fp = fopen(filename,"wb");
       if(filename_fp == NULL){
    	  free(key_buffer);
    	  return -1;
       }

       bw = BIO_new_fp(filename_fp, BIO_NOCLOSE);
       res = BIO_write(bw,key_buffer,length);
       if(res < 0){
    	  free(key_buffer);
    	  fclose(filename_fp);
    	  return -1;
       }

       free(key_buffer);
       fclose(filename_fp);
       return 1;

    }

    if(format == DER_FORMAT && key_type == PRIVATE_KEY){
       length = i2d_DSAPrivateKey(dsa,NULL);
       if(length < 0)
    	  return -1;

       key_buffer = malloc(sizeof(unsigned char)*length);
       if(key_buffer == NULL)
    	  return -1;

       p = key_buffer;
       res = i2d_DSAPrivateKey(dsa,&p);
       if(res < 0){
    	  free(key_buffer);
    	  return -1;
       }

       filename_fp = fopen(filename,"wb");
       if(filename_fp == NULL){
    	  free(key_buffer);
    	  return -1;
       }

       bw = BIO_new_fp(filename_fp, BIO_NOCLOSE);
       res = BIO_write(bw,key_buffer,length);
       if(res < 0){
    	  BIO_free_all(bw);
    	  free(key_buffer);
    	  fclose(filename_fp);
    	  return -1;
       }

       free(key_buffer);

       BIO_free_all(bw);
       fclose(filename_fp);

    }

    if(format == PEM_FORMAT && key_type == PUBLIC_KEY){
       filename_fp = fopen(filename,"w");
       if(filename_fp == NULL)
      	  return -1;

       res = PEM_write_DSA_PUBKEY(filename_fp, dsa);
       if(res < 0){
    	  fclose(filename_fp);
    	  return -1;
       }

       fclose(filename_fp);
       return 1;
    }

    if(format == PEM_FORMAT && key_type == PRIVATE_KEY){
       filename_fp = fopen(filename,"w");
       if(filename_fp == NULL)
    	  return -1;

       evp_private_key = EVP_PKEY_new();
       if(evp_private_key == NULL)
    	  return -1;

       res = EVP_PKEY_set1_DSA(evp_private_key,dsa);
       if(res != 1){
    	  EVP_PKEY_free(evp_private_key);
    	  return -1;
       }

       res = PEM_write_PrivateKey(filename_fp, evp_private_key, NULL, NULL, 0, 0, NULL);
       if(res < 0){
    	  EVP_PKEY_free(evp_private_key);
    	  return -1;
       }

       EVP_PKEY_free(evp_private_key);
       fclose(filename_fp);
       return 1;
    }

    return -1;

}

int write_RSA_key_to_file(RSA *rsa,const char *filename,int key_type,int format){

    int res;
    int length;
    unsigned char *key_buffer;
    unsigned char *p;
    FILE *filename_fp;
    EVP_PKEY *evp_private_key;
    BIO* bw;

	res = RSA_check_key(rsa);
	if(res != 1)
	   return -1;

    if(format == DER_FORMAT && key_type == PUBLIC_KEY){
       length = i2d_RSA_PUBKEY(rsa,NULL);
       if(length < 0)
    	  return -1;

       key_buffer = malloc(sizeof(unsigned char)*length);
       if(key_buffer == NULL)
     	  return -1;

       p = key_buffer;
       res = i2d_RSA_PUBKEY(rsa,&p);
       if(res < 0){
    	  free(key_buffer);
    	  return -1;
       }

       filename_fp = fopen(filename,"wb");
       if(filename_fp == NULL){
    	  free(key_buffer);
    	  return -1;
       }

       bw = BIO_new_fp(filename_fp, BIO_NOCLOSE);
       res = BIO_write(bw,key_buffer,length);
       if(res < 0){
    	  free(key_buffer);
    	  fclose(filename_fp);
    	  return -1;
       }

       free(key_buffer);
       fclose(filename_fp);
       return 1;

    }

    if(format == DER_FORMAT && key_type == PRIVATE_KEY){
       length = i2d_RSAPrivateKey(rsa,NULL);
       if(length < 0)
    	  return -1;

       key_buffer = malloc(sizeof(unsigned char)*length);
       if(key_buffer == NULL)
    	  return -1;

       p = key_buffer;
       res = i2d_RSAPrivateKey(rsa,&p);
       if(res < 0){
    	  free(key_buffer);
    	  return -1;
       }

       filename_fp = fopen(filename,"wb");
       if(filename_fp == NULL){
    	  free(key_buffer);
    	  return -1;
       }

       bw = BIO_new_fp(filename_fp, BIO_NOCLOSE);
       res = BIO_write(bw,key_buffer,length);
       if(res < 0){
    	  BIO_free_all(bw);
    	  free(key_buffer);
    	  fclose(filename_fp);
    	  return -1;
       }

       free(key_buffer);

       BIO_free_all(bw);
       fclose(filename_fp);

    }

    if(format == PEM_FORMAT && key_type == PUBLIC_KEY){
       filename_fp = fopen(filename,"w");
       if(filename_fp == NULL)
      	  return -1;

       res = PEM_write_RSA_PUBKEY(filename_fp, rsa);
       if(res < 0){
    	  fclose(filename_fp);
    	  return -1;
       }

       fclose(filename_fp);
       return 1;
    }

    if(format == PEM_FORMAT && key_type == PRIVATE_KEY){
       filename_fp = fopen(filename,"w");
       if(filename_fp == NULL)
    	  return -1;

       evp_private_key = EVP_PKEY_new();
       if(evp_private_key == NULL)
    	  return -1;

       res = EVP_PKEY_set1_RSA(evp_private_key,rsa);
       if(res != 1){
    	  EVP_PKEY_free(evp_private_key);
    	  return -1;
       }

       res = PEM_write_PrivateKey(filename_fp, evp_private_key, NULL, NULL, 0, 0, NULL);
       if(res < 0){
    	  EVP_PKEY_free(evp_private_key);
    	  return -1;
       }

       EVP_PKEY_free(evp_private_key);
       fclose(filename_fp);
       return 1;
    }

    return -1;
}

int write_DSA_key_to_mem(DSA *dsa,unsigned char *buffer,int key_type, int format){

    int length;
    int res;
    unsigned char *p;
    BIO *buffer_bio;

    if(key_type == PUBLIC_KEY && format == PEM_FORMAT){
       buffer_bio = BIO_new(BIO_s_mem());
       if(buffer_bio == NULL)
          return -1;

       res = PEM_write_bio_DSA_PUBKEY(buffer_bio,dsa);
       if(res < 0){
          BIO_free_all(buffer_bio);
          return -1;
       }

       length = BIO_pending(buffer_bio);
       if(length < 0){
          BIO_free_all(buffer_bio);
          return -1;
       }

       if(buffer == NULL){
       	  BIO_free_all(buffer_bio);
          return length;
       }

       res = BIO_read(buffer_bio,buffer,length);
       if(res < 0){
          BIO_free_all(buffer_bio);
          return -1;
       }

       BIO_free_all(buffer_bio);

       return length;
    }

    if(key_type == PRIVATE_KEY && format == PEM_FORMAT){
       buffer_bio = BIO_new(BIO_s_mem());
       if(buffer_bio == NULL)
          return -1;

       res = PEM_write_bio_DSAPrivateKey(buffer_bio, dsa, NULL, NULL, 0, NULL, NULL);
       if(res < 0){
       	  BIO_free_all(buffer_bio);
          return -1;
       }

       length = BIO_pending(buffer_bio);
       if(length < 0){
          BIO_free_all(buffer_bio);
          return -1;
       }

       if(buffer == NULL){
          BIO_free_all(buffer_bio);
          return length;
       }

       res = BIO_read(buffer_bio,buffer,length);
       if(res < 0){
       	  BIO_free_all(buffer_bio);
          return -1;
       }

       BIO_free_all(buffer_bio);

       return length;
    }

    if(key_type == PUBLIC_KEY && format == DER_FORMAT){
       length = i2d_DSA_PUBKEY(dsa,NULL);
       if(length < 0)
      	  return -1;

       if(buffer == NULL)
          return length;

       p = buffer;
       res = i2d_DSA_PUBKEY(dsa,&p);
       if(res < 0){
      	  free(buffer);
      	  return -1;
       }

       return length;
    }

    if(key_type == PRIVATE_KEY && format == DER_FORMAT){
       length = i2d_DSAPrivateKey(dsa,NULL);
       if(length < 0)
      	  return -1;

       if(buffer == NULL)
          return length;

       p = buffer;
       res = i2d_DSAPrivateKey(dsa,&p);
       if(res < 0){
      	  free(buffer);
      	  return -1;
       }

       return length;

    }

    return -1;
}

int write_RSA_key_to_mem(RSA *rsa,unsigned char *buffer,int key_type,int format){

    int length;
    int res;
    unsigned char *p;
    BIO *buffer_bio;

	res = RSA_check_key(rsa);
	if(res != 1)
	   return -1;

    if(key_type == PUBLIC_KEY && format == PEM_FORMAT){
       buffer_bio = BIO_new(BIO_s_mem());
       if(buffer_bio == NULL)
          return -1;

       res = PEM_write_bio_RSAPublicKey(buffer_bio,rsa);
       if(res < 0){
       	  BIO_free_all(buffer_bio);
          return -1;
       }

       length = BIO_pending(buffer_bio);
       if(length < 0){
          BIO_free_all(buffer_bio);
          return -1;
       }

       if(buffer == NULL){
       	  BIO_free_all(buffer_bio);
          return length;
       }

       res = BIO_read(buffer_bio,buffer,length);
       if(res < 0){
       	  BIO_free_all(buffer_bio);
          return -1;
       }

       BIO_free_all(buffer_bio);

       return length;
    }

    if(key_type == PRIVATE_KEY && format == PEM_FORMAT){
       buffer_bio = BIO_new(BIO_s_mem());
       if(buffer_bio == NULL)
          return -1;

       res = PEM_write_bio_RSAPrivateKey(buffer_bio, rsa, NULL, NULL, 0, NULL, NULL);
       if(res < 0){
       	  BIO_free_all(buffer_bio);
          return -1;
       }

       length = BIO_pending(buffer_bio);
       if(length < 0){
       	  BIO_free_all(buffer_bio);
          return -1;
       }

       if(buffer == NULL){
          BIO_free_all(buffer_bio);
          return length;
       }

       res = BIO_read(buffer_bio,buffer,length);
       if(res < 0){
       	  BIO_free_all(buffer_bio);
          return -1;
       }

       BIO_free_all(buffer_bio);
	   
       return length;
    }

    if(key_type == PUBLIC_KEY && format == DER_FORMAT){
       length = i2d_RSA_PUBKEY(rsa,NULL);
       if(length < 0)
      	  return -1;

       if(buffer == NULL)
       	  return length;

       p = buffer;
       res = i2d_RSA_PUBKEY(rsa,&p);
       if(res < 0){
      	  free(buffer);
      	  return -1;
       }

       return length;
    }

    if(key_type == PRIVATE_KEY && format == DER_FORMAT){
       length = i2d_RSAPrivateKey(rsa,NULL);
       if(length < 0)
      	  return -1;

       if(buffer == NULL)
          return length;

       p = buffer;
       res = i2d_RSAPrivateKey(rsa,&p);
       if(res < 0){
      	  free(buffer);
      	  return -1;
       }

       return length;
    }

    return -1;
}

int read_DSA_key_from_mem(DSA *dsa,char *buffer,int key_type,int format){

    BIO *key_bio;

   	if(key_type == PUBLIC_KEY && format == PEM_FORMAT){
       key_bio = BIO_new_mem_buf(buffer, -1);
       if(key_bio == NULL)
          return -1;

       dsa = PEM_read_bio_DSA_PUBKEY(key_bio,NULL,0,NULL);
       if(dsa == NULL)
    	  return -1;

       BIO_free(key_bio);
       return 1;
    }

    if(key_type == PRIVATE_KEY && format == PEM_FORMAT){
       key_bio = BIO_new_mem_buf(buffer, -1);
       if(key_bio == NULL)
          return -1;

       dsa = PEM_read_bio_DSAPrivateKey(key_bio,NULL,0,NULL);
       if(dsa == NULL)
    	  return -1;

       BIO_free(key_bio);
       return 1;
    }

    if(key_type == PRIVATE_KEY && format == DER_FORMAT){
       key_bio = BIO_new_mem_buf(buffer, -1);
       if(key_bio == NULL)
        	return -1;

       dsa = d2i_DSAPrivateKey_bio(key_bio, NULL);
       if(dsa == NULL){
           BIO_free(key_bio);
           return -1;
       }

       BIO_free(key_bio);
       return 1;
    }

    if(key_type == PUBLIC_KEY && format == DER_FORMAT){
       key_bio = BIO_new_mem_buf(buffer, -1);
       if(key_bio == NULL)
     	  return -1;

       dsa = d2i_DSA_PUBKEY_bio(key_bio, NULL);
       if(dsa == NULL){
          BIO_free(key_bio);
          return -1;
       }

       BIO_free(key_bio);
       return 1;
    }

    return -1;
}

int read_RSA_key_from_mem(RSA *rsa,char *buffer,int key_type,int format){

    int res;
	BIO *key_bio;

   	if(key_type == PUBLIC_KEY && format == PEM_FORMAT){
       key_bio = BIO_new_mem_buf(buffer, -1);
       if(key_bio == NULL)
          return -1;

       rsa = PEM_read_bio_RSA_PUBKEY(key_bio,NULL,0,NULL);
       if(rsa == NULL)
    	  return -1;

       BIO_free(key_bio);

       res = RSA_check_key(rsa);
   	   if(res != 1)
   		  return -1;

       return 1;
    }

    if(key_type == PRIVATE_KEY && format == PEM_FORMAT){
       key_bio = BIO_new_mem_buf(buffer, -1);
       if(key_bio == NULL)
          return -1;

       rsa = PEM_read_bio_RSAPrivateKey(key_bio,NULL,0,NULL);
       if(rsa == NULL)
    	  return -1;

       BIO_free(key_bio);

       res = RSA_check_key(rsa);
       if(res != 1)
   		  return -1;

       return 1;
    }

    if(key_type == PRIVATE_KEY && format == DER_FORMAT){
       key_bio = BIO_new_mem_buf(buffer, -1);
       if(key_bio == NULL)
          return -1;
		  
       rsa = d2i_RSAPrivateKey_bio(key_bio, NULL);
       if(rsa == NULL){
          BIO_free(key_bio);
          return -1;
       }

       BIO_free(key_bio);

       res = RSA_check_key(rsa);
       if(res != 1)
    	  return -1;

       return 1;
    }

    if(key_type == PUBLIC_KEY && format == DER_FORMAT){
   	   key_bio = BIO_new_mem_buf(buffer, -1);
       if(key_bio == NULL)
     	  return -1;

       rsa = d2i_RSA_PUBKEY_bio(key_bio, NULL);
       if(rsa == NULL){
          BIO_free(key_bio);
           return -1;
       }

       BIO_free(key_bio);

       res = RSA_check_key(rsa);
       if(res != 1)
    	  return -1;

       return 1;
    }

    return -1;
}

int sign_with_DSA_private_key(DSA *dsa, const unsigned char *message, unsigned int message_length, unsigned char *sign,unsigned int *sign_length){

	int res;
	unsigned char hash[20];

	SHA1(message, message_length, hash);
	res = DSA_sign(NID_sha1, hash, 20, sign, sign_length, dsa);
	if(res <= 0)
	   return -1;

	return 1;
}

int sign_with_RSA_private_key(RSA *rsa, const unsigned char *message, unsigned int message_length, unsigned char *sign,unsigned int *sign_length){

	int res;
	unsigned char hash[20];

	res = RSA_check_key(rsa);
	if(res != 1)
	   return -1;

	SHA1(message, message_length, hash);

	res = RSA_sign(NID_sha1, hash, 20, sign, sign_length, rsa);
    if(res <= 0)
       return -1;

	return 1;
}

int sign_with_private_key_from_file(const char *filename, const char *key_type, unsigned char *sign, unsigned int *sign_length, const unsigned char *message,int message_length){

    BIO *key_bio;

	RSA *rsa;
	DSA *dsa;
	int res;

	char * ext_buffer;
	EVP_PKEY *priv_key;
	FILE *key_file;

	unsigned char hash[20];

	if(strcmp(key_type,"DSA") != 0 && strcmp(key_type,"RSA") != 0)
	   return -1;

    ext_buffer = calloc(3,sizeof(char));
    memcpy(ext_buffer,filename+strlen(filename)-3,3);

    if(strcmp(ext_buffer,"DER")!=0 && strcmp(ext_buffer,"der")!=0 && strcmp(ext_buffer,"PEM")!=0 && strcmp(ext_buffer,"pem")!=0){
       return -1;
       free(ext_buffer);
    }

	if(strcmp(key_type,"RSA") == 0){
	   if(strcmp(ext_buffer,"PEM")==0 || strcmp(ext_buffer,"pem")==0){
          free(ext_buffer);

	      priv_key = EVP_PKEY_new();
   		  if(priv_key == NULL)
   			 return -1;

   		  key_file = fopen(filename, "r");
   		  if(key_file == NULL){
   			 EVP_PKEY_free(priv_key);
   			 return -1;
   		  }

   		  PEM_read_PrivateKey(key_file , &priv_key, NULL, NULL);
          if(priv_key == NULL){
        	 fclose(key_file);
        	 return -1;
          }

   		  fclose(key_file);
   		  rsa = EVP_PKEY_get1_RSA(priv_key);

   		  if(rsa == NULL){
   			 EVP_PKEY_free(priv_key);
   			 return -1;
   		  }

   		  res = RSA_check_key(rsa);
   		  if(res != 1)
   			 return -1;

   		  EVP_PKEY_free(priv_key);

       }

	   if(strcmp(ext_buffer,"DER")==0 || strcmp(ext_buffer,"der")==0){
	      free(ext_buffer);

    	  key_bio = BIO_new(BIO_s_file());
    	  if(key_bio == NULL)
    		 return -1;

    	  res = BIO_read_filename(key_bio,filename);
    	  if(res < 0){
    		 BIO_free(key_bio);
    		 return -1;
    	  }

          rsa = d2i_RSAPrivateKey_bio(key_bio, NULL);
          if(rsa == NULL){
             BIO_free(key_bio);
             return -1;
          }

          BIO_free(key_bio);

	   }

	   if(sign != NULL){
	      SHA1(message, message_length, hash);
		  res = RSA_sign(NID_sha1, hash, 20, sign, sign_length, rsa);
          if(res <= 0){
        	 RSA_free(rsa);
        	 return -1;
          }
		  RSA_free(rsa);

	   }else{
		  *sign_length = RSA_size(rsa);
		  RSA_free(rsa);
		  return 1;
	   }

	   return 1;
	}

	if(strcmp(key_type,"DSA") == 0){
	   if(strcmp(ext_buffer,"PEM")==0 || strcmp(ext_buffer,"pem")==0){
	      free(ext_buffer);

	      priv_key = EVP_PKEY_new();
		  if(priv_key == NULL)
		     return -1;

		  key_file = fopen(filename, "r");
		  if(key_file == NULL){
		     EVP_PKEY_free(priv_key);
		     return -1;
		  }

		  PEM_read_PrivateKey(key_file , &priv_key, NULL, NULL);
          if(priv_key == NULL){
     	     fclose(key_file);
     	     return -1;
          }

		  fclose(key_file);
		  dsa = EVP_PKEY_get1_DSA(priv_key);

		  if(dsa == NULL){
		     EVP_PKEY_free(priv_key);
		     return -1;
		  }

		  EVP_PKEY_free(priv_key);

       }

	if(strcmp(ext_buffer,"DER")==0 || strcmp(ext_buffer,"der")==0){
	   free(ext_buffer);

 	   key_bio = BIO_new(BIO_s_file());
 	   if(key_bio == NULL)
 		  return -1;

 	   res = BIO_read_filename(key_bio,filename);
 	   if(res < 0){
 		  BIO_free(key_bio);
 		  return -1;
 	   }

       dsa = d2i_DSAPrivateKey_bio(key_bio, NULL);
       if(dsa == NULL){
          BIO_free(key_bio);
          return -1;
       }

       BIO_free(key_bio);

	   }
    }

	   if(sign != NULL){
	      SHA1(message, message_length, hash);
		  res = DSA_sign(NID_sha1, hash, 20, sign, sign_length, dsa);

		  if(res <= 0){
			 DSA_free(dsa);
			 return -1;
		  }

		  DSA_free(dsa);

	   }else{
		  *sign_length = DSA_size(dsa);
		  DSA_free(dsa);
	   }

	   return 1;

	}

int verify_with_DSA_public_key(DSA *dsa,const unsigned char*message, unsigned int message_length, const unsigned char *sign,unsigned int sign_length){

    int res;
	unsigned char hash[20];

	SHA1(message, message_length, hash);
	res = DSA_verify(NID_sha1, hash, 20, sign, sign_length, dsa);

	return res;
}

int verify_with_RSA_public_key(RSA *rsa,const unsigned char*message, unsigned int message_length, const unsigned char *sign,unsigned int sign_length){

	int res;
	unsigned char hash[20];

	res = RSA_check_key(rsa);
	if(res != 1)
	   return -1;

	SHA1(message, message_length, hash);

	res = RSA_verify(NID_sha1, hash, 20, sign, sign_length, rsa);

	return res;
}

int verify_with_public_key_from_file(const char *filename,const char *key_type,const unsigned char *sign,unsigned int sign_length,const unsigned char *message,int message_length){

    int res;

    RSA *rsa;
    DSA *dsa;

    BIO *key_bio;
    FILE *key_file;

    char *ext_buffer;
    unsigned char hash[20];

    ext_buffer = calloc(3,sizeof(char));
    memcpy(ext_buffer,filename+strlen(filename)-3,3);

    if(strcmp(key_type,"RSA") != 0 && strcmp(key_type,"DSA") != 0)
       return -1;

    if(strcmp(key_type,"RSA")==0){
       if(strcmp(ext_buffer,"PEM") == 0 || strcmp(ext_buffer,"pem") == 0){
    	  free(ext_buffer);
          key_file = fopen(filename,"r");

          if(key_file == NULL)
        	 return -1;

          rsa = RSA_new();

          if(rsa == NULL){
        	 fclose(key_file);
        	 return -1;
          }

          rsa = PEM_read_RSAPublicKey(key_file,&rsa,NULL,NULL);
          if(rsa == NULL){
        	 fclose(key_file);
        	 return -1;
          }

          fclose(key_file);

       }

       if(strcmp(ext_buffer,"DER") == 0 || strcmp(ext_buffer,"der") == 0){
   	      free(ext_buffer);

    	  key_bio = BIO_new(BIO_s_file());
    	  if(key_bio == NULL)
    	   	 return -1;

    	  res = BIO_read_filename(key_bio,filename);
    	  if(res < 0){
    		 BIO_free(key_bio);
    		 return -1;
    	   }

           rsa = d2i_RSA_PUBKEY_bio(key_bio, NULL);

           if(rsa == NULL){
              BIO_free(key_bio);
              return -1;
           }

           BIO_free(key_bio);
       }

   	   SHA1(message, message_length, hash);
   	   res = RSA_verify(NID_sha1, hash, 20, sign, sign_length, rsa);

       RSA_free(rsa);
    }

    if(strcmp(key_type,"DSA")==0){
       if(strcmp(ext_buffer,"PEM") == 0 || strcmp(ext_buffer,"pem") == 0){
   	      free(ext_buffer);
          key_file = fopen(filename,"r");

          if(key_file == NULL)
             return -1;

          dsa = DSA_new();

          if(dsa == NULL){
         	 fclose(key_file);
         	 return -1;
          }

          dsa = PEM_read_DSA_PUBKEY(key_file,&dsa,NULL,NULL);
          if(dsa == NULL){
             fclose(key_file);
         	 return -1;
          }

          fclose(key_file);
       }

       if(strcmp(ext_buffer,"DER") == 0 || strcmp(ext_buffer,"der") == 0){
   	      free(ext_buffer);

     	  key_bio = BIO_new(BIO_s_file());
     	  if(key_bio == NULL)
     	   	 return -1;

     	  res = BIO_read_filename(key_bio,filename);
     	  if(res < 0){
     		 BIO_free(key_bio);
     		 return -1;
     	  }

          dsa = d2i_DSA_PUBKEY_bio(key_bio, NULL);

          if(dsa == NULL){
           	 BIO_free(key_bio);
             return -1;
          }

          BIO_free(key_bio);
       }

       SHA1(message, message_length, hash);
       res = DSA_verify(NID_sha1, hash, 20, sign, sign_length, dsa);

       DSA_free(dsa);
    }

    if(res <= 0)
       return 0;
    else
       return 1;
}

int encrypt_with_public_key_from_file(const char* filename,const char *key_type,const unsigned char *message,unsigned int message_length,unsigned char *encrypted_message,int padding_type){

    int res;

    RSA *rsa;

    BIO *key_bio;
    FILE *key_file;

    char *ext_buffer;

    ext_buffer = calloc(3,sizeof(char));
    memcpy(ext_buffer,filename+strlen(filename)-3,3);

    if(strcmp(key_type,"RSA") != 0){
       free(ext_buffer);
       return -1;
	   
    }else{
       if(strcmp(ext_buffer,"PEM") == 0 || strcmp(ext_buffer,"pem") == 0){
   	      free(ext_buffer);
          key_file = fopen(filename,"r");

          if(key_file == NULL)
        	 return -1;

          rsa = RSA_new();

          if(rsa == NULL){
        	 fclose(key_file);
        	 return -1;
          }

          rsa = PEM_read_RSAPublicKey(key_file,&rsa,NULL,NULL);
          if(rsa == NULL){
        	 fclose(key_file);
        	 return -1;
          }

          fclose(key_file);

       }

       if(strcmp(ext_buffer,"DER") == 0 || strcmp(ext_buffer,"der") == 0){
   	      free(ext_buffer);

    	  key_bio = BIO_new(BIO_s_file());
    	  if(key_bio == NULL)
    	   	 return -1;

    	  res = BIO_read_filename(key_bio,filename);
    	  if(res < 0){
    		 BIO_free(key_bio);
    		 return -1;
    	  }

          rsa = d2i_RSA_PUBKEY_bio(key_bio, NULL);

          if(rsa == NULL){
             BIO_free(key_bio);
             return -1;
          }

          BIO_free(key_bio);
       }

       if(message == NULL){
    	  res = RSA_size(rsa);
          RSA_free(rsa);
          return res;
       }

   	   res = RSA_check_key(rsa);
   	   if(res != 1)
   		  return -1;

       res = RSA_public_encrypt(message_length,message,encrypted_message,rsa,padding_type);

       RSA_free(rsa);

       return res;
    }

}

int decrypt_with_private_key_from_file(const char* filename,const char *key_type,const unsigned char *encrypted_message,unsigned int encrypted_message_length,unsigned char *original_message,int padding_type){

    int res;

    RSA *rsa;

    BIO *key_bio;
	EVP_PKEY *priv_key;
	FILE *key_file;

    char *ext_buffer;

    ext_buffer = calloc(3,sizeof(char));
    memcpy(ext_buffer,filename+strlen(filename)-3,3);

    if(strcmp(key_type,"RSA") != 0){
       free(ext_buffer);
       return -1;

    }else{
       if(strcmp(ext_buffer,"PEM") == 0 || strcmp(ext_buffer,"pem") == 0){
          free(ext_buffer);
		  
          priv_key = EVP_PKEY_new();
   		  if(priv_key == NULL)
   			 return -1;

   		  key_file = fopen(filename, "r");
   		  if(key_file == NULL){
   			 EVP_PKEY_free(priv_key);
   			 return -1;
   		  }

   		  PEM_read_PrivateKey(key_file , &priv_key, NULL, NULL);
          if(priv_key == NULL){
        	 fclose(key_file);
        	 return -1;
          }

   		  fclose(key_file);
   		  rsa = EVP_PKEY_get1_RSA(priv_key);

   		  if(rsa == NULL){
   			 EVP_PKEY_free(priv_key);
   			 return -1;
   		  }

   		  EVP_PKEY_free(priv_key);

       }

       if(strcmp(ext_buffer,"DER") == 0 || strcmp(ext_buffer,"der") == 0){
	      free(ext_buffer);

    	  key_bio = BIO_new(BIO_s_file());
    	  if(key_bio == NULL)
    		 return -1;

    	  res = BIO_read_filename(key_bio,filename);
    	  if(res < 0){
    		 BIO_free(key_bio);
    		 return -1;
    	  }

          rsa = d2i_RSAPrivateKey_bio(key_bio, NULL);
          if(rsa == NULL){
             BIO_free(key_bio);
           	 return -1;
          }

          BIO_free(key_bio);

       }

       if(encrypted_message == NULL){
    	  res = RSA_size(rsa);
          RSA_free(rsa);
          return res;
       }

   	   res = RSA_check_key(rsa);
   	   if(res != 1)
   		  return -1;

       res = RSA_private_decrypt(encrypted_message_length,encrypted_message,original_message,rsa,padding_type);

       RSA_free(rsa);

       return res;
    }

}
