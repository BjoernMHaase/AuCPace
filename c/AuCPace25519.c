// Reference implementation and associated test code for CPace and AuCPace
// Author Björn Haase
//
// Public Domain


#include <string.h>
#include "tweetnacl.h"
#include "AuCPace25519.h"

// For scrypt
#include "crypto/crypto_scrypt.h"

#define HASH_BUFFER_SIZE (512)

int map_to_group_mod_neg_CPace25519(unsigned char *G, 
                                    const unsigned char *sid, unsigned int len_sid,
                                    const unsigned char *PRS, unsigned int len_PRS,
                                    const unsigned char *CI, unsigned int len_CI)
{
   const char *DSI1 = "CPace25519-1";
   const int len_dsi1 = 12;
   int len_zpad = 128 - len_dsi1 - len_PRS;
   int len_total;
   char hashResult[64];
   
   if (len_zpad < 0)
   {
      len_zpad = 0;
   }

   len_total = len_dsi1 + len_PRS + len_sid + len_zpad + len_CI;
   if (len_total > HASH_BUFFER_SIZE)
      return 1;

   {
       char hashBuffer[HASH_BUFFER_SIZE];
       char *ptr = hashBuffer;
       memcpy(ptr,DSI1,len_dsi1); ptr+=len_dsi1;
       memcpy(ptr,PRS,len_PRS); ptr+=len_PRS;
       memset(ptr,0,len_zpad); ptr+=len_zpad;
       memcpy(ptr,sid,len_sid); ptr+=len_sid;
       memcpy(ptr,CI,len_CI);
       crypto_hash(hashResult,hashBuffer,len_total);
   }

   crypto_elligator2(G, hashResult,64);
   return 0;
}

int KDF_CPace25519(unsigned char *ISK,
   const unsigned char *sid, unsigned int len_sid,
   const unsigned char K[32],
   const unsigned char Ya[32],
   const unsigned char Yb[32])
{
   const char *DSI2 = "CPace25519-2";
   const int len_dsi2 = 12;
   int len_total;

   len_total = len_dsi2 + len_sid + 3 * 32;
   if (len_total > HASH_BUFFER_SIZE)
   {
      randombytes (ISK,64);
      return 1;
   }

   {
       char hashBuffer[HASH_BUFFER_SIZE];
       char *ptr = hashBuffer;
       memcpy(ptr,DSI2,len_dsi2); ptr+=len_dsi2;
       memcpy(ptr,sid,len_sid); ptr+=len_sid;
       memcpy(ptr,K,32); ptr+=32;
       memcpy(ptr,Ya,32); ptr+=32;
       memcpy(ptr,Yb,32); ptr+=32;
       crypto_hash(ISK,hashBuffer,len_total);
   }
   return 0;
}


int map_to_group_mod_neg_StrongAuCPace25519(unsigned char *Z,
   const char *username, unsigned int len_username,
   const char *password, unsigned int len_password)
{
   const char *DSI = "AuCPace25519"; int len_dsi = 12;
   int len_zpad = 128 - len_dsi - len_password;
   int len_total;
   char hashResult[64];
   
   if (len_zpad < 0)
   {
      len_zpad = 0;
   }

   len_total = len_dsi + len_password + len_zpad + len_username;
   if (len_total > HASH_BUFFER_SIZE)
      return 1;

   {
       char hashBuffer[HASH_BUFFER_SIZE];
       char *ptr = hashBuffer;
       memcpy(ptr,DSI,len_dsi); ptr+=len_dsi;
       memcpy(ptr,password,len_password); ptr+=len_password;
       memset(ptr,0,len_zpad); ptr+=len_zpad;
       memcpy(ptr,username,len_username);
       crypto_hash(hashResult,hashBuffer,len_total);
   }

   crypto_elligator2(Z, hashResult,64);
   return 0;
}

int AuCPace_Client_derive_w(char *w, 
   const char *username, unsigned int len_username,
   const char *password, unsigned int len_password,
   const char *salt, unsigned int len_salt)
{
    char buffer_up[128];

    unsigned int len_total = len_password + len_username;
    if (len_total > sizeof(buffer_up))
      return 1;

    memcpy(&buffer_up[0],password,len_password);
    memcpy(&buffer_up[len_password],username,len_username);

    unsigned char buff[2] = {0x50, 0x51};

    crypto_scrypt(buffer_up, len_total,
                   salt, len_salt,
                   1<<15, //N 
                   8, // r
                   1, // p
                   w, 32);
}

int AuCPace_Client_derive_WX(char *WX,
   const char *w, const char *X)
{
    crypto_scalarmult(WX,w,X);
    return 0;
}


int AuCPace_derive_Ta_Tb_SK (char Ta[16], char Tb[16], char SK[64],const char *ISK)
{
    char *DSI3 = "AuCPace25-Ta";
    char *DSI4 = "AuCPace25-Tb";
    char *DSI5 = "AuCPace25519";
    const int len_dsi = 12;
    const int len_ISK = 64;
    char hashResult[64];

    char hashBuffer[len_dsi + 64];
    int len_total = len_dsi + 64;

    memcpy(hashBuffer,DSI3,len_dsi);
    memcpy(&hashBuffer[len_dsi],ISK,len_ISK);
    crypto_hash(hashResult,hashBuffer,len_total);
    memcpy(Ta,&hashResult,16);

    memcpy(hashBuffer,DSI4,len_dsi);
    memcpy(&hashBuffer[len_dsi],ISK,len_ISK);
    crypto_hash(hashResult,hashBuffer,len_total);
    memcpy(Tb,&hashResult,16);

    memcpy(hashBuffer,DSI5,len_dsi);
    memcpy(&hashBuffer[len_dsi],ISK,len_ISK);
    crypto_hash(SK,hashBuffer,len_total);
}

