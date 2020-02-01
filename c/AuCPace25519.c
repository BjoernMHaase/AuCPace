#include <string.h>
#include "tweetnacl.h"
#include "AuCPace25519.h"

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

