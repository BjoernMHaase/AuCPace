// Reference implementation and associated test code for CPace and AuCPace
// Author Björn Haase
//
// Public Domain

#include "tweetnacl.h"
#include <stdio.h>
#include <assert.h>
#include <inttypes.h>
#include <string.h>
#include "AuCPace25519.h"

// Just for test purposes. Needed for linking.
int randombytes(uint8_t *where,uint64_t size)
{
	assert(0);	
}

void printLongInt(const unsigned char *data, const int len)
{
    int i;
    printf ("0x");
    for (i = 0; i < len; i ++)
    {
        printf("%02x", (int) data[len - 1 - i]);
    }
}

// ######################################################
//
// Tests for the elligator
//
// ######################################################

const uint8_t EllTestCase1_in[] = {
 0xbc,0x14,0x9a,0x46,0xd2,0x93,0xb0,0xae,0xea,0x34,0x58,0x13,0x49,0xd7,0x2f,0x8a,0x5a,0x96,0xcd,0x53,0x11,0x2,0xd6,0x73,0x79,0xcd,0x9b,0xfa,0xdd,0x4e,0xc8,0x0,
};

const uint8_t EllTestCase1_out[] = {
 0x66,0xb6,0x8f,0x75,0x75,0xcd,0x28,0x24,0x3,0xfc,0x2b,0xd3,0x23,0xff,0x4,0x60,0x12,0x3,0xc1,0xec,0x55,0x16,0xce,0x24,0x7f,0x7c,0xa,0xdb,0xef,0x5,0xd3,0x67,
};
const uint8_t EllTestCase2_in[] = {
 0x89,0xcf,0x55,0xd4,0xb5,0xd3,0xf8,0x4b,0x16,0x34,0x95,0x7a,0xc5,0x3,0xa3,0x2b,0x84,0xba,0x11,0x47,0x1a,0x96,0xb2,0x27,0xbc,0xa7,0xa,0xc,0x3b,0xf2,0x63,0x75,
};
const uint8_t EllTestCase2_out[] = {
 0x1d,0xb1,0x63,0xc8,0x6c,0xec,0xa7,0x62,0x19,0x3,0xc9,0x41,0x2d,0x6d,0xc7,0x1b,0x4e,0xd2,0x63,0xb6,0x87,0xee,0xd0,0x92,0xb1,0x94,0xb5,0xe5,0x40,0xbb,0xa3,0x8,
};

const uint8_t EllTestCase3_in[] = {
 0xbf,0x60,0x87,0x60,0x92,0x15,0x2,0xc2,0x52,0xa3,0xf7,0xb2,0xd8,0xb1,0xfb,0x75,0x4c,0x7c,0x96,0xd6,0x7a,0x7b,0x49,0x30,0xf3,0xa8,0xbe,0xa7,0x82,0xd6,0x9e,0x5a,0xfa,0x55,0x2f,0x88,0xe5,0xb4,0xef,0x7a,0xa2,0x61,0xf5,0xbf,0x1a,0xc0,0xd4,0x82,0x33,0x1,0x70,0x2f,0x1d,0x44,0x18,0x19,0xa0,0xd9,0x47,0x10,0x19,0x4a,0xd1,0x64,
};
const uint8_t EllTestCase3_out[] = {
 0x5a,0x44,0xea,0xd4,0xc9,0x6,0xcd,0x9e,0xe0,0x43,0xc4,0xee,0x87,0xfe,0xc8,0x56,0xe3,0xb7,0x20,0x3c,0x62,0x17,0x8,0x55,0x6c,0xf9,0x6b,0xd5,0x64,0x7c,0x3a,0x20,
};

void testElligator2()
{
    printf ("Testing elligator2.\n");

    uint8_t result_tc1[32];
    uint8_t result_tc2[32];
    uint8_t result_tc3[32];

    crypto_elligator2(result_tc1, EllTestCase1_in,32);

    printf ("Input first test case:\n");
    printLongInt (EllTestCase1_in,32);

    printf ("\nResult first test case:\n");
    printLongInt (result_tc1,32);
    printf ("\nExpected result:\n");
    printLongInt (EllTestCase1_out,32);
    printf ("\n");
    if (0 == memcmp(result_tc1,EllTestCase1_out,32))
      printf ("PASS.\n");
    else
      printf ("FAIL.\n");

    crypto_elligator2(result_tc2, EllTestCase2_in,32);

    printf ("\nInput second test case:\n");
    printLongInt (EllTestCase1_in,32);

    printf ("\nResult second test case:\n");
    printLongInt (result_tc2,32);
    printf ("\nExpected result:\n");
    printLongInt (EllTestCase2_out,32);
    printf ("\n");

    if (0 == memcmp(result_tc2,EllTestCase2_out,32))
      printf ("PASS.\n");
    else
      printf ("FAIL.\n");


    crypto_elligator2(result_tc3, EllTestCase3_in,64);

    printf ("\nInput third test case:\n");
    printLongInt (EllTestCase3_in,64);

    printf ("\nResult third test case:\n");
    printLongInt (result_tc3,32);
    printf ("\nExpected result:\n");
    printLongInt (EllTestCase3_out,32);
    printf ("\n");

    if (0 == memcmp(result_tc3,EllTestCase3_out,32))
      printf ("PASS.\n");
    else
      printf ("FAIL.\n");
}

// ######################################################
//
// Tests for X25519 and the inverse X25519
//
// ######################################################

const uint8_t tc_Z[] = {
 0x4b,0x7f,0x53,0x6b,0x82,0x16,0x89,0xf,0xbb,0xbb,0xdf,0x16,0xc5,0x14,0xac,0x53,0x6b,0x4,0xf6,0xbc,0x89,0xc7,0x27,0xb5,0x43,0x4a,0x6d,0x4c,0x1e,0x68,0x1,0x3c,
};
const uint8_t tc_r[] = {
 0xa8,0x82,0xf0,0xac,0x84,0x8b,0xb,0x6b,0x4c,0xa7,0xb4,0x2b,0xfa,0x1d,0x26,0x6a,0xfd,0xd,0xde,0xba,0x92,0x4,0xae,0x57,0xa9,0x84,0xa6,0x93,0x76,0xd5,0x98,0x56,
};
const uint8_t tc_U[] = {
 0x77,0xa9,0x86,0x73,0xa9,0xeb,0x77,0x14,0x12,0x66,0x16,0x97,0x1,0x57,0x70,0x8,0xd8,0x60,0x30,0x32,0x16,0x83,0x2f,0x12,0xa6,0x74,0xd9,0xfb,0x58,0xa0,0xf2,0xa,
};
const uint8_t tc_q[] = {
 0x28,0x96,0x77,0x22,0x32,0x48,0x7f,0xb3,0xa0,0x58,0xd5,0x8f,0x2c,0x31,0x0,0x23,0xe0,0x7e,0x40,0x17,0xc9,0x4d,0x56,0xcc,0x5f,0xae,0x4b,0x54,0xb4,0x46,0x5,0x74,
};
const uint8_t tc_UQ[] = {
 0xb5,0x6c,0xe,0xe7,0x2b,0x7a,0xa7,0x60,0x55,0xf6,0x95,0x9d,0x64,0x87,0x76,0xfe,0x1b,0xfa,0xf8,0xe0,0x57,0xc0,0xde,0x7a,0x5b,0xb,0x54,0xff,0xda,0x70,0x2,0x61,
};
const uint8_t tc_ZQ[] = {
 0x50,0x9a,0x3a,0x7c,0xf,0xa3,0xc0,0xd6,0xfe,0x7f,0x33,0x3f,0xd1,0x3f,0x73,0x90,0x6b,0x45,0x29,0xc1,0x9,0x4c,0x4a,0x4d,0xe1,0x58,0xd9,0xca,0x19,0x28,0x41,0x77,
};

void test_X25519()
{
    printf ("Testing X25519 and strong AuCPace salt blinding.\n");

    uint8_t result_Z[32];
    uint8_t result_U[32];
    uint8_t result_UQ[32];
    uint8_t result_ZQ[32];


    map_to_group_mod_neg_StrongAuCPace25519(result_Z,
      "username", 8, "password", 8);

    if (0 == memcmp(result_Z,tc_Z,32))
      printf ("PASS.\n");
    else
      printf ("FAIL.\n");

    crypto_scalarmult(result_U,tc_r,tc_Z);
    crypto_scalarmult(result_UQ,tc_q,tc_U);
    crypto_inverse_scalarmult(result_ZQ,tc_r,tc_UQ);

    if (0 == memcmp(result_U,tc_U,32))
      printf ("PASS.\n");
    else
      printf ("FAIL.\n");

    if (0 == memcmp(result_UQ,tc_UQ,32))
      printf ("PASS.\n");
    else
      printf ("FAIL.\n");

    printf ("Testing inverse X25519.\n");

    if (0 == memcmp(result_ZQ,tc_ZQ,32))
      printf ("PASS.\n");
    else
      printf ("FAIL.\n");
}

// ######################################################
//
// Tests for AuCPace and CPace
//
// ######################################################

const uint8_t tc_G[] = {
 0xc4,0xe,0xe0,0x76,0xcf,0xb7,0xa1,0xfd,0x47,0x54,0x5a,0x6,0x41,0x5a,0x10,0x91,0x89,0xda,0x47,0x5b,0xcb,0x4d,0xd6,0x63,0xf1,0x14,0xd6,0x49,0x71,0xa2,0xbf,0x41,
};
const uint8_t tc_ya[] = {
 0xd0,0x22,0xb7,0x98,0xe3,0xbe,0x24,0x97,0xd5,0x5,0xd1,0x0,0xe4,0x54,0xd,0xe4,0x3f,0xdf,0xa,0xeb,0xa9,0xeb,0xa3,0x75,0x42,0x99,0x44,0x41,0x33,0x93,0xec,0x7f,
};
const uint8_t tc_Ya[] = {
 0xea,0x1a,0x2b,0xc0,0xaa,0xd5,0x38,0x76,0x16,0x1,0xe3,0xa1,0x9e,0xe6,0x94,0x3b,0xf8,0x8b,0xc,0x98,0x1b,0x4b,0xfb,0x6d,0x8c,0x73,0x77,0xf9,0x1c,0xc8,0x4e,0x8,
};
const uint8_t tc_yb[] = {
 0xc0,0xec,0xc,0xd6,0x84,0x32,0x5,0x3c,0xcd,0x6f,0xd4,0xd6,0x4a,0x8,0x20,0x3e,0x8b,0xf2,0xb1,0x3c,0x49,0x58,0x90,0xb5,0x4c,0x87,0xaf,0xfc,0xf3,0x6f,0x6a,0x71,
};
const uint8_t tc_Yb[] = {
 0x5d,0x6e,0x6b,0xd7,0xad,0x8a,0x5c,0xc4,0xfb,0xb0,0xfa,0x8e,0x76,0x63,0x1c,0x91,0x45,0x49,0xe5,0x62,0x75,0x2d,0xf8,0xd2,0x8c,0xd6,0x9,0xa9,0xf,0x35,0xc7,0x29,
};
const uint8_t tc_K[] = {
 0xdc,0x70,0xf,0x2b,0x7e,0xce,0x7a,0x34,0xab,0xcf,0x91,0x3f,0x1e,0xea,0x23,0x36,0x9f,0x5c,0x94,0x3d,0xca,0xd0,0xe3,0x42,0xc6,0x2b,0x2c,0x1a,0x8f,0xee,0x72,0x51,
};
const uint8_t tc_ISK[] = {
 0xc4,0x11,0xe7,0xa6,0xd9,0xbd,0x29,0x18,0x46,0x3a,0x9e,0xb3,0x7e,0x59,0x2f,0x39,0xaf,0xf7,0x20,0xe6,0xaf,0xa0,0x32,0xa9,0x24,0xd5,0x64,0xdc,0x2,0x20,0x29,0x86,0x34,0xd4,0x1c,0xb7,0x31,0x33,0xed,0xb9,0x28,0x10,0x92,0xff,0xc4,0x23,0x2b,0xc8,0x2,0x6a,0x6,0x4,0xbf,0x7f,0x69,0x69,0xef,0xcb,0x67,0xee,0xfc,0x9,0x80,0xb6,
};

void test_CPace()
{
    uint8_t result_G[32];
    uint8_t result_Ya[32];
    uint8_t result_Yb[32];
    uint8_t result_K[32];
    uint8_t result_ISK[64];

    const uint8_t sid[] = {0x7e,0x4b,0x47,0x91,0xd6,0xa8,0xef,0x01,0x9b,0x93,0x6c,0x79,0xfb,0x7f,0x2c,0x57};
    int len_sid = 16;
    const uint8_t PRS[] = "password";
    int len_PRS = 8;
    const uint8_t CI[] = "AinitiatorBresponderAD";
    int len_CI = 22;
    int result=map_to_group_mod_neg_CPace25519(
     result_G, 
     sid, len_sid,
     PRS, len_PRS,
     CI, len_CI);

    printf ("Testing CPace test vectors.\n");

    if (0 == memcmp(result_G,tc_G,32))
      printf ("PASS.\n");
    else
      printf ("FAIL.\n");

    crypto_scalarmult(result_Ya,tc_ya,result_G);
    if (0 == memcmp(result_Ya,tc_Ya,32))
      printf ("PASS.\n");
    else
      printf ("FAIL.\n");

    crypto_scalarmult(result_Yb,tc_yb,result_G);
    if (0 == memcmp(result_Yb,tc_Yb,32))
      printf ("PASS.\n");
    else
      printf ("FAIL.\n");

    crypto_scalarmult(result_K,tc_yb,result_Ya);
    if (0 == memcmp(result_K,tc_K,32))
      printf ("PASS.\n");
    else
    {
         printf ("\nExpected result for K:\n");
         printLongInt (tc_K,32);
         printf ("\nOur result for K:\n");
         printLongInt (result_K,32);
         printf ("\nFAIL.\n");
    }
    
    crypto_scalarmult(result_K,tc_ya,result_Yb);
    if (0 == memcmp(result_K,tc_K,32))
      printf ("PASS.\n");
    else
    {
         printf ("\nExpected result for K:\n");
         printLongInt (tc_K,32);
         printf ("\nOur result for K:\n");
         printLongInt (result_K,32);
         printf ("\nFAIL.\n");
    }

    KDF_CPace25519(result_ISK,
     sid, len_sid,
     result_K,result_Ya,result_Yb);

    if (0 == memcmp(result_ISK,tc_ISK,64))
      printf ("PASS.\n");
    else
    {
         printf ("\nExpected result for ISK:\n");
         printLongInt (tc_ISK,64);
         printf ("\nOur result for ISK:\n");
         printLongInt (result_ISK,64);
         printf ("\nFAIL.\n");
    }
}

const uint8_t tc_w[] = {
 0xf2,0xb5,0x4e,0x73,0x25,0xa1,0xa4,0xfd,0xc8,0x8a,0x78,0x99,0xcf,0xe6,0x8a,0xee,0x41,0xeb,0xda,0x41,0x45,0xba,0x93,0x48,0xb,0xc2,0x95,0xc8,0x4a,0x8,0x32,0xd8,
};
const uint8_t tc_X[] = {
 0x8f,0x6b,0x81,0xee,0x23,0xd7,0x0,0xa0,0x78,0x3a,0xc1,0x6b,0xcc,0x3c,0xfb,0x62,0xf2,0xbc,0x7f,0xf8,0xda,0xed,0x28,0x59,0x77,0xa6,0x34,0xee,0x30,0xba,0x81,0x75,
};
const uint8_t tc_WX[] = {
 0xd7,0xaf,0x82,0x26,0xe6,0x87,0xdb,0xb2,0x13,0x6b,0x7a,0x53,0x58,0x9f,0x27,0x44,0x8f,0x11,0x36,0xc0,0xc,0x2e,0xd8,0xfb,0xc9,0xb1,0xd3,0x89,0x16,0xae,0x97,0x3e,
};

const uint8_t tc_ISK_test2[] = {
 0xfe,0x59,0x61,0x20,0x2d,0xb9,0x95,0xf8,0xc5,0xd4,0x78,0xa6,0x9,0x5f,0x11,0xb2,0xb3,0xeb,0x96,0xc5,0xcd,0x4,0x4f,0x6f,0xdf,0xfb,0xab,0x6e,0xe6,0xea,0x43,0x92,0xd1,0x33,0x55,0xe4,0xa4,0xb1,0x25,0x86,0x10,0x29,0x46,0x62,0x25,0xb8,0xcd,0x8d,0x3,0xc4,0xd5,0xda,0x78,0x8a,0x99,0x5c,0xc0,0x1d,0xb2,0x9a,0xc2,0x63,0xda,0x20,
};

const uint8_t tc_Ta[] = {
 0xbb,0xfb,0xae,0x57,0x2a,0xc1,0xef,0x86,0x9,0xbe,0x3d,0x2f,0x70,0xc,0xef,0x39,
};
const uint8_t tc_Tb[] = {
 0xde,0xd8,0x49,0x68,0x5e,0x96,0x38,0x95,0x82,0x58,0x2c,0x5b,0x8e,0xe,0x84,0x73,
};
const uint8_t tc_SK[] = {
 0x4f,0x4a,0xee,0x2d,0x83,0x8f,0xe6,0xdd,0x4f,0x96,0xb6,0xb6,0xe9,0x93,0xc4,0x3f,0x87,0x6d,0x64,0x10,0x50,0xc8,0xf1,0xfa,0xcd,0x8f,0x44,0x21,0xc9,0x3a,0xcf,0x55,0x95,0xdf,0xa9,0x48,0xf0,0xc6,0x66,0x1,0xe6,0x54,0xfa,0x59,0x62,0x6,0x56,0x5b,0xf4,0x5d,0x32,0x46,0x52,0x76,0xd2,0x12,0x6f,0xba,0x33,0x4a,0x38,0x35,0xeb,0x48,
};

void test_AuCPace()
{
   uint8_t result_w[32];
   uint8_t result_W[32];
   uint8_t result_PRS[32];
   uint8_t result_Ta[16];
   uint8_t result_Tb[16];
   uint8_t result_SK[64];

   AuCPace_Client_derive_w(result_w, 
      "username", 8, "password", 8,
      tc_ZQ, 32);

   AuCPace_Client_derive_WX(result_PRS,
      result_w, tc_X);

   if (0 == memcmp(result_w,tc_w,32))
      printf ("PASS.\n");
   else
   {
         printf ("\nExpected result for w:\n");
         printLongInt (tc_w,32);
         printf ("\nOur result for w:\n");
         printLongInt (result_w,32);
         printf ("\nFAIL.\n");
   }

   if (0 == memcmp(result_PRS,tc_WX,32))
      printf ("PASS.\n");
   else
   {
         printf ("\nExpected result for WX:\n");
         printLongInt (tc_WX,32);
         printf ("\nOur result for WX:\n");
         printLongInt (result_PRS,32);
         printf ("\nFAIL.\n");
   }

   AuCPace_derive_Ta_Tb_SK (result_Ta,result_Tb,result_SK,tc_ISK_test2);

   if (0 == memcmp(result_Ta,tc_Ta,16))
      printf ("PASS.\n");
   else
   {
         printf ("\nExpected result for Ta:\n");
         printLongInt (tc_Ta,16);
         printf ("\nOur result for Ta:\n");
         printLongInt (result_Ta,16);
         printf ("\nFAIL.\n");
   }

   if (0 == memcmp(result_Tb,tc_Tb,16))
      printf ("PASS.\n");
   else
   {
         printf ("\nExpected result for Tb:\n");
         printLongInt (tc_Tb,16);
         printf ("\nOur result for Tb:\n");
         printLongInt (result_Tb,16);
         printf ("\nFAIL.\n");
   }

   if (0 == memcmp(result_SK,tc_SK,64))
      printf ("PASS.\n");
   else
   {
         printf ("\nExpected result for SK:\n");
         printLongInt (tc_SK,64);
         printf ("\nOur result for SK:\n");
         printLongInt (result_SK,64);
         printf ("\nFAIL.\n");
   }

}

int main ()
{
    printf ("Starting tests.\n\n");

    testElligator2();
    test_X25519();
    test_CPace();
    test_AuCPace();
}

