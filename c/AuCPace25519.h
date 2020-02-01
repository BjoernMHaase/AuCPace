#ifndef AUCPACE_HEADER_
#define AUCPACE_HEADER_

extern int randombytes (unsigned char *,unsigned long);

extern int map_to_group_mod_neg_CPace25519(
     unsigned char *G, 
     const unsigned char *sid, unsigned int len_sid,
     const unsigned char *PRS, unsigned int len_PRS,
     const unsigned char *CI, unsigned int len_CI);

extern int KDF_CPace25519(unsigned char *ISK,
   const unsigned char *sid, unsigned int len_sid,
   const unsigned char K[32],
   const unsigned char Ya[32],
   const unsigned char Yb[32]);

#endif
