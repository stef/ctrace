#include "set.h"
#include <string.h>
#include <random/rand32.h>

static unsigned int nth_bit_set(uint32_t value, unsigned int n) {
  // src: https://stackoverflow.com/questions/45482787/how-to-efficiently-find-the-n-th-set-bit
  const uint32_t  pop2  = (value & 0x55555555u) + ((value >> 1) & 0x55555555u);
  const uint32_t  pop4  = (pop2  & 0x33333333u) + ((pop2  >> 2) & 0x33333333u);
  const uint32_t  pop8  = (pop4  & 0x0f0f0f0fu) + ((pop4  >> 4) & 0x0f0f0f0fu);
  const uint32_t  pop16 = (pop8  & 0x00ff00ffu) + ((pop8  >> 8) & 0x00ff00ffu);
  const uint32_t  pop32 = (pop16 & 0x000000ffu) + ((pop16 >>16) & 0x000000ffu);
  unsigned int    rank  = 0;
  unsigned int    temp;

  if (n++ >= pop32) return 32;

  temp = pop16 & 0xffu;
  /* if (n > temp) { n -= temp; rank += 16; } */
  rank += ((temp - n) & 256) >> 4;
  n -= temp & ((temp - n) >> 8);

  temp = (pop8 >> rank) & 0xffu;
  /* if (n > temp) { n -= temp; rank += 8; } */
  rank += ((temp - n) & 256) >> 5;
  n -= temp & ((temp - n) >> 8);

  temp = (pop4 >> rank) & 0x0fu;
  /* if (n > temp) { n -= temp; rank += 4; } */
  rank += ((temp - n) & 256) >> 6;
  n -= temp & ((temp - n) >> 8);

  temp = (pop2 >> rank) & 0x03u;
  /* if (n > temp) { n -= temp; rank += 2; } */
  rank += ((temp - n) & 256) >> 7;
  n -= temp & ((temp - n) >> 8);

  temp = (value >> rank) & 0x01u;
  /* if (n > temp) rank += 1; */
  rank += ((temp - n) & 256) >> 8;

  return rank;
}

static int logbase2(uint32_t v) { // find the log base 2 of 32-bit v
   static const int MultiplyDeBruijnBitPosition[32] = {
      0, 9, 1, 10, 13, 21, 2, 29, 11, 14, 16, 18, 22, 25, 3, 30,
      8, 12, 20, 28, 15, 17, 24, 7, 19, 27, 23, 6, 26, 5, 4, 31
   };

   v |= v >> 1; // first round down to one less than a power of 2
   v |= v >> 2;
   v |= v >> 4;
   v |= v >> 8;
   v |= v >> 16;

   return MultiplyDeBruijnBitPosition[(uint32_t)(v * 0x07C4ACDDU) >> 27];
}

static int cntbits(uint32_t v) { // count bits set in this (32-bit value)
   uint32_t c; // store the total here
   static const int S[] = {1, 2, 4, 8, 16}; // Magic Binary Numbers
   static const int B[] = {0x55555555, 0x33333333, 0x0F0F0F0F, 0x00FF00FF, 0x0000FFFF};

   c = v - ((v >> 1) & B[0]);
   c = ((c >> S[1]) & B[1]) + (c & B[1]);
   c = ((c >> S[2]) + c) & B[2];
   c = ((c >> S[3]) + c) & B[3];
   c = ((c >> S[4]) + c) & B[4];

   return c;
}

void init_set(ephids_set *set) {
  set->size = DP3T_EPIDS_PER_DAY;
  set->cap = DP3T_EPIDS_PER_DAY;
  memset(set->limbs, 0xffffffff, sizeof set->limbs);
  set->limbs[DP3T_EPIDS_PER_DAY/32]&= ~(~0u << (DP3T_EPIDS_PER_DAY%32));
}

static int fetch(ephids_set *ephids, const uint32_t n) {
  if(n>ephids->size) return -1;
  uint32_t i, c0=0, c1=0;
  for(i=0;i<ephids->cap/32+1;i++) {
    c1+=cntbits(ephids->limbs[i]);
    if(c1>n) break;
    c0 = c1;
  }
  int j= nth_bit_set(ephids->limbs[i], n-c0);
  if(j==32) {
    //printf("size: %ld, n: %d, n-c0: %d, i: %d, limb: %x\n", ephids->size, n, n-c0, i, ephids->limbs[i]);
    return -1;
  }
  ephids->limbs[i]&=~(1<<j);
  return i*32+j;
}

static int _rand(const unsigned max) {
  uint32_t tmp=0xffffffff,
    log2max = logbase2(max),
    mask = ~(~0 << log2max);
  while(tmp>=max) {
    sys_csrand_get(&tmp,sizeof tmp);
    tmp &= mask;
  }
  return tmp;
}

int nextid(ephids_set *ephids) {
  int res = fetch(ephids, _rand(ephids->size));
  ephids->size--;
  return res;
}

