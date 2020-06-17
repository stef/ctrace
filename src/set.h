#ifndef set_h
#define set_h

#include <stdint.h>
#include <stdlib.h>
#include "dp3t.h"

typedef struct {
  uint32_t limbs[DP3T_EPIDS_PER_DAY/32+1];
  size_t size;
  size_t cap;
} ephids_set;

void init_set(ephids_set *set);
int nextid(ephids_set *ephids);

#endif // set_h
