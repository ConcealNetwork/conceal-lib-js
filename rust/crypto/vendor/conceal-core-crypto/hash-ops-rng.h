#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>

enum { HASH_DATA_AREA = 136 };

#pragma pack(push, 1)
typedef union {
  uint8_t b[200];
  uint64_t w[25];
} hash_state;
#pragma pack(pop)

void hash_permutation(hash_state *state);
