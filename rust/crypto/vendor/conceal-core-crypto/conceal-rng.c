#include <stddef.h>
#include <string.h>

#include "hash-ops-rng.h"

static hash_state state;

void conceal_rng_seed_test(void) {
  memset(&state, 42, sizeof(state));
}

void conceal_rng_seed_bytes(const uint8_t *seed, size_t len) {
  memset(&state, 0, sizeof(state));
  if (len > sizeof(state)) {
    len = sizeof(state);
  }
  memcpy(&state, seed, len);
}

void conceal_rng_fill(uint8_t *result, size_t n) {
  if (n == 0) {
    return;
  }
  for (;;) {
    hash_permutation(&state);
    if (n <= HASH_DATA_AREA) {
      memcpy(result, &state, n);
      return;
    }
    memcpy(result, &state, HASH_DATA_AREA);
    result += HASH_DATA_AREA;
    n -= HASH_DATA_AREA;
  }
}
