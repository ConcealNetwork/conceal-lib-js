#include "hash-ops-rng.h"
#include "keccak.h"

void hash_permutation(hash_state *state) {
  keccakf((uint64_t *)state, 24);
}
