/* Compile crypto-ops.c for wasm32 with renamed globals that collide with wasm-bindgen exports. */
#define sc_0 conceal_ops_sc_0
#define sc_reduce32 conceal_ops_sc_reduce32
#define sc_add conceal_ops_sc_add
#define sc_sub conceal_ops_sc_sub
#define sc_mulsub conceal_ops_sc_mulsub
#define sc_check conceal_ops_sc_check
#define ge_scalarmult_base conceal_ops_ge_scalarmult_base
#define ge_scalarmult conceal_ops_ge_scalarmult
#define ge_mul8 conceal_ops_ge_mul8
#define ge_add conceal_ops_ge_add
#define ge_tobytes conceal_ops_ge_tobytes
#define ge_frombytes_vartime conceal_ops_ge_frombytes_vartime
#define ge_p3_tobytes conceal_ops_ge_p3_tobytes
#define ge_frombytes_vartime conceal_ops_ge_frombytes_vartime
#define ge_double_scalarmult_base_vartime conceal_ops_ge_double_scalarmult_base_vartime
#define ge_double_scalarmult_precomp_vartime conceal_ops_ge_double_scalarmult_precomp_vartime
#define ge_dsm_precomp conceal_ops_ge_dsm_precomp
#define sc_reduce conceal_ops_sc_reduce
#define sc_reduce32 conceal_ops_sc_reduce32
#define sc_add conceal_ops_sc_add
#define sc_sub conceal_ops_sc_sub
#define sc_mulsub conceal_ops_sc_mulsub
#define sc_check conceal_ops_sc_check
#define sc_isnonzero conceal_ops_sc_isnonzero

#include "crypto-ops.c"
