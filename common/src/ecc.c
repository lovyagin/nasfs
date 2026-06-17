/**
 * @file ecc.c
 * @brief Implementation of standard-compliant, UB-free Error Correcting Code (FEC).
 */

#include "ecc.h"
#include <string.h>

void ecc_compute_parity(const uint8_t** blocks, size_t num_blocks, size_t block_size, uint8_t* out_parity) {
  if (num_blocks == 0 || !blocks || !out_parity) {
    return;
  }

  // Initialize the parity block with the first data block
  memcpy(out_parity, blocks[0], block_size);

  // XOR with the remaining blocks safely byte-by-byte.
  // Modern compilers automatically auto-vectorize this loop (using SSE, AVX, or NEON)
  // without strict aliasing or alignment Undefined Behavior.
  for (size_t b = 1; b < num_blocks; b++) {
    const uint8_t* current_block = blocks[b];
    for (size_t i = 0; i < block_size; i++) {
      out_parity[i] ^= current_block[i];
    }
  }
}

void ecc_reconstruct_block(const uint8_t** blocks, size_t num_healthy_blocks, const uint8_t* parity_block, size_t block_size, uint8_t* out_recovered) {
  if (!out_recovered || !parity_block) {
    return;
  }

  // If there are no other healthy blocks, the recovered block is exactly the parity block
  if (num_healthy_blocks == 0 || !blocks) {
    memcpy(out_recovered, parity_block, block_size);
    return;
  }

  // Initialize recovery block with parity block
  memcpy(out_recovered, parity_block, block_size);

  // XOR with all other healthy blocks safely
  for (size_t b = 0; b < num_healthy_blocks; b++) {
    const uint8_t* current_block = blocks[b];
    for (size_t i = 0; i < block_size; i++) {
      out_recovered[i] ^= current_block[i];
    }
  }
}
