/**
 * @file ecc.c
 * @brief Implementation of standard-compliant, UB-free Error Correcting Code
 * (FEC).
 */

#include "ecc.h"

#include <string.h>

void ecc_compute_parity(const uint8_t** blocks, size_t num_blocks,
                        size_t block_size, uint8_t* out_parity) {
  if (num_blocks == 0 || !blocks || !out_parity) {
    return;
  }

  // Initialize the parity block with the first data block
  memcpy(out_parity, blocks[0], block_size);

  // XOR with the remaining blocks safely byte-by-byte.
  // Modern compilers automatically auto-vectorize this loop (using SSE, AVX, or
  // NEON) without strict aliasing or alignment Undefined Behavior.
  for (size_t b = 1; b < num_blocks; b++) {
    const uint8_t* current_block = blocks[b];
    for (size_t i = 0; i < block_size; i++) {
      out_parity[i] ^= current_block[i];
    }
  }
}

void ecc_reconstruct_block(const uint8_t** blocks, size_t num_healthy_blocks,
                           const uint8_t* parity_block, size_t block_size,
                           uint8_t* out_recovered) {
  if (!out_recovered || !parity_block) {
    return;
  }

  // If there are no other healthy blocks, the recovered block is exactly the
  // parity block
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

int nasfs_ecc_group(uint8_t profile, unsigned* data, unsigned* parity) {
  static const unsigned group_sizes[] = {1, 4, 8, 16, 8};
  if (profile > NASFS_ECC_RS_8) return -1;
  *data = group_sizes[profile];
  *parity = profile == NASFS_ECC_OFF ? 0 : profile == NASFS_ECC_RS_8 ? 2 : 1;
  return 0;
}

/* Reed–Solomon over GF(256), with primitive polynomial x^8+x^4+x^3+x^2+1. */
static uint8_t gf_multiply(unsigned a, unsigned b) {
  unsigned result = 0;
  while (b) {
    if (b & 1u) result ^= a;
    b >>= 1u;
    a = (a << 1u) ^ ((a & 0x80u) ? 0x11du : 0u);
  }
  return (uint8_t)result;
}

static uint8_t gf_inverse(unsigned value) {
  unsigned result = 1;
  for (unsigned power = 254; power; power >>= 1u) {
    if (power & 1u) result = gf_multiply(result, value);
    value = gf_multiply(value, value);
  }
  return (uint8_t)result;
}

static void gf_table(uint8_t table[256], unsigned factor) {
  for (unsigned i = 0; i < 256; ++i) table[i] = gf_multiply(i, factor);
}

void nasfs_ecc_accumulate(uint8_t* p, uint8_t* q, const uint8_t* data,
                          unsigned ordinal, size_t length) {
  for (size_t i = 0; i < length; ++i) p[i] ^= data[i];
  if (q) {
    uint8_t table[256];
    gf_table(table, ordinal + 1u);
    for (size_t i = 0; i < length; ++i) q[i] ^= table[data[i]];
  }
}

int nasfs_ecc_restore(uint8_t* const* data, unsigned count, const uint8_t* p,
                      const uint8_t* q, unsigned target, size_t length,
                      uint8_t* output) {
  if (!data || !output || count > NASFS_ECC_MAX_DATA || target >= count)
    return -1;
  if (data[target]) {
    memcpy(output, data[target], length);
    return 0;
  }
  unsigned missing = 0, other = target;
  for (unsigned i = 0; i < count; ++i) {
    if (!data[i]) {
      missing++;
      if (i != target) other = i;
    }
  }
  if (missing > (unsigned)(p != NULL) + (unsigned)(q != NULL)) return -1;

  if (missing == 1 && p) {
    memcpy(output, p, length);
    for (unsigned row = 0; row < count; ++row) {
      if (data[row]) nasfs_ecc_accumulate(output, NULL, data[row], row, length);
    }
    return 0;
  }

  if (!q || (missing == 2 && !p)) return -1;

  /* Reduce the Q equation and, for two erasures, eliminate the other block. */
  unsigned other_factor = other + 1u;
  uint8_t other_table[256], inverse[256];
  gf_table(other_table, other_factor);
  unsigned divisor = missing == 1 ? target + 1u : (target + 1u) ^ other_factor;
  gf_table(inverse, gf_inverse(divisor));
  memcpy(output, q, length);
  if (missing == 2) {
    for (size_t i = 0; i < length; ++i) output[i] ^= other_table[p[i]];
  }

  for (unsigned row = 0; row < count; ++row) {
    if (!data[row]) continue;
    uint8_t table[256];
    gf_table(table, missing == 1 ? row + 1u : (row + 1u) ^ other_factor);
    for (size_t i = 0; i < length; ++i) output[i] ^= table[data[row][i]];
  }
  for (size_t i = 0; i < length; ++i) output[i] = inverse[output[i]];
  return 0;
}
