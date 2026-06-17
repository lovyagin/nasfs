/**
 * @file test_ecc.c
 * @brief Unit tests for NASFS XOR Parity Block Error Correcting Code (FEC).
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ecc.h"

int main(void) {
  printf("Starting ECC unit tests...\n");

  size_t block_size = 65536;  // 64 KB block size, matching NASFS block size
  size_t num_blocks = 4;      // Let's have 4 blocks of data

  // Allocate memory for blocks
  uint8_t** original_blocks = malloc(num_blocks * sizeof(uint8_t*));
  uint8_t** healthy_blocks = malloc((num_blocks - 1) * sizeof(uint8_t*));
  uint8_t* parity_block = malloc(block_size);
  uint8_t* reconstructed_block = malloc(block_size);

  if (!original_blocks || !healthy_blocks || !parity_block ||
      !reconstructed_block) {
    fprintf(stderr, "Memory allocation failed\n");
    return 1;
  }

  // Populate data blocks with some mock data (different contents)
  for (size_t b = 0; b < num_blocks; b++) {
    original_blocks[b] = malloc(block_size);
    if (!original_blocks[b]) {
      return 1;
    }
    for (size_t i = 0; i < block_size; i++) {
      original_blocks[b][i] = (uint8_t)((b * 17 + i * 3) & 0xFF);
    }
  }

  // Compute the XOR Parity block (RAID-5 style FEC)
  ecc_compute_parity((const uint8_t**)original_blocks, num_blocks, block_size,
                     parity_block);

  // Demonstrate corruption: we "lose" or corrupt block index 1
  size_t corrupted_index = 1;
  uint8_t* corrupted_block_backup = malloc(block_size);
  memcpy(corrupted_block_backup, original_blocks[corrupted_index], block_size);

  // Introduce silent data corruption (bit rot) by flipping a bit in block 1
  original_blocks[corrupted_index][1024] ^= 0x40;  // Flip 6th bit

  // Check if it is different
  if (memcmp(original_blocks[corrupted_index], corrupted_block_backup,
             block_size) == 0) {
    fprintf(stderr, "Error: Corruption induction failed\n");
    return 1;
  }
  printf("Successfully simulated data corruption (bit rot) in Block %zu.\n",
         corrupted_index);

  // Reconstruct the corrupted block using parity and other healthy blocks
  // Prepare array of healthy blocks (excluding block 1)
  size_t h_idx = 0;
  for (size_t b = 0; b < num_blocks; b++) {
    if (b != corrupted_index) {
      healthy_blocks[h_idx++] = original_blocks[b];
    }
  }

  // Run the reconstruction
  ecc_reconstruct_block((const uint8_t**)healthy_blocks, num_blocks - 1,
                        parity_block, block_size, reconstructed_block);

  // Verify that the reconstructed block is exactly the same as the original
  // uncorrupted block 1
  if (memcmp(reconstructed_block, corrupted_block_backup, block_size) != 0) {
    fprintf(stderr,
            "ECC Error: Reconstructed block does not match the original "
            "uncorrupted data!\n");
    return 1;
  }

  printf(
      "ECC Success: Block %zu was reconstructed perfectly from XOR parity!\n",
      corrupted_index);

  // Clean up
  free(corrupted_block_backup);
  for (size_t b = 0; b < num_blocks; b++) {
    free(original_blocks[b]);
  }
  free(original_blocks);
  free(healthy_blocks);
  free(parity_block);
  free(reconstructed_block);

  printf("All ECC unit tests passed successfully.\n");
  return 0;
}
