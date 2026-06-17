/**
 * @file ecc.h
 * @brief Forward Error Correction (FEC) using XOR Parity Blocks for NASFS.
 */

#ifndef NASFS_ECC_H
#define NASFS_ECC_H

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Computes the XOR parity block from a group of data blocks.
 *
 * Given N data blocks of the same size, this function computes:
 * parity[i] = block_0[i] ^ block_1[i] ^ ... ^ block_{N-1}[i]
 *
 * @param blocks Array of pointers to the data blocks.
 * @param num_blocks Number of data blocks.
 * @param block_size Size of each block in bytes.
 * @param out_parity Pointer to the buffer where the computed parity block will
 * be stored. Must be at least block_size bytes.
 */
void ecc_compute_parity(const uint8_t** blocks, size_t num_blocks,
                        size_t block_size, uint8_t* out_parity);

/**
 * @brief Reconstructs a single lost or corrupted block using the parity block
 * and the other healthy blocks.
 *
 * If block K is corrupted, it can be recovered by XORing all other healthy
 * blocks and the parity block: recovered_K = block_0 ^ ... ^ block_{K-1} ^
 * block_{K+1} ^ ... ^ block_{N-1} ^ parity
 *
 * @param blocks Array of pointers to the healthy data blocks (excluding the
 * corrupted one).
 * @param num_healthy_blocks Number of healthy data blocks (which is N - 1).
 * @param parity_block Pointer to the parity block.
 * @param block_size Size of each block in bytes.
 * @param out_recovered Pointer to the buffer where the reconstructed block will
 * be stored.
 */
void ecc_reconstruct_block(const uint8_t** blocks, size_t num_healthy_blocks,
                           const uint8_t* parity_block, size_t block_size,
                           uint8_t* out_recovered);

#endif /* NASFS_ECC_H */
