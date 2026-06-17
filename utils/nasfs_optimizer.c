/**
 * @file nasfs_optimizer.c
 * @brief Hardware Optimizer Utility for determining the best Block Size based
 * on CPU cache.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

void benchmark_block_size(size_t block_size, double* out_throughput) {
  size_t total_data = 100 * 1024 * 1024;  // 100 MB test
  size_t iterations = total_data / block_size;

  uint8_t* buf1 = malloc(block_size);
  uint8_t* buf2 = malloc(block_size);
  if (!buf1 || !buf2) return;

  memset(buf1, 0xAA, block_size);
  memset(buf2, 0xBB, block_size);

  uint64_t start = uv_hrtime();

  // Simulate data processing (XOR parity / Encryption memory access patterns)
  for (size_t i = 0; i < iterations; i++) {
    for (size_t j = 0; j < block_size; j++) {
      buf1[j] ^= buf2[j];
    }
    // Artificial constraint to prevent compiler optimizing the loop away
    // entirely
    buf2[0] = buf1[0];
  }

  uint64_t end = uv_hrtime();

  double duration_sec = (double)(end - start) / 1e9;
  *out_throughput = (total_data / 1024.0 / 1024.0) / duration_sec;

  free(buf1);
  free(buf2);
}

int main(void) {
  printf("===============================================================\n");
  printf("          NASFS Hardware Optimizer & Auto-Tuner\n");
  printf("===============================================================\n");
  printf("Analyzing CPU L1/L2/L3 cache throughput...\n\n");

  size_t sizes[] = {16384, 32768, 65536, 131072, 262144, 524288, 1048576};
  int num_sizes = sizeof(sizes) / sizeof(sizes[0]);

  size_t best_size = 65536;
  double best_throughput = 0.0;

  for (int i = 0; i < num_sizes; i++) {
    double throughput = 0;
    benchmark_block_size(sizes[i], &throughput);
    printf("Block Size %7zu bytes : Throughput %8.2f MB/s\n", sizes[i],
           throughput);

    if (throughput > best_throughput) {
      best_throughput = throughput;
      best_size = sizes[i];
    }
  }

  printf("\n===============================================================\n");
  printf("🏆 Optimal Block Size for this Hardware: %zu bytes\n", best_size);
  printf("===============================================================\n");
  printf(
      "\nTo apply this globally, add the following to your configuration:\n");
  printf("Server (nasfs.conf): BlockSize %zu\n", best_size);
  printf("Client (Terminal):   export NASFS_BLOCK_SIZE=%zu\n\n", best_size);

  return 0;
}
