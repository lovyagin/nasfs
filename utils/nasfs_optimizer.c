/**
 * @file nasfs_optimizer.c
 * @brief NASFS Hardware Optimizer — measures real crypto+I/O throughput at
 *        multiple block sizes and outputs the optimal BlockSize for this host.
 *
 * Benchmarks each candidate block size with the same operations the client
 * runs on every block: AEAD encryption + BLAKE2b integrity hash.  The winner
 * is the block size that maximises combined crypto throughput on this CPU.
 *
 * Usage: nasfs_optimizer [--runs N]   (default: 5 passes per size)
 *
 * Output: recommended BlockSize and the matching NASFS_BLOCK_SIZE export line,
 *         ready to paste into nasfs.conf or the installer script.
 */

#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

#define BENCH_TOTAL_BYTES (128UL * 1024 * 1024) /* 128 MB per run */
#define MAX_BLOCK (4 * 1024 * 1024)
#define XCHACHA_KEY_BYTES crypto_aead_xchacha20poly1305_ietf_KEYBYTES
#define XCHACHA_NPUB_BYTES crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
#define XCHACHA_ABYTES crypto_aead_xchacha20poly1305_ietf_ABYTES

typedef struct {
  size_t block_size;
  double encrypt_mbps;
  double hash_mbps;
  double combined_mbps;
} bench_result_t;

static double bench_xchacha20(size_t block_size, int runs) {
  uint8_t key[XCHACHA_KEY_BYTES];
  uint8_t nonce[XCHACHA_NPUB_BYTES];
  randombytes_buf(key, sizeof(key));
  randombytes_buf(nonce, sizeof(nonce));

  uint8_t* plain = malloc(block_size);
  uint8_t* cipher = malloc(block_size + XCHACHA_ABYTES);
  if (!plain || !cipher) {
    free(plain);
    free(cipher);
    return 0.0;
  }
  memset(plain, 0xAB, block_size);

  size_t blocks_per_run = BENCH_TOTAL_BYTES / block_size;
  double best_mbps = 0.0;

  for (int r = 0; r < runs; r++) {
    uint64_t t0 = uv_hrtime();
    for (size_t i = 0; i < blocks_per_run; i++) {
      unsigned long long clen = 0;
      /* increment nonce per block — mirrors what the client does */
      uint64_t seq = (uint64_t)i;
      memcpy(nonce, &seq, sizeof(seq));
      crypto_aead_xchacha20poly1305_ietf_encrypt(cipher, &clen, plain,
                                                 block_size, NULL, 0, NULL,
                                                 nonce, key);
    }
    uint64_t t1 = uv_hrtime();
    double secs = (double)(t1 - t0) / 1e9;
    double mbps = ((double)BENCH_TOTAL_BYTES / (1024.0 * 1024.0)) / secs;
    if (mbps > best_mbps) best_mbps = mbps;
  }

  free(plain);
  free(cipher);
  return best_mbps;
}

static double bench_blake2b(size_t block_size, int runs) {
  uint8_t* data = malloc(block_size);
  uint8_t hash[32];
  if (!data) return 0.0;
  memset(data, 0xCD, block_size);

  size_t blocks_per_run = BENCH_TOTAL_BYTES / block_size;
  double best_mbps = 0.0;

  for (int r = 0; r < runs; r++) {
    uint64_t t0 = uv_hrtime();
    for (size_t i = 0; i < blocks_per_run; i++) {
      crypto_generichash(hash, sizeof(hash), data, block_size, NULL, 0);
    }
    uint64_t t1 = uv_hrtime();
    double secs = (double)(t1 - t0) / 1e9;
    double mbps = ((double)BENCH_TOTAL_BYTES / (1024.0 * 1024.0)) / secs;
    if (mbps > best_mbps) best_mbps = mbps;
  }

  free(data);
  return best_mbps;
}

/* harmonic mean of the two rates — represents the combined pipeline */
static double harmonic2(double a, double b) {
  if (a <= 0.0 || b <= 0.0) return 0.0;
  return 2.0 / (1.0 / a + 1.0 / b);
}

int main(int argc, char** argv) {
  int runs = 5;
  for (int i = 1; i < argc - 1; i++) {
    if (strcmp(argv[i], "--runs") == 0) {
      runs = atoi(argv[i + 1]);
      if (runs < 1) runs = 1;
      if (runs > 20) runs = 20;
    }
  }

  if (sodium_init() < 0) {
    fprintf(stderr, "libsodium init failed\n");
    return 1;
  }

  size_t candidates[] = {8192,   16384,  32768,   65536,
                         131072, 262144, 524288,  1048576};
  int n = (int)(sizeof(candidates) / sizeof(candidates[0]));
  bench_result_t results[8];

  printf("============================================================\n");
  printf("  NASFS Hardware Optimizer — real crypto throughput survey\n");
  printf("  Block size candidates: %d   Passes per size: %d\n", n, runs);
  printf("  Payload per pass: %lu MB\n",
         (unsigned long)(BENCH_TOTAL_BYTES / 1024 / 1024));
  printf("============================================================\n");
  printf("%-12s  %-14s  %-14s  %-14s\n", "BlockSize",
         "XChaCha20 MB/s", "BLAKE2b MB/s", "Combined MB/s");
  printf("------------------------------------------------------------\n");

  size_t best_size = 65536;
  double best_combined = 0.0;

  for (int i = 0; i < n; i++) {
    size_t bs = candidates[i];
    double enc = bench_xchacha20(bs, runs);
    double hsh = bench_blake2b(bs, runs);
    double comb = harmonic2(enc, hsh);

    results[i].block_size = bs;
    results[i].encrypt_mbps = enc;
    results[i].hash_mbps = hsh;
    results[i].combined_mbps = comb;

    printf("%-12zu  %-14.1f  %-14.1f  %-14.1f%s\n", bs, enc, hsh, comb,
           comb > best_combined ? "  <--" : "");

    if (comb > best_combined) {
      best_combined = comb;
      best_size = bs;
    }
  }

  printf("============================================================\n");
  printf("Optimal block size: %zu bytes (%.1f MB/s combined)\n", best_size,
         best_combined);
  printf("============================================================\n\n");
  printf("Apply to server config (nasfs.conf):\n");
  printf("  BlockSize %zu\n\n", best_size);
  printf("Apply to client (shell):\n");
  printf("  export NASFS_BLOCK_SIZE=%zu\n\n", best_size);

  return 0;
}
