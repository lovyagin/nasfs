/**
 * @file nasfs_optimizer.c
 * @brief NASFS Hardware Optimizer — measures real crypto throughput at multiple
 *        block sizes and outputs the optimal BlockSize for this host.
 *
 * Benchmarks each candidate block size with the actual operations NASFS runs
 * on every block: AEAD encrypt + BLAKE2b integrity hash.  Tests all three
 * supported AEAD algorithms so the best cipher for this CPU is also surfaced.
 *
 * Usage: nasfs_optimizer [--runs N]   (default: 5 passes per size)
 *
 * Output: per-cipher throughput table + recommended BlockSize and
 *         NASFS_BLOCK_SIZE / NASFS_FILE_CIPHER export lines.
 */

#include <openssl/evp.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

#define BENCH_TOTAL_BYTES (128UL * 1024 * 1024)

/* ---- helpers ---- */

static double bench_xchacha20(size_t block_size, int runs) {
  uint8_t key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
  uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
  randombytes_buf(key, sizeof(key));
  uint8_t* plain = malloc(block_size);
  uint8_t* cipher =
      malloc(block_size + crypto_aead_xchacha20poly1305_ietf_ABYTES);
  if (!plain || !cipher) {
    free(plain);
    free(cipher);
    return 0;
  }
  memset(plain, 0xAB, block_size);

  size_t n = BENCH_TOTAL_BYTES / block_size;
  double best = 0;
  for (int r = 0; r < runs; r++) {
    uint64_t t0 = uv_hrtime();
    for (size_t i = 0; i < n; i++) {
      unsigned long long clen = 0;
      uint64_t seq = i;
      memcpy(nonce, &seq, sizeof(seq));
      memset(nonce + sizeof(seq), 0,
             crypto_aead_xchacha20poly1305_ietf_NPUBBYTES - sizeof(seq));
      crypto_aead_xchacha20poly1305_ietf_encrypt(
          cipher, &clen, plain, block_size, NULL, 0, NULL, nonce, key);
    }
    double mbps =
        (BENCH_TOTAL_BYTES / 1048576.0) / ((double)(uv_hrtime() - t0) / 1e9);
    if (mbps > best) best = mbps;
  }
  free(plain);
  free(cipher);
  return best;
}

static double bench_aesgcm(size_t block_size, int runs) {
  uint8_t key[32], nonce[12], tag[16];
  randombytes_buf(key, sizeof(key));
  uint8_t* plain = malloc(block_size);
  uint8_t* cipher = malloc(block_size);
  if (!plain || !cipher) {
    free(plain);
    free(cipher);
    return 0;
  }
  memset(plain, 0xCD, block_size);

  size_t n = BENCH_TOTAL_BYTES / block_size;
  double best = 0;
  for (int r = 0; r < runs; r++) {
    uint64_t t0 = uv_hrtime();
    for (size_t i = 0; i < n; i++) {
      uint64_t seq = i;
      memcpy(nonce, &seq, sizeof(seq));
      memset(nonce + sizeof(seq), 0, sizeof(nonce) - sizeof(seq));

      EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
      int len = 0;
      EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL);
      EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce);
      EVP_EncryptUpdate(ctx, cipher, &len, plain, (int)block_size);
      EVP_EncryptFinal_ex(ctx, cipher + len, &len);
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag);
      EVP_CIPHER_CTX_free(ctx);
    }
    double mbps =
        (BENCH_TOTAL_BYTES / 1048576.0) / ((double)(uv_hrtime() - t0) / 1e9);
    if (mbps > best) best = mbps;
  }
  free(plain);
  free(cipher);
  return best;
}

static double bench_blake2b(size_t block_size, int runs) {
  uint8_t* data = malloc(block_size);
  uint8_t hash[32];
  if (!data) return 0;
  memset(data, 0xEF, block_size);

  size_t n = BENCH_TOTAL_BYTES / block_size;
  double best = 0;
  for (int r = 0; r < runs; r++) {
    uint64_t t0 = uv_hrtime();
    for (size_t i = 0; i < n; i++)
      crypto_generichash(hash, sizeof(hash), data, block_size, NULL, 0);
    double mbps =
        (BENCH_TOTAL_BYTES / 1048576.0) / ((double)(uv_hrtime() - t0) / 1e9);
    if (mbps > best) best = mbps;
  }
  free(data);
  return best;
}

static double harmonic2(double a, double b) {
  if (a <= 0 || b <= 0) return 0;
  return 2.0 / (1.0 / a + 1.0 / b);
}

int main(int argc, char** argv) {
  int runs = 5;
  for (int i = 1; i + 1 < argc; i++) {
    if (strcmp(argv[i], "--runs") == 0) {
      runs = (int)strtol(argv[i + 1], NULL, 10);
      if (runs < 1) runs = 1;
      if (runs > 20) runs = 20;
    }
  }

  if (sodium_init() < 0) {
    fprintf(stderr, "libsodium init failed\n");
    return 1;
  }

  size_t sizes[] = {8192, 16384, 32768, 65536, 131072, 262144, 524288, 1048576};
  int n = (int)(sizeof(sizes) / sizeof(sizes[0]));

  printf("=================================================================\n");
  printf("  NASFS Hardware Optimizer — real cipher + hash throughput\n");
  printf("  Block candidates: %d   Passes per size: %d   Data/pass: %lu MB\n",
         n, runs, (unsigned long)(BENCH_TOTAL_BYTES / 1024 / 1024));
  printf("=================================================================\n");
  printf("%-10s  %-14s  %-14s  %-14s  %-14s\n", "BlockSize", "XChaCha20 MB/s",
         "AES-256-GCM MB/s", "BLAKE2b MB/s", "Best_combined");
  printf("-----------------------------------------------------------------\n");

  size_t best_size_xcha = 65536, best_size_aes = 65536;
  double best_comb_xcha = 0, best_comb_aes = 0;
  double best_xcha_speed = 0, best_aes_speed = 0;

  for (int i = 0; i < n; i++) {
    size_t bs = sizes[i];
    double xcha = bench_xchacha20(bs, runs);
    double aes = bench_aesgcm(bs, runs);
    double blake = bench_blake2b(bs, runs);
    double comb_xcha = harmonic2(xcha, blake);
    double comb_aes = harmonic2(aes, blake);
    double best_comb = comb_aes > comb_xcha ? comb_aes : comb_xcha;
    const char* winner = comb_aes > comb_xcha ? "AES" : "XCH";

    printf("%-10zu  %-14.1f  %-14.1f  %-14.1f  %.1f (%s)%s\n", bs, xcha, aes,
           blake, best_comb, winner,
           best_comb > (best_comb_xcha > best_comb_aes ? best_comb_xcha
                                                       : best_comb_aes)
               ? "  <--"
               : "");

    if (comb_xcha > best_comb_xcha) {
      best_comb_xcha = comb_xcha;
      best_size_xcha = bs;
      best_xcha_speed = xcha;
    }
    if (comb_aes > best_comb_aes) {
      best_comb_aes = comb_aes;
      best_size_aes = bs;
      best_aes_speed = aes;
    }
  }

  int aes_wins = best_comb_aes > best_comb_xcha;
  size_t rec_size = aes_wins ? best_size_aes : best_size_xcha;
  const char* rec_cipher = aes_wins ? "aes256gcm" : "xchacha20poly1305";
  double rec_speed = aes_wins ? best_aes_speed : best_xcha_speed;

  printf("=================================================================\n");
  printf("XChaCha20 peak : %.1f MB/s combined @ %zu bytes\n", best_comb_xcha,
         best_size_xcha);
  printf("AES-256-GCM peak: %.1f MB/s combined @ %zu bytes\n", best_comb_aes,
         best_size_aes);
  printf("\nRecommended cipher : %s (%.1f MB/s encrypt)\n", rec_cipher,
         rec_speed);
  printf("Recommended block  : %zu bytes\n", rec_size);
  printf(
      "=================================================================\n\n");
  printf("Apply to server config (nasfs.conf):\n");
  printf("  BlockSize %zu\n\n", rec_size);
  printf("Apply to client (shell):\n");
  printf("  export NASFS_BLOCK_SIZE=%zu\n", rec_size);
  printf("  export NASFS_FILE_CIPHER=%s\n\n", rec_cipher);

  return 0;
}
