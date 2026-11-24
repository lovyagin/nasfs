#!/usr/bin/env bash
# Block-size and cipher sweep benchmark for NASFS vs SFTP
#
# Tests PUT+GET across multiple block sizes and both cipher options
# (xchacha20poly1305 and aes256gcm) under single-core throttle.
# Reports median throughput over N runs.
#
# Usage: ./benchmark_blocksize.sh [--sftp-host HOST] [--sftp-user USER]
#                                  [--sftp-port PORT] [--sftp-key FILE]
#                                  [--runs N] [--sizes SZ,SZ,...]
#                                  [--ciphers xchacha20poly1305,aes256gcm] [--no-sftp]

set -euo pipefail
export LC_ALL=C LANG=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SERVER_BIN="${NASFS_SERVER_BIN:-$ROOT_DIR/build/nasfs_server}"
CLIENT_BIN="${NASFS_CLIENT_BIN:-$ROOT_DIR/build/nasfs_client}"
# shellcheck source-path=SCRIPTDIR
source "$SCRIPT_DIR/integration_helpers.sh"

SFTP_HOST="localhost"
SFTP_USER="${USER:-$(id -un)}"
SFTP_PORT="22"
SFTP_KEY=""
COMPARE_SFTP=1
RUNS=5
BLOCK_SIZES=(32768 65536 131072 262144 524288 1048576)
FILE_SIZES=(1048576 10485760 104857600)
FILE_LABELS=("1MB" "10MB" "100MB")
CIPHERS=("xchacha20poly1305" "aes256gcm")

SERVER_PORT=${NASFS_BENCH_PORT:-18081}
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
CSV="${NASFS_BENCH_CSV:-$ROOT_DIR/bench_${TIMESTAMP}.csv}"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sftp-host)  SFTP_HOST="$2";  shift 2 ;;
    --sftp-user)  SFTP_USER="$2";  shift 2 ;;
    --sftp-port)  SFTP_PORT="$2";  shift 2 ;;
    --no-sftp)  COMPARE_SFTP=0; shift ;;
    --sftp-key)   SFTP_KEY="$2";   shift 2 ;;
    --runs)       RUNS="$2";        shift 2 ;;
    --sizes)      IFS=',' read -ra BLOCK_SIZES <<< "$2"; shift 2 ;;
    --ciphers)    IFS=',' read -ra CIPHERS     <<< "$2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 1 ;;
  esac
done

THROTTLE=(nice -n 19)
if command -v taskset >/dev/null && affinity=$(taskset -pc "$$" 2>/dev/null); then
  affinity=${affinity##*: }
  THROTTLE=(taskset -c "${affinity%%[-,]*}" "${THROTTLE[@]}")
fi

SFTP_OPTS=(-P "$SFTP_PORT" -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=10)
[[ -n "$SFTP_KEY" ]] && SFTP_OPTS+=(-i "$SFTP_KEY")

benchmark_home=${HOME:-}
setup_integration
BENCH_ROOT="$TEST_ROOT"
echo "cipher,block_bytes,file_size,direction,run,throughput_MBps" > "$CSV"

# ---- float helpers using awk (no bc needed) ----
fgt() { awk "BEGIN {exit (($1) > ($2)) ? 0 : 1}"; }
fge() { awk "BEGIN {exit (($1) >= ($2)) ? 0 : 1}"; }
fmt() { awk "BEGIN {printf \"%7.2f\", $1}"; }

# median of N values (sort, pick middle)
median() {
  local vals=("$@")
  local n=${#vals[@]}
  local sorted
  sorted=$(printf '%s\n' "${vals[@]}" | sort -g)
  local mid=$(( (n - 1) / 2 ))
  echo "$sorted" | awk "NR==$(( mid + 1 )) {printf \"%.4f\", \$1}"
}

now_ns() { python3 -c "import time; print(time.monotonic_ns())"; }

block_label() {
  local bs=$1
  if   (( bs >= 1048576 )); then echo "$(( bs/1048576 ))M"
  elif (( bs >= 1024 ));    then echo "$(( bs/1024 ))K"
  else echo "${bs}B"; fi
}

start_server() {
  local block_size=$1
  cat > "$BENCH_ROOT/server.conf" <<EOF
ListenAddr 127.0.0.1
Port $SERVER_PORT
MaxConn 20
LogFile $LOG_DIR/server.log
LogLevel Info
DaemonMode No
PidFile $BENCH_ROOT/server.pid
StorageDir $STORAGE_DIR
KexAlgorithms ML-KEM-512
CipherAlgorithms xchacha20poly1305
AuthMethods password
AuthPassword nasfs
BlockSize $block_size
EOF
  rm -f "$STORAGE_DIR"/*
  : > "$LOG_DIR/server.log"
  start_integration_server "$BENCH_ROOT/server.conf" "${THROTTLE[@]}"
}

run_nasfs_put() {
  local cipher=$1 block_size=$2 file=$3
  local sz t0 t1
  sz=$(wc -c < "$file" | tr -d ' ')
  t0=$(now_ns)
  env \
    NASFS_KEX_ALGORITHMS="ML-KEM-512" \
    NASFS_CIPHER_ALGORITHMS="xchacha20poly1305" \
    NASFS_AUTH_METHOD="password" \
    NASFS_AUTH_USER="bench" \
    NASFS_AUTH_PASSWORD="nasfs" \
    NASFS_ENCRYPTION_KEY="benchkey" \
    NASFS_FILE_CIPHER="$cipher" \
    NASFS_FILE_HASH="blake2b" \
    NASFS_KDF="argon2id" \
    NASFS_BLOCK_SIZE="$block_size" \
    "${THROTTLE[@]}" "$CLIENT_BIN" put "$file" "bench_$$.bin" >/dev/null || return
  t1=$(now_ns)
  awk "BEGIN {printf \"%.4f\", ($sz / 1048576.0) / (($t1 - $t0) / 1e9)}"
}

run_nasfs_get() {
  local cipher=$1 block_size=$2 fsz=$3
  local local_out="$BENCH_ROOT/got_$$.bin" t0 t1
  t0=$(now_ns)
  env \
    NASFS_KEX_ALGORITHMS="ML-KEM-512" \
    NASFS_CIPHER_ALGORITHMS="xchacha20poly1305" \
    NASFS_AUTH_METHOD="password" \
    NASFS_AUTH_USER="bench" \
    NASFS_AUTH_PASSWORD="nasfs" \
    NASFS_ENCRYPTION_KEY="benchkey" \
    NASFS_FILE_CIPHER="$cipher" \
    NASFS_FILE_HASH="blake2b" \
    NASFS_KDF="argon2id" \
    NASFS_BLOCK_SIZE="$block_size" \
    "${THROTTLE[@]}" "$CLIENT_BIN" get "bench_$$.bin" "$local_out" >/dev/null || return
  t1=$(now_ns)
  rm -f "$local_out"
  awk "BEGIN {printf \"%.4f\", ($fsz / 1048576.0) / (($t1 - $t0) / 1e9)}"
}

sftp_batch() {
  sftp "${SFTP_OPTS[@]}" -b - "$SFTP_USER@$SFTP_HOST"
}

run_sftp_put() {
  local file=$1 sz remote_dir="/tmp/sftp_bench_$$"
  sz=$(wc -c < "$file" | tr -d ' ')
  printf 'mkdir %s\n' "$remote_dir" | sftp_batch >/dev/null || return
  local t0 t1 status=0
  t0=$(now_ns)
  printf 'put "%s" %s/f\n' "$file" "$remote_dir" \
    | sftp_batch >/dev/null || status=$?
  t1=$(now_ns)
  printf -- '-rm %s/f\nrmdir %s\n' "$remote_dir" "$remote_dir" \
    | sftp_batch >/dev/null 2>&1 || true
  (( status == 0 )) || return "$status"
  awk "BEGIN {printf \"%.4f\", ($sz / 1048576.0) / (($t1 - $t0) / 1e9)}"
}

run_sftp_get() {
  local file=$1 sz remote_path="/tmp/sftp_src_$$"
  sz=$(wc -c < "$file" | tr -d ' ')
  local t0 t1 local_out="$BENCH_ROOT/sftp_got_$$.bin" status=0
  if printf 'put "%s" %s\n' "$file" "$remote_path" | sftp_batch >/dev/null; then
    t0=$(now_ns)
    printf 'get %s "%s"\n' "$remote_path" "$local_out" \
      | sftp_batch >/dev/null || status=$?
    t1=$(now_ns)
  else
    status=$?
  fi
  printf 'rm %s\n' "$remote_path" | sftp_batch >/dev/null 2>&1 || true
  rm -f "$local_out"
  (( status == 0 )) || return "$status"
  awk "BEGIN {printf \"%.4f\", ($sz / 1048576.0) / (($t1 - $t0) / 1e9)}"
}

# ---- Pre-generate test files ----
for fsz in "${FILE_SIZES[@]}"; do
  tfile="$BENCH_ROOT/test_${fsz}.bin"
  [[ -f "$tfile" ]] || dd if=/dev/urandom of="$tfile" bs=4096 \
      count=$(( fsz / 4096 )) 2>/dev/null
done

# ---- Header ----
echo ""
echo -e "${BOLD}NASFS cipher+block sweep vs SFTP — $(date)${NC}"
echo -e "Throttle: ${THROTTLE[*]}   Runs per point: $RUNS (median reported)"
echo ""

BEST_PUT=()
BEST_GET=()

for cidx in "${!CIPHERS[@]}"; do
  cipher="${CIPHERS[$cidx]}"
  # prettier label
  [[ "$cipher" == "aes256gcm" ]] && clabel="AES-256-GCM" || clabel="XChaCha20-Poly1305"

  echo -e "${CYAN}=== NASFS / ${clabel} ===${NC}"
  printf "%-10s" "BlockSize"
  for lbl in "${FILE_LABELS[@]}"; do
    printf "  PUT %-6s  GET %-6s" "$lbl" "$lbl"
  done
  printf "\n"
  printf "%-10s" "----------"
  for _ in "${FILE_LABELS[@]}"; do printf "  %-12s  %-12s" "------------" "------------"; done
  printf "\n"

  for bidx in "${!BLOCK_SIZES[@]}"; do
    bs="${BLOCK_SIZES[$bidx]}"
    lbl=$(block_label "$bs")
    start_server "$bs"
    printf "%-10s" "$lbl"

    for fidx in "${!FILE_SIZES[@]}"; do
      fsz="${FILE_SIZES[$fidx]}"
      flbl="${FILE_LABELS[$fidx]}"
      tfile="$BENCH_ROOT/test_${fsz}.bin"

      puts=(); gets=()
      for run in $(seq 1 "$RUNS"); do
        rm -f "$STORAGE_DIR"/bench_*.bin
        p=$(run_nasfs_put "$cipher" "$bs" "$tfile")
        g=$(run_nasfs_get "$cipher" "$bs" "$fsz")
        puts+=("$p"); gets+=("$g")
        echo "${cipher},${bs},${flbl},put,${run},${p}" >> "$CSV"
        echo "${cipher},${bs},${flbl},get,${run},${g}" >> "$CSV"
      done

      mp=$(median "${puts[@]}")
      mg=$(median "${gets[@]}")
      idx=$(( (cidx * ${#BLOCK_SIZES[@]} + bidx) * ${#FILE_SIZES[@]} + fidx ))
      BEST_PUT[idx]="$mp"
      BEST_GET[idx]="$mg"

      printf "  %s MB/s  %s MB/s" "$(fmt "$mp")" "$(fmt "$mg")"
    done
    printf "\n"
    stop_integration_server
  done
  echo ""
done

if (( ! COMPARE_SFTP )); then
  printf 'CSV: %s\n' "$CSV"
  exit 0
fi

export HOME="$benchmark_home"

# ---- SFTP baseline ----
echo -e "${CYAN}=== SFTP (${SFTP_USER}@${SFTP_HOST}:${SFTP_PORT}) ===${NC}"
printf "%-10s" "SFTP"
SFTP_PUT=()
SFTP_GET=()
for fidx in "${!FILE_SIZES[@]}"; do
  fsz="${FILE_SIZES[$fidx]}"
  flbl="${FILE_LABELS[$fidx]}"
  tfile="$BENCH_ROOT/test_${fsz}.bin"

  sputs=(); sgets=()
  for run in $(seq 1 "$RUNS"); do
    sp=$(run_sftp_put "$tfile")
    echo "sftp,N/A,${flbl},put,${run},${sp}" >> "$CSV"
    sg=$(run_sftp_get "$tfile")
    echo "sftp,N/A,${flbl},get,${run},${sg}" >> "$CSV"
    sputs+=("$sp"); sgets+=("$sg")
  done
  SFTP_PUT[fidx]=$(median "${sputs[@]}")
  SFTP_GET[fidx]=$(median "${sgets[@]}")
  printf "  %s MB/s  %s MB/s" "$(fmt "${SFTP_PUT[fidx]}")" "$(fmt "${SFTP_GET[fidx]}")"
done
printf "\n\n"

# ---- Summary: best config vs SFTP ----
echo -e "${BOLD}=== Summary: best NASFS config vs SFTP (median of $RUNS runs) ===${NC}"
printf "%-10s  %-5s  %-22s  %-22s  %-12s  %s\n" \
  "FileSize" "Dir" "NASFS_best" "SFTP" "Ratio" "Winner"
printf "%-10s  %-5s  %-22s  %-22s  %-12s  %s\n" \
  "--------" "---" "----------" "----" "-----" "------"

for fidx in "${!FILE_LABELS[@]}"; do
  flbl="${FILE_LABELS[$fidx]}"
  sftp_p="${SFTP_PUT[fidx]}"
  sftp_g="${SFTP_GET[fidx]}"

  best_p=0; best_p_label=""; best_g=0; best_g_label=""
  for cidx in "${!CIPHERS[@]}"; do
    cipher="${CIPHERS[$cidx]}"
    [[ "$cipher" == "aes256gcm" ]] && clabel="AES" || clabel="XCH"
    for bidx in "${!BLOCK_SIZES[@]}"; do
      bs="${BLOCK_SIZES[$bidx]}"
      lbl=$(block_label "$bs")
      idx=$(( (cidx * ${#BLOCK_SIZES[@]} + bidx) * ${#FILE_SIZES[@]} + fidx ))
      p="${BEST_PUT[idx]}"
      g="${BEST_GET[idx]}"
      fgt "$p" "$best_p" && { best_p="$p"; best_p_label="${clabel}@${lbl}"; } || true
      fgt "$g" "$best_g" && { best_g="$g"; best_g_label="${clabel}@${lbl}"; } || true
    done
  done

  rp=$(awk "BEGIN {printf \"%.2f\", $best_p / $sftp_p}")
  rg=$(awk "BEGIN {printf \"%.2f\", $best_g / $sftp_g}")

  cp="$RED"; fge "$rp" "1.0" && cp="$GREEN" || true
  cg="$RED"; fge "$rg" "1.0" && cg="$GREEN" || true
  wp="SFTP"; fge "$rp" "1.0" && wp="NASFS" || true
  wg="SFTP"; fge "$rg" "1.0" && wg="NASFS" || true

  printf "%-10s  %-5s  %s MB/s (%-10s)  %s MB/s                ${cp}%sx${NC}       %s\n" \
    "$flbl" "PUT" "$(fmt "$best_p")" "$best_p_label" "$(fmt "$sftp_p")" "$rp" "$wp"
  printf "%-10s  %-5s  %s MB/s (%-10s)  %s MB/s                ${cg}%sx${NC}       %s\n" \
    "$flbl" "GET" "$(fmt "$best_g")" "$best_g_label" "$(fmt "$sftp_g")" "$rg" "$wg"
done

echo ""
echo -e "CSV: ${BOLD}${CSV}${NC}"
