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
#                                  [--ciphers xchacha20poly1305,aes256gcm]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SERVER_BIN="$ROOT_DIR/build/nasfs_server"
CLIENT_BIN="$ROOT_DIR/build/nasfs_client"

SFTP_HOST="localhost"
SFTP_USER="$USER"
SFTP_PORT="22"
SFTP_KEY=""
RUNS=5
BLOCK_SIZES=(32768 65536 131072 262144 524288 1048576)
FILE_SIZES=(1048576 10485760 104857600)
FILE_LABELS=("1MB" "10MB" "100MB")
CIPHERS=("xchacha20poly1305" "aes256gcm")

SERVER_PORT=18081
BENCH_ROOT="/tmp/nasfs_bench_$$"
STORAGE_DIR="$BENCH_ROOT/storage"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
CSV="$ROOT_DIR/bench_${TIMESTAMP}.csv"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sftp-host)  SFTP_HOST="$2";  shift 2 ;;
    --sftp-user)  SFTP_USER="$2";  shift 2 ;;
    --sftp-port)  SFTP_PORT="$2";  shift 2 ;;
    --sftp-key)   SFTP_KEY="$2";   shift 2 ;;
    --runs)       RUNS="$2";        shift 2 ;;
    --sizes)      IFS=',' read -ra BLOCK_SIZES <<< "$2"; shift 2 ;;
    --ciphers)    IFS=',' read -ra CIPHERS     <<< "$2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 1 ;;
  esac
done

TASKSET=""
command -v taskset &>/dev/null && TASKSET="taskset -c 0"
THROTTLE="$TASKSET nice -n 19"

SFTP_OPTS=(-P "$SFTP_PORT" -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=10)
[[ -n "$SFTP_KEY" ]] && SFTP_OPTS+=(-i "$SFTP_KEY")

cleanup() {
  pkill -f "nasfs_server.*$SERVER_PORT" 2>/dev/null || true
  rm -rf "$BENCH_ROOT"
}
trap cleanup EXIT
cleanup
mkdir -p "$BENCH_ROOT" "$STORAGE_DIR"
echo "cipher,block_bytes,file_size,direction,run,throughput_MBps" > "$CSV"

# ---- float helpers using awk (no bc needed) ----
fgt() { awk "BEGIN {exit (($1) > ($2)) ? 0 : 1}"; }
fge() { awk "BEGIN {exit (($1) >= ($2)) ? 0 : 1}"; }
fmt() { awk "BEGIN {printf \"%7.2f\", $1}"; }

# average of all values passed as args
avg() {
  local vals=("$@") sum=0 n=${#vals[@]}
  for v in "${vals[@]}"; do
    sum=$(awk "BEGIN {printf \"%.6f\", $sum + $v}")
  done
  awk "BEGIN {printf \"%.4f\", $sum / $n}"
}

# median of N values (sort, pick middle)
median() {
  local vals=("$@") n=${#vals[@]}
  local sorted
  sorted=$(printf '%s\n' "${vals[@]}" | sort -g)
  local mid=$(( (n - 1) / 2 ))
  echo "$sorted" | awk "NR==$(( mid + 1 )) {printf \"%.4f\", \$1}"
}

now_ns() { date +%s%N; }

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
LogFile $BENCH_ROOT/server.log
LogLevel Error
DaemonMode No
PidFile $BENCH_ROOT/server.pid
StorageDir $STORAGE_DIR
KexAlgorithms ML-KEM-512,Kyber512
CipherAlgorithms xchacha20poly1305
AuthMethods password
AuthPassword nasfs
BlockSize $block_size
EOF
  rm -f "$STORAGE_DIR"/*
  $THROTTLE "$SERVER_BIN" "$BENCH_ROOT/server.conf" >> "$BENCH_ROOT/server_out.log" 2>&1 &
  for i in $(seq 1 50); do
    bash -c "echo >/dev/tcp/127.0.0.1/$SERVER_PORT" 2>/dev/null && return 0
    sleep 0.1
  done
  echo "Server did not start on port $SERVER_PORT" >&2; exit 1
}

stop_server() {
  pkill -f "nasfs_server.*$SERVER_PORT" 2>/dev/null || true
  sleep 0.3
}

run_nasfs_put() {
  local cipher=$1 block_size=$2 file=$3
  local sz t0 t1
  sz=$(wc -c < "$file" | tr -d ' ')
  t0=$(now_ns)
  $THROTTLE env \
    NASFS_KEX_ALGORITHMS="ML-KEM-512" \
    NASFS_CIPHER_ALGORITHMS="xchacha20poly1305" \
    NASFS_AUTH_METHOD="password" \
    NASFS_AUTH_USER="bench" \
    NASFS_AUTH_PASSWORD="nasfs" \
    NASFS_ENCRYPTION_KEY="benchkey" \
    NASFS_FILE_CIPHER="$cipher" \
    NASFS_FILE_HASH="blake2b" \
    NASFS_KDF="hkdf" \
    NASFS_BLOCK_SIZE="$block_size" \
    NASFS_SERVER_IP="127.0.0.1" \
    NASFS_SERVER_PORT="$SERVER_PORT" \
    "$CLIENT_BIN" put "$file" "bench_$$.bin" >/dev/null 2>&1
  t1=$(now_ns)
  awk "BEGIN {printf \"%.4f\", ($sz / 1048576.0) / (($t1 - $t0) / 1e9)}"
}

run_nasfs_get() {
  local cipher=$1 block_size=$2 fsz=$3
  local local_out="$BENCH_ROOT/got_$$.bin" t0 t1
  t0=$(now_ns)
  $THROTTLE env \
    NASFS_KEX_ALGORITHMS="ML-KEM-512" \
    NASFS_CIPHER_ALGORITHMS="xchacha20poly1305" \
    NASFS_AUTH_METHOD="password" \
    NASFS_AUTH_USER="bench" \
    NASFS_AUTH_PASSWORD="nasfs" \
    NASFS_ENCRYPTION_KEY="benchkey" \
    NASFS_FILE_CIPHER="$cipher" \
    NASFS_FILE_HASH="blake2b" \
    NASFS_KDF="hkdf" \
    NASFS_BLOCK_SIZE="$block_size" \
    NASFS_SERVER_IP="127.0.0.1" \
    NASFS_SERVER_PORT="$SERVER_PORT" \
    "$CLIENT_BIN" get "bench_$$.bin" "$local_out" >/dev/null 2>&1
  t1=$(now_ns)
  rm -f "$local_out"
  awk "BEGIN {printf \"%.4f\", ($fsz / 1048576.0) / (($t1 - $t0) / 1e9)}"
}

run_sftp_put() {
  local file=$1 sz remote_dir="/tmp/sftp_bench_$$"
  sz=$(wc -c < "$file" | tr -d ' ')
  printf "mkdir %s\n" "$remote_dir" \
    | sftp "${SFTP_OPTS[@]}" "$SFTP_USER@$SFTP_HOST" >/dev/null 2>&1 || true
  local t0 t1
  t0=$(now_ns)
  printf "put %s %s/f\n" "$file" "$remote_dir" \
    | sftp "${SFTP_OPTS[@]}" "$SFTP_USER@$SFTP_HOST" >/dev/null 2>&1
  t1=$(now_ns)
  printf "rm %s/f\nrmdir %s\n" "$remote_dir" "$remote_dir" \
    | sftp "${SFTP_OPTS[@]}" "$SFTP_USER@$SFTP_HOST" >/dev/null 2>&1 || true
  awk "BEGIN {printf \"%.4f\", ($sz / 1048576.0) / (($t1 - $t0) / 1e9)}"
}

run_sftp_get() {
  local file=$1 sz remote_path="/tmp/sftp_src_$$"
  sz=$(wc -c < "$file" | tr -d ' ')
  printf "put %s %s\n" "$file" "$remote_path" \
    | sftp "${SFTP_OPTS[@]}" "$SFTP_USER@$SFTP_HOST" >/dev/null 2>&1
  local t0 t1 local_out="$BENCH_ROOT/sftp_got_$$.bin"
  t0=$(now_ns)
  printf "get %s %s\n" "$remote_path" "$local_out" \
    | sftp "${SFTP_OPTS[@]}" "$SFTP_USER@$SFTP_HOST" >/dev/null 2>&1
  t1=$(now_ns)
  printf "rm %s\n" "$remote_path" \
    | sftp "${SFTP_OPTS[@]}" "$SFTP_USER@$SFTP_HOST" >/dev/null 2>&1 || true
  rm -f "$local_out"
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
echo -e "Throttle: $THROTTLE   Runs per point: $RUNS (median reported)"
echo ""

declare -A BEST_PUT BEST_GET  # [cipher_bs_flbl] -> mbps

for cipher in "${CIPHERS[@]}"; do
  short="${cipher%%poly1305}"; short="${short%%256gcm}256gcm"; short="${short%_}"
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

  for bs in "${BLOCK_SIZES[@]}"; do
    lbl=$(block_label "$bs")
    start_server "$bs"
    printf "%-10s" "$lbl"

    for fidx in "${!FILE_SIZES[@]}"; do
      fsz="${FILE_SIZES[$fidx]}"
      flbl="${FILE_LABELS[$fidx]}"
      tfile="$BENCH_ROOT/test_${fsz}.bin"

      puts=(); gets=()
      for run in $(seq 1 $RUNS); do
        rm -f "$STORAGE_DIR"/bench_*.bin
        p=$(run_nasfs_put "$cipher" "$bs" "$tfile")
        g=$(run_nasfs_get "$cipher" "$bs" "$fsz")
        puts+=("$p"); gets+=("$g")
        echo "${cipher},${bs},${flbl},put,${run},${p}" >> "$CSV"
        echo "${cipher},${bs},${flbl},get,${run},${g}" >> "$CSV"
      done

      mp=$(median "${puts[@]}")
      mg=$(median "${gets[@]}")
      BEST_PUT["${cipher}_${bs}_${flbl}"]="$mp"
      BEST_GET["${cipher}_${bs}_${flbl}"]="$mg"

      printf "  %s MB/s  %s MB/s" "$(fmt "$mp")" "$(fmt "$mg")"
    done
    printf "\n"
    stop_server
  done
  echo ""
done

# ---- SFTP baseline ----
echo -e "${CYAN}=== SFTP (${SFTP_USER}@${SFTP_HOST}:${SFTP_PORT}) ===${NC}"
printf "%-10s" "SFTP"
declare -A SFTP_PUT SFTP_GET
for fidx in "${!FILE_SIZES[@]}"; do
  fsz="${FILE_SIZES[$fidx]}"
  flbl="${FILE_LABELS[$fidx]}"
  tfile="$BENCH_ROOT/test_${fsz}.bin"

  sputs=(); sgets=()
  for run in $(seq 1 $RUNS); do
    sp=$(run_sftp_put "$tfile")
    sg=$(run_sftp_get "$tfile")
    sputs+=("$sp"); sgets+=("$sg")
    echo "sftp,N/A,${flbl},put,${run},${sp}" >> "$CSV"
    echo "sftp,N/A,${flbl},get,${run},${sg}" >> "$CSV"
  done
  SFTP_PUT["$flbl"]=$(median "${sputs[@]}")
  SFTP_GET["$flbl"]=$(median "${sgets[@]}")
  printf "  %s MB/s  %s MB/s" "$(fmt "${SFTP_PUT[$flbl]}")" "$(fmt "${SFTP_GET[$flbl]}")"
done
printf "\n\n"

# ---- Summary: best config vs SFTP ----
echo -e "${BOLD}=== Summary: best NASFS config vs SFTP (median of $RUNS runs) ===${NC}"
printf "%-10s  %-5s  %-22s  %-22s  %-12s  %s\n" \
  "FileSize" "Dir" "NASFS_best" "SFTP" "Ratio" "Winner"
printf "%-10s  %-5s  %-22s  %-22s  %-12s  %s\n" \
  "--------" "---" "----------" "----" "-----" "------"

for flbl in "${FILE_LABELS[@]}"; do
  sftp_p="${SFTP_PUT[$flbl]}"
  sftp_g="${SFTP_GET[$flbl]}"

  best_p=0; best_p_label=""; best_g=0; best_g_label=""
  for cipher in "${CIPHERS[@]}"; do
    [[ "$cipher" == "aes256gcm" ]] && clabel="AES" || clabel="XCH"
    for bs in "${BLOCK_SIZES[@]}"; do
      lbl=$(block_label "$bs")
      p="${BEST_PUT["${cipher}_${bs}_${flbl}"]:-0}"
      g="${BEST_GET["${cipher}_${bs}_${flbl}"]:-0}"
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
