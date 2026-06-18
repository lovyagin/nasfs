#!/usr/bin/env bash
# NASFS small-file IOPS benchmark vs SFTP
#
# Measures:
#   - Files/second (throughput in file operations)
#   - Latency per file (ms per PUT / GET)
#   - Total time to transfer N files of size S
#
# Each NASFS PUT/GET is a new connection (PQC handshake + auth per file).
# SFTP batches all files in a single session — this difference is intentional
# and shows the architectural overhead of per-connection PQC KEX.
#
# Usage: ./benchmark_iops.sh [--sftp-host HOST] [--sftp-user USER]
#                             [--sftp-port PORT] [--sftp-key FILE]
#                             [--count N] [--runs R]

set -euo pipefail
export LC_ALL=C LANG=C

# ---- Mode legend -------------------------------------------------------
# serial  : N connections, one file each (original behaviour)
# batch   : 1 connection, N files via mput/mget (new session reuse)
# sftp    : 1 SSH session, N files via sftp -b (batch commands)
# -----------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SERVER_BIN="$ROOT_DIR/build/nasfs_server"
CLIENT_BIN="$ROOT_DIR/build/nasfs_client"

SFTP_HOST="localhost"
SFTP_USER="$USER"
SFTP_PORT="22"
SFTP_KEY=""
COUNT=20          # files per batch
RUNS=3            # repeat each batch, take median

# File sizes to test (bytes) — small file range
FILE_SIZES=(4096 16384 65536 262144)
FILE_LABELS=("4KB" "16KB" "64KB" "256KB")

SERVER_PORT=18082
BENCH_ROOT="/tmp/nasfs_iops_$$"
STORAGE_DIR="$BENCH_ROOT/storage"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
CSV="$ROOT_DIR/bench_iops_${TIMESTAMP}.csv"

CYAN='\033[0;36m'; BOLD='\033[1m'; RED='\033[0;31m'
GREEN='\033[0;32m'; NC='\033[0m'

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sftp-host) SFTP_HOST="$2"; shift 2 ;;
    --sftp-user) SFTP_USER="$2"; shift 2 ;;
    --sftp-port) SFTP_PORT="$2"; shift 2 ;;
    --sftp-key)  SFTP_KEY="$2";  shift 2 ;;
    --count)     COUNT="$2";     shift 2 ;;
    --runs)      RUNS="$2";      shift 2 ;;
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
echo "system,file_size,direction,run,count,total_sec,files_per_sec,latency_ms,throughput_MBps" > "$CSV"

now_ns() { date +%s%N; }

median() {
  local vals=("$@") n=${#vals[@]}
  printf '%s\n' "${vals[@]}" | sort -g | awk "NR==$(( (n-1)/2 + 1 )) {printf \"%.4f\", \$1}"
}

start_server() {
  cat > "$BENCH_ROOT/server.conf" <<EOF
ListenAddr 127.0.0.1
Port $SERVER_PORT
MaxConn 50
LogFile $BENCH_ROOT/server.log
LogLevel Error
DaemonMode No
PidFile $BENCH_ROOT/server.pid
StorageDir $STORAGE_DIR
KexAlgorithms ML-KEM-512,Kyber512
CipherAlgorithms xchacha20poly1305
AuthMethods password
AuthPassword nasfs
BlockSize 65536
EOF
  rm -f "$STORAGE_DIR"/*
  $THROTTLE "$SERVER_BIN" "$BENCH_ROOT/server.conf" >> "$BENCH_ROOT/server_out.log" 2>&1 &
  for i in $(seq 1 50); do
    bash -c "echo >/dev/tcp/127.0.0.1/$SERVER_PORT" 2>/dev/null && return 0
    sleep 0.1
  done
  echo "Server did not start" >&2; exit 1
}

stop_server() {
  pkill -f "nasfs_server.*$SERVER_PORT" 2>/dev/null || true
  sleep 0.2
}

nasfs_env() {
  env \
    NASFS_KEX_ALGORITHMS="ML-KEM-512" \
    NASFS_CIPHER_ALGORITHMS="xchacha20poly1305" \
    NASFS_AUTH_METHOD="password" \
    NASFS_AUTH_USER="bench" \
    NASFS_AUTH_PASSWORD="nasfs" \
    NASFS_ENCRYPTION_KEY="iops-bench-key" \
    NASFS_FILE_CIPHER="xchacha20poly1305" \
    NASFS_FILE_HASH="blake2b" \
    NASFS_KDF="hkdf" \
    NASFS_BLOCK_SIZE="65536" \
    NASFS_SERVER_IP="127.0.0.1" \
    NASFS_SERVER_PORT="$SERVER_PORT" \
    "$@"
}

# N serial PUTs (one connection per file)
bench_nasfs_serial_put() {
  local fsz=$1 count=$2
  local tfile="$BENCH_ROOT/src_${fsz}.bin"
  rm -f "$STORAGE_DIR"/*
  local t0 t1
  t0=$(now_ns)
  for i in $(seq 1 "$count"); do
    $THROTTLE nasfs_env "$CLIENT_BIN" put "$tfile" "iops_${i}_$$.bin" >/dev/null 2>&1
  done
  t1=$(now_ns)
  local total_sec
  total_sec=$(awk "BEGIN {printf \"%.4f\", ($t1 - $t0) / 1e9}")
  awk "BEGIN {fps=$count/$total_sec; lat=$total_sec*1000/$count; tput=$count*$fsz/1048576.0/$total_sec; printf \"%.4f %.4f %.2f %.4f\", $total_sec, fps, lat, tput}"
}

# N serial GETs (one connection per file)
bench_nasfs_serial_get() {
  local fsz=$1 count=$2
  local out="$BENCH_ROOT/got_$$.bin"
  local t0 t1
  t0=$(now_ns)
  for i in $(seq 1 "$count"); do
    $THROTTLE nasfs_env "$CLIENT_BIN" get "iops_${i}_$$.bin" "$out" >/dev/null 2>&1
    rm -f "$out"
  done
  t1=$(now_ns)
  local total_sec
  total_sec=$(awk "BEGIN {printf \"%.4f\", ($t1 - $t0) / 1e9}")
  awk "BEGIN {fps=$count/$total_sec; lat=$total_sec*1000/$count; tput=$count*$fsz/1048576.0/$total_sec; printf \"%.4f %.4f %.2f %.4f\", $total_sec, fps, lat, tput}"
}

# N files in ONE session via mput (batch)
bench_nasfs_batch_put() {
  local fsz=$1 count=$2
  local tfile="$BENCH_ROOT/src_${fsz}.bin"
  rm -f "$STORAGE_DIR"/*
  # build args: same source file, unique remote names
  local args=()
  for i in $(seq 1 "$count"); do args+=("$tfile"); done
  # mput uploads each file as basename of local path — all same name, server overwrites.
  # Use symlinks with unique names to get unique remote filenames.
  local ldir="$BENCH_ROOT/mput_src_$$"
  mkdir -p "$ldir"
  for i in $(seq 1 "$count"); do
    ln -sf "$tfile" "$ldir/iops_${i}_$$.bin"
  done
  local largs=()
  for i in $(seq 1 "$count"); do largs+=("$ldir/iops_${i}_$$.bin"); done

  local t0 t1
  t0=$(now_ns)
  $THROTTLE nasfs_env "$CLIENT_BIN" mput "${largs[@]}" >/dev/null 2>&1
  t1=$(now_ns)
  rm -rf "$ldir"
  local total_sec
  total_sec=$(awk "BEGIN {printf \"%.4f\", ($t1 - $t0) / 1e9}")
  awk "BEGIN {fps=$count/$total_sec; lat=$total_sec*1000/$count; tput=$count*$fsz/1048576.0/$total_sec; printf \"%.4f %.4f %.2f %.4f\", $total_sec, fps, lat, tput}"
}

# N files in ONE session via mget (batch)
bench_nasfs_batch_get() {
  local fsz=$1 count=$2
  local ldir="$BENCH_ROOT/mget_dst_$$"
  mkdir -p "$ldir"
  local remotes=()
  for i in $(seq 1 "$count"); do remotes+=("iops_${i}_$$.bin"); done
  local t0 t1
  # mget downloads each remote to cwd basename; cd to ldir
  t0=$(now_ns)
  (cd "$ldir" && $THROTTLE nasfs_env "$CLIENT_BIN" mget "${remotes[@]}" >/dev/null 2>&1)
  t1=$(now_ns)
  rm -rf "$ldir"
  local total_sec
  total_sec=$(awk "BEGIN {printf \"%.4f\", ($t1 - $t0) / 1e9}")
  awk "BEGIN {fps=$count/$total_sec; lat=$total_sec*1000/$count; tput=$count*$fsz/1048576.0/$total_sec; printf \"%.4f %.4f %.2f %.4f\", $total_sec, fps, lat, tput}"
}

# SFTP batches all files in ONE session (sftp -b batchfile)
bench_sftp_put_batch() {
  local file=$1 count=$2 fsz=$3
  local remote_dir="/tmp/sftp_iops_$$"
  local batchfile="$BENCH_ROOT/sftp_put_batch.txt"

  printf "mkdir %s\n" "$remote_dir" \
    | sftp "${SFTP_OPTS[@]}" "$SFTP_USER@$SFTP_HOST" >/dev/null 2>&1 || true

  # build batch: N put commands in one session
  : > "$batchfile"
  for i in $(seq 1 "$count"); do
    echo "put $file $remote_dir/f_${i}" >> "$batchfile"
  done

  local t0 t1
  t0=$(now_ns)
  sftp "${SFTP_OPTS[@]}" -b "$batchfile" "$SFTP_USER@$SFTP_HOST" >/dev/null 2>&1
  t1=$(now_ns)

  # cleanup remote
  : > "$batchfile"
  for i in $(seq 1 "$count"); do echo "rm $remote_dir/f_${i}" >> "$batchfile"; done
  echo "rmdir $remote_dir" >> "$batchfile"
  sftp "${SFTP_OPTS[@]}" -b "$batchfile" "$SFTP_USER@$SFTP_HOST" >/dev/null 2>&1 || true

  local total_sec fps lat_ms throughput
  total_sec=$(awk "BEGIN {printf \"%.4f\", ($t1 - $t0) / 1e9}")
  fps=$(awk       "BEGIN {printf \"%.4f\", $count / $total_sec}")
  lat_ms=$(awk    "BEGIN {printf \"%.2f\",  $total_sec * 1000 / $count}")
  throughput=$(awk "BEGIN {printf \"%.4f\", ($count * $fsz / 1048576.0) / $total_sec}")
  echo "$total_sec $fps $lat_ms $throughput"
}

bench_sftp_get_batch() {
  local file=$1 count=$2 fsz=$3
  local remote_dir="/tmp/sftp_iops_src_$$"
  local batchfile="$BENCH_ROOT/sftp_get_batch.txt"
  local local_dir="$BENCH_ROOT/sftp_got"
  mkdir -p "$local_dir"

  # upload all files first (setup)
  printf "mkdir %s\n" "$remote_dir" \
    | sftp "${SFTP_OPTS[@]}" "$SFTP_USER@$SFTP_HOST" >/dev/null 2>&1 || true
  : > "$batchfile"
  for i in $(seq 1 "$count"); do echo "put $file $remote_dir/f_${i}" >> "$batchfile"; done
  sftp "${SFTP_OPTS[@]}" -b "$batchfile" "$SFTP_USER@$SFTP_HOST" >/dev/null 2>&1

  # time the batch GET in one session
  : > "$batchfile"
  for i in $(seq 1 "$count"); do echo "get $remote_dir/f_${i} $local_dir/f_${i}" >> "$batchfile"; done

  local t0 t1
  t0=$(now_ns)
  sftp "${SFTP_OPTS[@]}" -b "$batchfile" "$SFTP_USER@$SFTP_HOST" >/dev/null 2>&1
  t1=$(now_ns)

  rm -rf "$local_dir"
  # cleanup remote
  : > "$batchfile"
  for i in $(seq 1 "$count"); do echo "rm $remote_dir/f_${i}" >> "$batchfile"; done
  echo "rmdir $remote_dir" >> "$batchfile"
  sftp "${SFTP_OPTS[@]}" -b "$batchfile" "$SFTP_USER@$SFTP_HOST" >/dev/null 2>&1 || true

  local total_sec fps lat_ms throughput
  total_sec=$(awk "BEGIN {printf \"%.4f\", ($t1 - $t0) / 1e9}")
  fps=$(awk       "BEGIN {printf \"%.4f\", $count / $total_sec}")
  lat_ms=$(awk    "BEGIN {printf \"%.2f\",  $total_sec * 1000 / $count}")
  throughput=$(awk "BEGIN {printf \"%.4f\", ($count * $fsz / 1048576.0) / $total_sec}")
  echo "$total_sec $fps $lat_ms $throughput"
}

# ---- Header ----
echo ""
echo -e "${BOLD}NASFS small-file IOPS benchmark vs SFTP — $(date)${NC}"
echo -e "Throttle: $THROTTLE"
echo -e "Files per batch: $COUNT   Runs: $RUNS (median)\n"
echo -e "${CYAN}Note: NASFS = new PQC connection per file | SFTP = single session for all files${NC}\n"

# pre-generate source files
for fsz in "${FILE_SIZES[@]}"; do
  tfile="$BENCH_ROOT/src_${fsz}.bin"
  dd if=/dev/urandom of="$tfile" bs="$fsz" count=1 2>/dev/null
done

start_server

declare -A SER_FPS_PUT SER_FPS_GET SER_LAT_PUT SER_LAT_GET
declare -A BAT_FPS_PUT BAT_FPS_GET BAT_LAT_PUT BAT_LAT_GET

hdr="%-8s  %-5s  %8s  %8s  %9s  %9s\n"
row="%-8s  %-5s  %6.2f/s  %6.2f/s  %6.0f ms  %6.0f ms\n"

# ---- NASFS serial (one connection per file) ----
echo -e "${CYAN}=== NASFS serial (new PQC connection per file) ===${NC}"
printf "$hdr" "FileSize" "Dir" "Files/s" "Files/s" "Lat/file" "Lat/file"
printf "$hdr" "--------" "---" "[serial]" "[batch]" "[serial]" "[batch]"

for fidx in "${!FILE_SIZES[@]}"; do
  fsz="${FILE_SIZES[$fidx]}"
  flbl="${FILE_LABELS[$fidx]}"

  # --- serial PUT ---
  ser_put_fps=(); ser_put_lat=()
  for run in $(seq 1 $RUNS); do
    read -r total fps lat tput <<< "$(bench_nasfs_serial_put "$fsz" "$COUNT")"
    ser_put_fps+=("$fps"); ser_put_lat+=("$lat")
    echo "nasfs_serial,${fsz},put,${run},${COUNT},${total},${fps},${lat},${tput}" >> "$CSV"
  done
  SER_FPS_PUT["$flbl"]=$(median "${ser_put_fps[@]}")
  SER_LAT_PUT["$flbl"]=$(median "${ser_put_lat[@]}")

  # --- batch PUT (mput) ---
  bat_put_fps=(); bat_put_lat=()
  for run in $(seq 1 $RUNS); do
    read -r total fps lat tput <<< "$(bench_nasfs_batch_put "$fsz" "$COUNT")"
    bat_put_fps+=("$fps"); bat_put_lat+=("$lat")
    echo "nasfs_batch,${fsz},put,${run},${COUNT},${total},${fps},${lat},${tput}" >> "$CSV"
  done
  BAT_FPS_PUT["$flbl"]=$(median "${bat_put_fps[@]}")
  BAT_LAT_PUT["$flbl"]=$(median "${bat_put_lat[@]}")

  printf "$row" "$flbl" "PUT" \
    "${SER_FPS_PUT[$flbl]}" "${BAT_FPS_PUT[$flbl]}" \
    "${SER_LAT_PUT[$flbl]}" "${BAT_LAT_PUT[$flbl]}"

  # --- serial GET ---
  ser_get_fps=(); ser_get_lat=()
  for run in $(seq 1 $RUNS); do
    read -r total fps lat tput <<< "$(bench_nasfs_serial_get "$fsz" "$COUNT")"
    ser_get_fps+=("$fps"); ser_get_lat+=("$lat")
    echo "nasfs_serial,${fsz},get,${run},${COUNT},${total},${fps},${lat},${tput}" >> "$CSV"
  done
  SER_FPS_GET["$flbl"]=$(median "${ser_get_fps[@]}")
  SER_LAT_GET["$flbl"]=$(median "${ser_get_lat[@]}")

  # --- batch GET (mget) ---
  bat_get_fps=(); bat_get_lat=()
  for run in $(seq 1 $RUNS); do
    read -r total fps lat tput <<< "$(bench_nasfs_batch_get "$fsz" "$COUNT")"
    bat_get_fps+=("$fps"); bat_get_lat+=("$lat")
    echo "nasfs_batch,${fsz},get,${run},${COUNT},${total},${fps},${lat},${tput}" >> "$CSV"
  done
  BAT_FPS_GET["$flbl"]=$(median "${bat_get_fps[@]}")
  BAT_LAT_GET["$flbl"]=$(median "${bat_get_lat[@]}")

  printf "$row" "$flbl" "GET" \
    "${SER_FPS_GET[$flbl]}" "${BAT_FPS_GET[$flbl]}" \
    "${SER_LAT_GET[$flbl]}" "${BAT_LAT_GET[$flbl]}"
done

stop_server

# ---- SFTP IOPS ----
echo ""
echo -e "${CYAN}=== SFTP (${COUNT} files, single session, batch commands) ===${NC}"
printf "%-8s  %-5s  %-8s  %-10s  %-12s  %-12s\n" \
  "FileSize" "Dir" "Files/s" "Latency" "Throughput" "Total(${COUNT}f)"
printf "%-8s  %-5s  %-8s  %-10s  %-12s  %-12s\n" \
  "--------" "---" "-------" "-------" "----------" "------------"

declare -A S_FPS_PUT S_FPS_GET S_LAT_PUT S_LAT_GET S_TPUT_PUT S_TPUT_GET

for fidx in "${!FILE_SIZES[@]}"; do
  fsz="${FILE_SIZES[$fidx]}"
  flbl="${FILE_LABELS[$fidx]}"
  tfile="$BENCH_ROOT/src_${fsz}.bin"

  put_fps=(); put_lat=(); put_tput=(); put_total=()
  for run in $(seq 1 $RUNS); do
    read -r total fps lat tput <<< "$(bench_sftp_put_batch "$tfile" "$COUNT" "$fsz")"
    put_fps+=("$fps"); put_lat+=("$lat"); put_tput+=("$tput"); put_total+=("$total")
    echo "sftp,${fsz},put,${run},${COUNT},${total},${fps},${lat},${tput}" >> "$CSV"
  done
  mfps=$(median "${put_fps[@]}")
  mlat=$(median "${put_lat[@]}")
  mtput=$(median "${put_tput[@]}")
  mtotal=$(median "${put_total[@]}")
  S_FPS_PUT["$flbl"]="$mfps"; S_LAT_PUT["$flbl"]="$mlat"; S_TPUT_PUT["$flbl"]="$mtput"

  printf "%-8s  %-5s  %6.2f/s   %6.0f ms    %6.2f MB/s    %.1f s\n" \
    "$flbl" "PUT" "$mfps" "$mlat" "$mtput" "$mtotal"

  get_fps=(); get_lat=(); get_tput=(); get_total=()
  for run in $(seq 1 $RUNS); do
    read -r total fps lat tput <<< "$(bench_sftp_get_batch "$tfile" "$COUNT" "$fsz")"
    get_fps+=("$fps"); get_lat+=("$lat"); get_tput+=("$tput"); get_total+=("$total")
    echo "sftp,${fsz},get,${run},${COUNT},${total},${fps},${lat},${tput}" >> "$CSV"
  done
  mfps=$(median "${get_fps[@]}")
  mlat=$(median "${get_lat[@]}")
  mtput=$(median "${get_tput[@]}")
  mtotal=$(median "${get_total[@]}")
  S_FPS_GET["$flbl"]="$mfps"; S_LAT_GET["$flbl"]="$mlat"; S_TPUT_GET["$flbl"]="$mtput"

  printf "%-8s  %-5s  %6.2f/s   %6.0f ms    %6.2f MB/s    %.1f s\n" \
    "$flbl" "GET" "$mfps" "$mlat" "$mtput" "$mtotal"
done

# ---- Comparison table ----
echo ""
echo -e "${BOLD}=== Summary: serial vs batch vs SFTP (${COUNT} files, median ${RUNS} runs) ===${NC}"
printf "%-8s  %-5s  %9s  %9s  %9s  %9s  %9s  %9s\n" \
  "Size" "Dir" "ser f/s" "bat f/s" "sftp f/s" "ser lat" "bat lat" "sftp lat"
printf "%-8s  %-5s  %9s  %9s  %9s  %9s  %9s  %9s\n" \
  "-----" "---" "-------" "-------" "--------" "-------" "-------" "--------"

for flbl in "${FILE_LABELS[@]}"; do
  for dir in PUT GET; do
    if [[ "$dir" == "PUT" ]]; then
      ser_fps="${SER_FPS_PUT[$flbl]:-0}"; bat_fps="${BAT_FPS_PUT[$flbl]:-0}"; sftp_fps="${S_FPS_PUT[$flbl]:-0}"
      ser_lat="${SER_LAT_PUT[$flbl]:-0}"; bat_lat="${BAT_LAT_PUT[$flbl]:-0}"; sftp_lat="${S_LAT_PUT[$flbl]:-0}"
    else
      ser_fps="${SER_FPS_GET[$flbl]:-0}"; bat_fps="${BAT_FPS_GET[$flbl]:-0}"; sftp_fps="${S_FPS_GET[$flbl]:-0}"
      ser_lat="${SER_LAT_GET[$flbl]:-0}"; bat_lat="${BAT_LAT_GET[$flbl]:-0}"; sftp_lat="${S_LAT_GET[$flbl]:-0}"
    fi
    speedup=$(awk "BEGIN {printf \"%.2f\", $bat_fps / ($ser_fps > 0 ? $ser_fps : 1)}")
    printf "%-8s  %-5s  %7.2f/s  %7.2f/s  %7.2f/s  %6.0f ms  %6.0f ms  %6.0f ms  batch %sx vs serial\n" \
      "$flbl" "$dir" "$ser_fps" "$bat_fps" "$sftp_fps" \
      "$ser_lat" "$bat_lat" "$sftp_lat" "$speedup"
  done
done

echo ""
echo -e "${CYAN}serial  = one PQC KEX + auth per file (baseline overhead)${NC}"
echo -e "${CYAN}batch   = one PQC KEX + auth for all N files (mput/mget session reuse)${NC}"
echo -e "${CYAN}sftp    = one SSH handshake for all N files (sftp -b batchfile)${NC}"
echo -e "CSV: ${BOLD}${CSV}${NC}"
