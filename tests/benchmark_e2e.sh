#!/usr/bin/env bash
# NASFS End-to-End Transfer Benchmark
#
# Measures upload/download throughput for all three file encryption ciphers
# across a range of file sizes and compares with SFTP on the same loopback.
#
# Usage:
#   ./benchmark_e2e.sh [--throttle] [--sftp-host HOST] [--sftp-user USER]
#
# Options:
#   --throttle        Run under 'nice -n 19' to simulate a single-threaded,
#                     CPU-starved server (no hardware pinning on macOS).
#   --sftp-host HOST  SFTP/SSH host for comparison (default: localhost).
#   --sftp-user USER  SFTP username (default: $USER).
#
# Environment:
#   NASFS_JPEG  Path to a JPEG to include in the transfer tests (optional).
#               Falls back to the first *.jpeg found in ~/Downloads if unset.

set -euo pipefail

# ── Paths ──────────────────────────────────────────────────────────────────────
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$ROOT_DIR/build"
SERVER_BIN="$BUILD_DIR/nasfs_server"
CLIENT_BIN="$BUILD_DIR/nasfs_client"
BENCH_DIR="$BUILD_DIR/bench_workspace"
STORAGE_DIR="$BENCH_DIR/storage"
LOG_DIR="$BENCH_DIR/logs"
KEY_FILE="$BENCH_DIR/bench.key"
AUTH_KEYS="$BENCH_DIR/authorized_keys"
CSV_OUT="$BENCH_DIR/results_$(date +%Y%m%d_%H%M%S).csv"
SERVER_PORT=18080

# ── Colours ───────────────────────────────────────────────────────────────────
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'; NC='\033[0m'

# ── Argument parsing ───────────────────────────────────────────────────────────
THROTTLE=0
SFTP_HOST="localhost"
SFTP_USER="${USER:-root}"
while [[ $# -gt 0 ]]; do
    case $1 in
        --throttle)   THROTTLE=1; shift ;;
        --sftp-host)  SFTP_HOST="$2"; shift 2 ;;
        --sftp-user)  SFTP_USER="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# ── Helpers ────────────────────────────────────────────────────────────────────
ts() { python3 -c "import time; print(time.monotonic())"; }

elapsed() {   # elapsed <t0> <t1>
    python3 -c "print(round($2 - $1, 4))"
}

throughput_mbs() {   # throughput_mbs <bytes> <seconds>
    python3 -c "b=$1; s=$2; print('---' if s<=0 else f'{b/1024/1024/s:.2f}')"
}

median_of_3() {
    python3 -c "
import sys
vals = sorted(float(x) for x in sys.argv[1:])
print(vals[1])
" "$1" "$2" "$3"
}

run_client() {
    local cipher=$1; shift
    local args=("$@")
    env NASFS_KEX_ALGORITHMS="ML-KEM-512" \
        NASFS_CIPHER_ALGORITHMS="xchacha20poly1305" \
        NASFS_AUTH_METHOD="password" \
        NASFS_AUTH_USER="bench" \
        NASFS_AUTH_PASSWORD="bench-pass" \
        NASFS_ENCRYPTION_KEY="benchmark-encryption-key-32chars!" \
        NASFS_FILE_CIPHER="$cipher" \
        NASFS_FILE_HASH="blake2b" \
        HOME="$BENCH_DIR" \
        "$CLIENT_BIN" "${args[@]}" >/dev/null 2>&1
}

maybe_nice() {
    if [[ $THROTTLE -eq 1 ]]; then
        nice -n 19 "$@"
    else
        "$@"
    fi
}

# ── Setup ──────────────────────────────────────────────────────────────────────
mkdir -p "$STORAGE_DIR" "$LOG_DIR" "$BENCH_DIR/.nasfs"

if [[ ! -f "$SERVER_BIN" || ! -f "$CLIENT_BIN" ]]; then
    printf "${R}Error: binaries not found under %s. Run cmake --build first.${NC}\n" "$BUILD_DIR"
    exit 1
fi

# Generate client key for the bench (password auth only, but keygen still needed
# in case an auth method is added later; we skip pubkey here).
if [[ ! -f "$KEY_FILE" ]]; then
    "$CLIENT_BIN" keygen "$KEY_FILE" "$AUTH_KEYS" ML-DSA-65 >/dev/null 2>&1
fi

# Server config
cat >"$BENCH_DIR/bench_server.conf" <<EOF
ListenAddr 127.0.0.1
Port $SERVER_PORT
MaxConn 32
LogFile $LOG_DIR/server.log
LogLevel Error
DaemonMode No
PidFile $LOG_DIR/server.pid
StorageDir $STORAGE_DIR
KexAlgorithms ML-KEM-512
CipherAlgorithms xchacha20poly1305
AuthMethods password
AuthPassword bench-pass
AuthorizedKeysFile $AUTH_KEYS
PubKeyAuthAlgorithms ML-DSA-65
EOF

# Override port in client via env — client reads NASFS_SERVER_PORT if set
# (fallback: connect to 8080). We patch the port by temporarily exporting it.
export NASFS_SERVER_PORT=$SERVER_PORT

# ── Test files ─────────────────────────────────────────────────────────────────
declare -A FILE_LABELS
declare -A FILE_PATHS

make_file() {
    local label=$1 path=$2 size_bytes=$3
    if [[ ! -f "$path" ]]; then
        dd if=/dev/urandom of="$path" bs=1024 count=$(( size_bytes / 1024 )) 2>/dev/null
    fi
    FILE_LABELS[$label]=$label
    FILE_PATHS[$label]=$path
}

make_file "4 KB"   "$BENCH_DIR/f_4k.bin"   4096
make_file "64 KB"  "$BENCH_DIR/f_64k.bin"  65536
make_file "1 MB"   "$BENCH_DIR/f_1m.bin"   1048576
make_file "10 MB"  "$BENCH_DIR/f_10m.bin"  10485760
make_file "100 MB" "$BENCH_DIR/f_100m.bin" 104857600

# Optional JPEG
JPEG_PATH="${NASFS_JPEG:-}"
if [[ -z "$JPEG_PATH" ]]; then
    JPEG_PATH=$(find ~/Downloads -maxdepth 1 -name "*.jpeg" -o -name "*.jpg" 2>/dev/null | head -1 || true)
fi
if [[ -n "$JPEG_PATH" && -f "$JPEG_PATH" ]]; then
    JPEG_SIZE=$(wc -c < "$JPEG_PATH" | tr -d ' ')
    cp "$JPEG_PATH" "$BENCH_DIR/cat.jpeg"
    FILE_LABELS["cat.jpeg"]="cat.jpeg"
    FILE_PATHS["cat.jpeg"]="$BENCH_DIR/cat.jpeg"
    JPEG_SIZE_LABEL="$(python3 -c "print(f'{$JPEG_SIZE/1024:.0f} KB')")"
    printf "${B}[info]${NC} JPEG found: %s (%s)\n" "$(basename "$JPEG_PATH")" "$JPEG_SIZE_LABEL"
fi

FILE_ORDER=("4 KB" "64 KB" "1 MB" "10 MB" "100 MB")
[[ -n "${FILE_PATHS[cat.jpeg]:-}" ]] && FILE_ORDER+=("cat.jpeg")

CIPHERS=("xsalsa20poly1305" "xchacha20poly1305" "aes256gcm")

# ── Start server ───────────────────────────────────────────────────────────────
pkill -f "nasfs_server" 2>/dev/null || true
sleep 0.4

maybe_nice "$SERVER_BIN" "$BENCH_DIR/bench_server.conf" >"$LOG_DIR/server_stdout.log" 2>&1 &
SERVER_PID=$!

cleanup() {
    kill "$SERVER_PID" 2>/dev/null || true
    pkill -f "nasfs_server" 2>/dev/null || true
}
trap cleanup EXIT

sleep 1.5
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    printf "${R}Server failed to start. Log:${NC}\n"
    cat "$LOG_DIR/server_stdout.log"
    exit 1
fi

MODE_LABEL="normal"
[[ $THROTTLE -eq 1 ]] && MODE_LABEL="throttled (nice -n 19)"

printf "\n${Y}══════════════════════════════════════════════════════════════════${NC}\n"
printf "${Y}   NASFS End-to-End Transfer Benchmark${NC}\n"
printf "${Y}   Mode: %s${NC}\n" "$MODE_LABEL"
printf "${Y}══════════════════════════════════════════════════════════════════${NC}\n\n"

# ── CSV header ─────────────────────────────────────────────────────────────────
echo "mode,tool,cipher,file_size,direction,throughput_mbs,elapsed_s" > "$CSV_OUT"

# ── Benchmark function ─────────────────────────────────────────────────────────
declare -A RESULTS  # key: "cipher|size|direction" → throughput MB/s

bench_nasfs() {
    local cipher=$1 size_label=$2 filepath=$3 direction=$4
    local bytes
    bytes=$(wc -c < "$filepath" | tr -d ' ')
    local remote_name
    remote_name="bench_${cipher}_${size_label// /_}_${direction}.bin"
    local out_file="$BENCH_DIR/got_${cipher}_${size_label// /_}.bin"

    local t0 t1 t2 t3 elapsed_a elapsed_b elapsed_c best_elapsed

    # Warm-up run (not counted)
    if [[ "$direction" == "put" ]]; then
        run_client "$cipher" put "$filepath" "$remote_name" 2>/dev/null || true
    fi

    # 3 timed runs
    local elapsed_arr=()
    for run in 1 2 3; do
        rm -f "$out_file" "$STORAGE_DIR/$remote_name"
        if [[ "$direction" == "put" ]]; then
            t0=$(ts)
            run_client "$cipher" put "$filepath" "$remote_name"
            t1=$(ts)
        else
            # PUT first so we have something to GET
            run_client "$cipher" put "$filepath" "$remote_name" 2>/dev/null || true
            t0=$(ts)
            run_client "$cipher" get "$remote_name" "$out_file"
            t1=$(ts)
        fi
        elapsed_arr+=("$(elapsed "$t0" "$t1")")
    done

    local best
    best=$(median_of_3 "${elapsed_arr[0]}" "${elapsed_arr[1]}" "${elapsed_arr[2]}")
    local mbs
    mbs=$(throughput_mbs "$bytes" "$best")

    local key="${cipher}|${size_label}|${direction}"
    RESULTS[$key]="$mbs"

    echo "$MODE_LABEL,nasfs,$cipher,$size_label,$direction,$mbs,$best" >> "$CSV_OUT"
}

# ── SFTP helper ─────────────────────────────────────────────────────────────────
SFTP_OK=0
SFTP_DIR=""
check_sftp() {
    if ssh -o BatchMode=yes -o ConnectTimeout=3 -o StrictHostKeyChecking=no \
        "${SFTP_USER}@${SFTP_HOST}" true 2>/dev/null; then
        SFTP_OK=1
        SFTP_DIR=$(ssh -o BatchMode=yes "${SFTP_USER}@${SFTP_HOST}" \
            "mktemp -d /tmp/nasfs_bench_XXXXXX" 2>/dev/null)
    fi
}

declare -A SFTP_RESULTS
bench_sftp() {
    local cipher_flag=$1 size_label=$2 filepath=$3 direction=$4 label=$5
    local bytes
    bytes=$(wc -c < "$filepath" | tr -d ' ')
    local remote="$SFTP_DIR/$(basename "$filepath")"
    local local_out="$BENCH_DIR/sftp_got_${size_label// /_}.bin"

    local elapsed_arr=()
    for run in 1 2 3; do
        local t0 t1
        rm -f "$local_out"
        if [[ "$direction" == "put" ]]; then
            t0=$(ts)
            sftp $cipher_flag -o BatchMode=yes -o StrictHostKeyChecking=no \
                -b - "${SFTP_USER}@${SFTP_HOST}" <<< "put $filepath $remote" \
                >/dev/null 2>&1
            t1=$(ts)
        else
            # ensure remote file exists
            sftp $cipher_flag -o BatchMode=yes -o StrictHostKeyChecking=no \
                -b - "${SFTP_USER}@${SFTP_HOST}" <<< "put $filepath $remote" \
                >/dev/null 2>&1 || true
            t0=$(ts)
            sftp $cipher_flag -o BatchMode=yes -o StrictHostKeyChecking=no \
                -b - "${SFTP_USER}@${SFTP_HOST}" <<< "get $remote $local_out" \
                >/dev/null 2>&1
            t1=$(ts)
        fi
        elapsed_arr+=("$(elapsed "$t0" "$t1")")
    done

    local best
    best=$(median_of_3 "${elapsed_arr[0]}" "${elapsed_arr[1]}" "${elapsed_arr[2]}")
    local mbs
    mbs=$(throughput_mbs "$bytes" "$best")

    local key="${label}|${size_label}|${direction}"
    SFTP_RESULTS[$key]="$mbs"
    echo "$MODE_LABEL,sftp,$label,$size_label,$direction,$mbs,$best" >> "$CSV_OUT"
}

# ── Run NASFS benchmarks ───────────────────────────────────────────────────────
printf "${B}Running NASFS benchmarks...${NC}\n"
for size_label in "${FILE_ORDER[@]}"; do
    filepath="${FILE_PATHS[$size_label]}"
    printf "  %-10s " "$size_label"
    for cipher in "${CIPHERS[@]}"; do
        printf "."
        bench_nasfs "$cipher" "$size_label" "$filepath" "put"
        bench_nasfs "$cipher" "$size_label" "$filepath" "get"
    done
    printf " done\n"
done

# ── Run SFTP benchmarks (if SSH available) ─────────────────────────────────────
printf "${B}Checking SFTP availability on %s...${NC}\n" "$SFTP_HOST"
check_sftp
if [[ $SFTP_OK -eq 1 ]]; then
    printf "${G}SFTP available. Running comparison...${NC}\n"
    for size_label in "${FILE_ORDER[@]}"; do
        filepath="${FILE_PATHS[$size_label]}"
        printf "  %-10s " "$size_label"
        bench_sftp "-c chacha20-poly1305@openssh.com" "$size_label" "$filepath" \
            "put" "sftp-chacha20"
        bench_sftp "-c chacha20-poly1305@openssh.com" "$size_label" "$filepath" \
            "get" "sftp-chacha20"
        bench_sftp "-c aes256-gcm@openssh.com" "$size_label" "$filepath" \
            "put" "sftp-aes256gcm"
        bench_sftp "-c aes256-gcm@openssh.com" "$size_label" "$filepath" \
            "get" "sftp-aes256gcm"
        printf " done\n"
    done
    # cleanup remote temp dir
    ssh -o BatchMode=yes "${SFTP_USER}@${SFTP_HOST}" "rm -rf $SFTP_DIR" 2>/dev/null || true
else
    printf "${Y}[skip] SSH not available on %s — SFTP columns will show '---'${NC}\n" "$SFTP_HOST"
    printf "${Y}       Enable Remote Login (macOS) or pass --sftp-host to compare.${NC}\n"
fi

# ── Print results table ────────────────────────────────────────────────────────
printf "\n${Y}══════════════════════════════════════════════════════════════════════════════════${NC}\n"
printf "${Y}  Throughput in MB/s  (median of 3 runs)  —  mode: %s${NC}\n" "$MODE_LABEL"
printf "${Y}══════════════════════════════════════════════════════════════════════════════════${NC}\n"

# Header row
printf "\n%-12s │ %s │ %s │ %s │ %s │ %s │ %s │ %s\n" \
    "" \
    "xsalsa20  PUT" "xsalsa20  GET" \
    "xchacha20 PUT" "xchacha20 GET" \
    "aes256gcm PUT" "aes256gcm GET" \
    "sftp-cha20 P/G  sftp-aes256 P/G"

printf "%s\n" "────────────┼──────────────┼──────────────┼──────────────┼──────────────┼──────────────┼──────────────┼─────────────────────────────────"

for size_label in "${FILE_ORDER[@]}"; do
    get_r() {
        local k="${1}|${2}|${3}"
        echo "${RESULTS[$k]:-  ---  }"
    }
    get_s() {
        local k="${1}|${2}|${3}"
        echo "${SFTP_RESULTS[$k]:-  ---  }"
    }

    xs_put=$(get_r "xsalsa20poly1305" "$size_label" "put")
    xs_get=$(get_r "xsalsa20poly1305" "$size_label" "get")
    xc_put=$(get_r "xchacha20poly1305" "$size_label" "put")
    xc_get=$(get_r "xchacha20poly1305" "$size_label" "get")
    ag_put=$(get_r "aes256gcm" "$size_label" "put")
    ag_get=$(get_r "aes256gcm" "$size_label" "get")
    sc_put=$(get_s "sftp-chacha20" "$size_label" "put")
    sc_get=$(get_s "sftp-chacha20" "$size_label" "get")
    sa_put=$(get_s "sftp-aes256gcm" "$size_label" "put")
    sa_get=$(get_s "sftp-aes256gcm" "$size_label" "get")

    printf "%-12s │ %12s │ %12s │ %12s │ %12s │ %12s │ %12s │ %8s / %-8s    %8s / %-8s\n" \
        "$size_label" \
        "$xs_put" "$xs_get" \
        "$xc_put" "$xc_get" \
        "$ag_put" "$ag_get" \
        "$sc_put" "$sc_get" \
        "$sa_put" "$sa_get"
done

printf "\n"
printf "${G}Results saved to: %s${NC}\n\n" "$CSV_OUT"
printf "Cipher legend:\n"
printf "  xsalsa20poly1305  — software stream cipher (Salsa20 + Poly1305 MAC)\n"
printf "  xchacha20poly1305 — software stream cipher (ChaCha20 + Poly1305 MAC)\n"
printf "  aes256gcm         — hardware-accelerated AES-256-GCM (ARM FEAT_AES / x86 AES-NI)\n"
printf "  sftp-chacha20     — OpenSSH chacha20-poly1305@openssh.com\n"
printf "  sftp-aes256gcm    — OpenSSH aes256-gcm@openssh.com\n"
printf "\nNote: connection handshake (ML-KEM-512 PQC key exchange) adds ~5–15 ms fixed\n"
printf "overhead per transfer, which dominates throughput for small files (< 1 MB).\n\n"
