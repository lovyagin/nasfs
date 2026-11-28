# shellcheck shell=bash
# Shared SFTP batch scratch management. Source from a benchmark script.

sftp_batch() {
  sftp "${SFTP_OPTS[@]}" -b - "$SFTP_USER@$SFTP_HOST"
}

allocate_sftp_scratch() {
  local token
  token=$(python3 -c 'import secrets; print(secrets.token_hex(16))') || return
  local candidate="/tmp/nasfs-bench-$token"
  if ! printf 'mkdir %s\n' "$candidate" | sftp_batch >/dev/null; then
    printf 'Cannot allocate SFTP scratch directory %s\n' "$candidate" >&2
    return 1
  fi
  remote_dir=$candidate
}

cleanup_sftp_scratch() {
  local status=$? i
  local file_count=$1
  if ! {
    for ((i = 1; i <= file_count; i++)); do
      printf -- '-rm %s/f_%d\n' "$remote_dir" "$i"
    done
    printf 'rmdir %s\n' "$remote_dir"
  } | sftp_batch >/dev/null; then
    printf 'Cannot remove SFTP scratch directory %s\n' "$remote_dir" >&2
    if (( status == 0 )); then status=1; fi
  fi
  exit "$status"
}

prepare_sftp_scratch() {
  allocate_sftp_scratch || return
  trap 'cleanup_sftp_scratch "$count"' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
}
