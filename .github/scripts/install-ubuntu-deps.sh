#!/usr/bin/env bash

set -euo pipefail

if command -v sudo >/dev/null 2>&1; then
  SUDO="sudo"
else
  SUDO=""
fi

run_root() {
  if [ -n "$SUDO" ]; then
    "$SUDO" "$@"
  else
    "$@"
  fi
}

run_root apt-get update
run_root apt-get install -y \
  autoconf \
  automake \
  build-essential \
  cmake \
  git \
  libssl-dev \
  libsodium-dev \
  libtool \
  libuv1-dev \
  ninja-build \
  pkg-config \
  shellcheck \
  clang \
  clang-tidy \
  clang-format

if run_root apt-get install -y liboqs-dev; then
  exit 0
fi

if ! pkg-config --exists liboqs; then
  rm -rf /tmp/liboqs
  git clone --depth 1 --branch 0.15.0 https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs
  cmake -S /tmp/liboqs -B /tmp/liboqs/build \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_USE_OPENSSL=ON \
    -DCMAKE_INSTALL_PREFIX=/usr/local
  cmake --build /tmp/liboqs/build
  run_root cmake --install /tmp/liboqs/build
fi
