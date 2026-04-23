#!/usr/bin/env bash

set -euo pipefail

sudo apt-get update
sudo apt-get install -y \
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
  clang-format

if ! pkg-config --exists liboqs; then
  git clone --depth 1 --branch 0.15.0 https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs
  cmake -S /tmp/liboqs -B /tmp/liboqs/build \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_USE_OPENSSL=ON \
    -DCMAKE_INSTALL_PREFIX=/usr/local
  cmake --build /tmp/liboqs/build
  sudo cmake --install /tmp/liboqs/build
fi
