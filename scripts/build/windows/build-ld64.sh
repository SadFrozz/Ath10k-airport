#!/bin/bash
set -euo pipefail
export PATH=/usr/bin:/bin
repo=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$repo/.cache/windows-kext/cctools/cctools"
export CC=gcc CXX=g++ OBJC=gcc OBJCXX=g++
export CFLAGS='-O2 -D_GNU_SOURCE -Wno-error=implicit-function-declaration'
export CXXFLAGS='-O2 -std=gnu++11 -D_GNU_SOURCE'
bash ./autogen.sh
./configure --target=x86_64-apple-darwin11 --disable-clang-as --disable-dependency-tracking
make -C ld64 -j3
