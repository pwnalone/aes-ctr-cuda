#!/usr/bin/bash

set -e

BUILD_TYPE=${1:-Release}

mkdir -p build
cd build
cmake .. -DCMAKE_BUILD_TYPE=${BUILD_TYPE}
cmake --build .
