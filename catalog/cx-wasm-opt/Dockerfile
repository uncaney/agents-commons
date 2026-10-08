# syntax=docker/dockerfile:1
# cx-wasm-opt: wasm binary on stdin -> optimized wasm (fixed -Os style) on stdout, binaryen
# library on wasm32-wasi (SPEC-v2 15.4; pinned, it is over 4 MiB). Build context = catalog/ ;
# driven by catalog/build.sh:
#   docker build -f cx-wasm-opt/Dockerfile --output type=local,dest=out/cx-wasm-opt .
# Pins: wasi-sdk 24, binaryen version_133 (sha256 below).
#
# STATUS: unverified on the server and the riskiest build of the catalog. Binaryen assumes two
# things wasi-sdk's libc++ lacks: threads (std::thread/mutex/condition_variable, shimmed to
# single-threaded headers in shim/) and C++ exceptions (compiled with -fignore-exceptions: try
# bodies run as-is, throw becomes a call to __cxa_throw, provided by cxa_stubs.cc as `err ...`
# + exit 1). The find_package(Threads) line is replaced by an empty interface target. Expect to
# iterate on this file on the server; README.md lists the fallbacks.

# --- shared toolchain stage (identical text in every catalog Dockerfile => one cached layer)
FROM debian:bookworm-slim AS sdk
ARG WASI_SDK_VERSION=24
ARG WASI_SDK_SHA256=c6c38aab56e5de88adf6c1ebc9c3ae8da72f88ec2b656fb024eda8d4167a0bc5
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl xz-utils unzip make cmake patch gcc g++ libc6-dev python3 \
    && rm -rf /var/lib/apt/lists/*
RUN [ "$(uname -m)" = x86_64 ] || { echo "the wasi-sdk pin is x86_64-linux only" >&2; exit 1; } \
 && curl -fsSL -o /tmp/wasi-sdk.tar.gz "https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-${WASI_SDK_VERSION}/wasi-sdk-${WASI_SDK_VERSION}.0-x86_64-linux.tar.gz" \
 && echo "${WASI_SDK_SHA256}  /tmp/wasi-sdk.tar.gz" | sha256sum -c - \
 && mkdir -p /opt/wasi-sdk && tar -xzf /tmp/wasi-sdk.tar.gz -C /opt/wasi-sdk --strip-components=1 \
 && rm /tmp/wasi-sdk.tar.gz
ENV WASI_SDK_PATH=/opt/wasi-sdk \
    WASI_SYSROOT=/opt/wasi-sdk/share/wasi-sysroot \
    SOURCE_DATE_EPOCH=0 \
    CX_CFLAGS="-O2 -ffile-prefix-map=/src=. -D_WASI_EMULATED_SIGNAL -D_WASI_EMULATED_PROCESS_CLOCKS -D_WASI_EMULATED_GETPID" \
    CX_LDFLAGS="-lwasi-emulated-signal -lwasi-emulated-process-clocks -lwasi-emulated-getpid -Wl,--strip-all"
# host-native copy of the catalog's own strip tool: drops producers/name sections after linking
COPY cx-wasm-strip/cx-wasm-strip.c /src/cx-wasm-strip/cx-wasm-strip.c
RUN gcc -O2 -o /usr/local/bin/cx-wasm-strip /src/cx-wasm-strip/cx-wasm-strip.c

# --- binaryen static library for wasm32-wasi
FROM sdk AS build
ARG BINARYEN_VERSION=version_133
ARG BINARYEN_SHA256=2f3e3d9edc56751499571da073a8a81943ca3fcbc08a945d2c619a7a1d4eb88b
WORKDIR /src
RUN curl -fsSL -o binaryen.tar.gz "https://github.com/WebAssembly/binaryen/archive/refs/tags/${BINARYEN_VERSION}.tar.gz" \
 && echo "${BINARYEN_SHA256}  binaryen.tar.gz" | sha256sum -c - \
 && tar -xzf binaryen.tar.gz && mv "binaryen-${BINARYEN_VERSION}" binaryen && rm binaryen.tar.gz
COPY cx-wasm-opt/shim/ /src/shim/
RUN sed -i 's/^find_package(Threads REQUIRED)$/add_library(Threads::Threads INTERFACE IMPORTED)/' binaryen/CMakeLists.txt \
 && grep -n "Threads::Threads INTERFACE IMPORTED" binaryen/CMakeLists.txt
RUN cmake -S binaryen -B binaryen/build \
      -DCMAKE_TOOLCHAIN_FILE="$WASI_SDK_PATH/share/cmake/wasi-sdk.cmake" \
      -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTS=OFF -DBUILD_TOOLS=OFF \
      -DBUILD_LLVM_DWARF=OFF -DBYN_ENABLE_LTO=OFF -DENABLE_WERROR=OFF -DINSTALL_LIBS=OFF \
      -DCMAKE_CXX_FLAGS="$CX_CFLAGS -fignore-exceptions -I/src/shim" -DCMAKE_C_FLAGS="$CX_CFLAGS" \
 && cmake --build binaryen/build --target binaryen -j"$(nproc)" \
 && ls -l binaryen/build/lib/libbinaryen.a

# --- wrapper + link (binaryen's parser recurses deeply: 16 MiB linear stack)
COPY cx-wasm-opt/cx-wasm-opt.cc cx-wasm-opt/cxa_stubs.cc /src/cx-wasm-opt/
RUN set -eu; CXX="$WASI_SDK_PATH/bin/clang++ --target=wasm32-wasi --sysroot=$WASI_SYSROOT"; mkdir -p /out; \
    $CXX $CX_CFLAGS -std=c++20 -fignore-exceptions -Wall -I/src/shim -I binaryen/src -I binaryen/build/src \
      cx-wasm-opt/cx-wasm-opt.cc cx-wasm-opt/cxa_stubs.cc binaryen/build/lib/libbinaryen.a \
      $CX_LDFLAGS -Wl,-z,stack-size=16777216 -o /out/cx-wasm-opt.raw.wasm \
 && cx-wasm-strip < /out/cx-wasm-opt.raw.wasm > /out/cx-wasm-opt.wasm \
 && ls -l /out/cx-wasm-opt.wasm && sha256sum /out/cx-wasm-opt.wasm

FROM scratch AS export
COPY --from=build /out/cx-wasm-opt.wasm /cx-wasm-opt.wasm
