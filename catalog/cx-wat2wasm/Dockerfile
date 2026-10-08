# syntax=docker/dockerfile:1
# cx-wat2wasm: WAT text on stdin -> wasm binary on stdout, wabt library on wasm32-wasi
# (SPEC-v2 15.4 toolchain services). Build context = catalog/ ; driven by catalog/build.sh:
#   docker build -f cx-wat2wasm/Dockerfile --output type=local,dest=out/cx-wat2wasm .
# Pins: wasi-sdk 24, wabt 1.0.42 (sha256 below). wabt builds with -fno-exceptions by default,
# which is what wasi-sdk's libc++ needs. Expected size well under 4 MiB.
# STATUS: unverified on the server (no Docker on the Mac); the wabt stage below is byte-identical
# in cx-wasm-validate/Dockerfile and cx-wasm-strip/Dockerfile so BuildKit builds it once.

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

# --- wabt static library for wasm32-wasi (shared text with the other wabt tools)
FROM sdk AS wabt
ARG WABT_VERSION=1.0.42
ARG WABT_SHA256=a76cda3c174a43097863a07fc0b0c202f770f53e21806ea2636f167d1ffb1e30
WORKDIR /src
RUN curl -fsSL -o wabt.tar.xz "https://github.com/WebAssembly/wabt/releases/download/${WABT_VERSION}/wabt-${WABT_VERSION}.tar.xz" \
 && echo "${WABT_SHA256}  wabt.tar.xz" | sha256sum -c - \
 && tar -xJf wabt.tar.xz && mv "wabt-${WABT_VERSION}" wabt && rm wabt.tar.xz
RUN cmake -S wabt -B wabt/build \
      -DCMAKE_TOOLCHAIN_FILE="$WASI_SDK_PATH/share/cmake/wasi-sdk.cmake" \
      -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=OFF -DBUILD_TOOLS=OFF -DBUILD_LIBWASM=OFF \
      -DUSE_INTERNAL_SHA256=ON -DWITH_EXCEPTIONS=OFF -DWABT_INSTALL_RULES=OFF \
      -DCMAKE_CXX_FLAGS="$CX_CFLAGS" -DCMAKE_C_FLAGS="$CX_CFLAGS" \
 && cmake --build wabt/build --target wabt -j"$(nproc)" \
 && ls -l wabt/build/libwabt.a

# --- wrapper + link
FROM wabt AS build
COPY cx-wat2wasm/cx-wat2wasm.cc /src/cx-wat2wasm/
RUN set -eu; CXX="$WASI_SDK_PATH/bin/clang++ --target=wasm32-wasi --sysroot=$WASI_SYSROOT"; mkdir -p /out; \
    $CXX $CX_CFLAGS -std=c++20 -fno-exceptions -Wall -I wabt/include -I wabt/build/include \
      cx-wat2wasm/cx-wat2wasm.cc wabt/build/libwabt.a \
      $CX_LDFLAGS -Wl,-z,stack-size=4194304 -o /out/cx-wat2wasm.raw.wasm \
 && cx-wasm-strip < /out/cx-wat2wasm.raw.wasm > /out/cx-wat2wasm.wasm \
 && ls -l /out/cx-wat2wasm.wasm && sha256sum /out/cx-wat2wasm.wasm

FROM scratch AS export
COPY --from=build /out/cx-wat2wasm.wasm /cx-wat2wasm.wasm
