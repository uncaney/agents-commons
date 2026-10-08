# syntax=docker/dockerfile:1
# cxlua: Lua 5.4 + the common launcher, compiled to wasm32-wasi (SPEC-v2 15.4).
# Build context = catalog/ ; driven by catalog/build.sh (never on the Mac):
#   docker build -f cxlua/Dockerfile --output type=local,dest=out/cxlua .
# Pins: wasi-sdk 24 (sha256 below), Lua 5.4.9 (sha256 below). Expected size ~0.4 MiB.
# STATUS: the launcher was exercised natively (clang + Lua 5.4.9 on macOS); the wasm build
# runs on the server through build.sh and the KAT suite through verify.sh.

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

# --- Lua 5.4 library for wasm32-wasi
FROM sdk AS build
ARG LUA_VERSION=5.4.9
ARG LUA_SHA256=2335b6c582a52654f94612bf10d2f4672805d05329aa6568b1d8cd9e5c6fb8e6
WORKDIR /src
RUN curl -fsSL -o lua.tar.gz "https://www.lua.org/ftp/lua-${LUA_VERSION}.tar.gz" \
 && echo "${LUA_SHA256}  lua.tar.gz" | sha256sum -c - \
 && tar -xzf lua.tar.gz && mv "lua-${LUA_VERSION}" lua && rm lua.tar.gz
RUN set -eu; CC="$WASI_SDK_PATH/bin/clang --target=wasm32-wasi --sysroot=$WASI_SYSROOT"; \
    cd lua/src; \
    for f in $(ls *.c | grep -v -e '^lua\.c$' -e '^luac\.c$'); do \
      $CC $CX_CFLAGS -std=gnu99 -Wall -DLUA_COMPAT_5_3 -c "$f"; \
    done; \
    "$WASI_SDK_PATH/bin/llvm-ar" rcs liblua.a *.o

# --- launcher + link
COPY launcher/ /src/launcher/
COPY cxlua/cxlua.c cxlua/wasi_stubs.c /src/cxlua/
RUN set -eu; CC="$WASI_SDK_PATH/bin/clang --target=wasm32-wasi --sysroot=$WASI_SYSROOT"; mkdir -p /out; \
    $CC $CX_CFLAGS -std=gnu99 -Wall -I lua/src -I launcher \
      cxlua/cxlua.c cxlua/wasi_stubs.c launcher/launcher.c lua/src/liblua.a -lm \
      $CX_LDFLAGS -Wl,-z,stack-size=2097152 -o /out/cxlua.raw.wasm \
 && cx-wasm-strip < /out/cxlua.raw.wasm > /out/cxlua.wasm \
 && ls -l /out/cxlua.wasm && sha256sum /out/cxlua.wasm

FROM scratch AS export
COPY --from=build /out/cxlua.wasm /cxlua.wasm
