# syntax=docker/dockerfile:1
# cxjs: quickjs-ng + the common launcher, compiled to wasm32-wasi (SPEC-v2 15.4).
# Build context = catalog/ ; driven by catalog/build.sh (never on the Mac):
#   docker build -f cxjs/Dockerfile --output type=local,dest=out/cxjs .
# Pins: wasi-sdk 24, quickjs-ng v0.17.0 (sha256 below; its CMake has first-class WASI
# support: _WASI_EMULATED_* defines and a 2 MiB stack). Expected size ~1.3 MiB (< 4 MiB).
# STATUS: the launcher was exercised natively (clang + quickjs-ng 0.17.0 on macOS); the wasm
# build runs on the server through build.sh and the KAT suite through verify.sh.

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

# --- quickjs-ng library (engine only, no quickjs-libc: the launcher provides print/stdin)
FROM sdk AS build
ARG QJS_VERSION=0.17.0
ARG QJS_SHA256=559bc4c420475e55c7ab4510adbc562f55d7524d75e8e89d79ce4bb02f5687d9
WORKDIR /src
RUN curl -fsSL -o qjs.tar.gz "https://github.com/quickjs-ng/quickjs/archive/refs/tags/v${QJS_VERSION}.tar.gz" \
 && echo "${QJS_SHA256}  qjs.tar.gz" | sha256sum -c - \
 && tar -xzf qjs.tar.gz && mv "quickjs-${QJS_VERSION}" quickjs && rm qjs.tar.gz
RUN cmake -S quickjs -B quickjs/build \
      -DCMAKE_TOOLCHAIN_FILE="$WASI_SDK_PATH/share/cmake/wasi-sdk.cmake" \
      -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF \
      -DQJS_BUILD_EXAMPLES=OFF -DQJS_ENABLE_INSTALL=OFF -DQJS_BUILD_LIBC=OFF \
      -DCMAKE_C_FLAGS="$CX_CFLAGS" \
 && cmake --build quickjs/build --target qjs -j"$(nproc)"

# --- launcher + link (2 MiB linear stack like quickjs-ng's own WASI target; JS stack 1 MiB)
COPY launcher/ /src/launcher/
COPY cxjs/cxjs.c /src/cxjs/
RUN set -eu; CC="$WASI_SDK_PATH/bin/clang --target=wasm32-wasi --sysroot=$WASI_SYSROOT"; mkdir -p /out; \
    $CC $CX_CFLAGS -std=c99 -Wall -I quickjs -I launcher \
      cxjs/cxjs.c launcher/launcher.c quickjs/build/libqjs.a -lm \
      $CX_LDFLAGS -Wl,-z,stack-size=2097152 -o /out/cxjs.raw.wasm \
 && cx-wasm-strip < /out/cxjs.raw.wasm > /out/cxjs.wasm \
 && ls -l /out/cxjs.wasm && sha256sum /out/cxjs.wasm

FROM scratch AS export
COPY --from=build /out/cxjs.wasm /cxjs.wasm
