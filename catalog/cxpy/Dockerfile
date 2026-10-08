# syntax=docker/dockerfile:1
# cxpy: CPython 3.13 for wasm32-wasi with the stdlib packed in by wasi-vfs, behind the
# common launcher (SPEC-v2 15.4: PyConfig use_hash_seed=1 hash_seed=0 isolated=1
# site_import=0 buffered_stdio=0). Build context = catalog/ ; driven by catalog/build.sh:
#   docker build -f cxpy/Dockerfile --output type=local,dest=out/cxpy .
# Pins: wasi-sdk 24, CPython 3.13.16, wasi-vfs 0.6.3 (sha256 below). Expected size 25-40 MiB:
# over 16 MiB, so it enters the store through `cxa blob` (PUT /admin/blob) and needs a pin.
# STATUS: the launcher (cxpy.c + bootstrap.py) was exercised natively against CPython 3.14 on
# macOS; the CPython wasm cross-build and the wasi-vfs pack run on the server (30-60 min,
# single-threaded parts). RustPython is the documented fallback if this stage cannot be made
# to pass the KAT suite (README.md).

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

# --- CPython cross-build (host build-python first, then wasm32-wasip1 static libpython)
FROM sdk AS build
ARG PY_VERSION=3.13.16
ARG PY_SHA256=f4b1bfb3c79b5bb11b8d228a12504163b4c0dab4d679828d8f5f26b6cb6ab35d
ARG WASI_VFS_VERSION=0.6.3
ARG WASI_VFS_CLI_SHA256=c9ee8179f6f0882abc37024fbe0cd678311aa8a29083fa364915ed4d29a69485
ARG WASI_VFS_LIB_SHA256=f94dc7fdabdefc0fed78b70f1ab100207db0558cbabb004dd9e5a0bdeec4256f
WORKDIR /src
RUN curl -fsSL -o py.tar.xz "https://www.python.org/ftp/python/${PY_VERSION}/Python-${PY_VERSION}.tar.xz" \
 && echo "${PY_SHA256}  py.tar.xz" | sha256sum -c - \
 && tar -xJf py.tar.xz && mv "Python-${PY_VERSION}" cpython && rm py.tar.xz
RUN curl -fsSL -o vfs-cli.zip "https://github.com/kateinoigakukun/wasi-vfs/releases/download/v${WASI_VFS_VERSION}/wasi-vfs-cli-x86_64-unknown-linux-gnu.zip" \
 && echo "${WASI_VFS_CLI_SHA256}  vfs-cli.zip" | sha256sum -c - \
 && curl -fsSL -o vfs-lib.zip "https://github.com/kateinoigakukun/wasi-vfs/releases/download/v${WASI_VFS_VERSION}/libwasi_vfs-wasm32-unknown-unknown.zip" \
 && echo "${WASI_VFS_LIB_SHA256}  vfs-lib.zip" | sha256sum -c - \
 && mkdir -p /opt/wasi-vfs/bin /opt/wasi-vfs/lib \
 && unzip -q -o vfs-cli.zip -d /opt/wasi-vfs/bin && chmod +x /opt/wasi-vfs/bin/wasi-vfs \
 && unzip -q -o vfs-lib.zip -d /opt/wasi-vfs/lib && rm vfs-cli.zip vfs-lib.zip \
 && find /opt/wasi-vfs -type f | sort
# Tools/wasm/wasi.py drives configure/make for both halves; the host runner is only recorded
# (never executed), /bin/true avoids its wasmtime lookup. Static modules only: no dlopen.
RUN cd cpython && python3 Tools/wasm/wasi.py build --wasi-sdk "$WASI_SDK_PATH" --host-runner /bin/true \
 && ls -l cross-build/wasm32-wasip1/libpython3.13.a cross-build/wasm32-wasip1/python.wasm

# --- stdlib tree to pack (sources only; tests, GUI and packaging tools dropped)
RUN set -eu; L=/pack/usr/local/lib/python3.13; mkdir -p "$L"; cp -r cpython/Lib/. "$L"/; \
    cp cpython/cross-build/wasm32-wasip1/build/lib.wasi-wasm32-3.13/_sysconfigdata*.py "$L"/ 2>/dev/null || true; \
    rm -rf "$L"/test "$L"/idlelib "$L"/tkinter "$L"/turtledemo "$L"/turtle.py "$L"/ensurepip \
           "$L"/lib2to3 "$L"/pydoc_data "$L"/site-packages "$L"/venv "$L"/__phello__ "$L"/__hello__.py; \
    find "$L" -name '__pycache__' -type d -prune -exec rm -rf {} +; \
    find "$L" -name 'test' -type d -prune -exec rm -rf {} +; \
    find "$L" -name 'tests' -type d -prune -exec rm -rf {} +; \
    du -sh "$L"

# --- launcher + link + pack + strip
COPY launcher/ /src/launcher/
COPY cxpy/cxpy.c cxpy/bootstrap.py /src/cxpy/
COPY tools/embed.sh /src/tools/embed.sh
RUN set -eu; sh tools/embed.sh cxpy/bootstrap.py cxpy/bootstrap.inc; \
    B=cpython/cross-build/wasm32-wasip1; \
    CC="$WASI_SDK_PATH/bin/clang --target=wasm32-wasip1 --sysroot=$WASI_SYSROOT"; \
    LIBS=$(sed -n 's/^LIBS=[[:space:]]*//p' "$B/Makefile"); \
    MODLIBS=$(sed -n 's/^MODLIBS=[[:space:]]*//p' "$B/Makefile"); \
    LDFLAGS=$(sed -n 's/^LDFLAGS=[[:space:]]*//p' "$B/Makefile" | sed 's/-Wl,--stack-first//'); \
    mkdir -p /out; \
    $CC $CX_CFLAGS -std=c99 -Wall -I cpython/Include -I "$B" -I launcher -I cxpy \
      cxpy/cxpy.c launcher/launcher.c -o /out/cxpy.raw.wasm \
      "$B/libpython3.13.a" $MODLIBS $LIBS $LDFLAGS -L/opt/wasi-vfs/lib -lwasi_vfs \
      -lwasi-emulated-signal -lwasi-emulated-process-clocks -lwasi-emulated-getpid \
      -Wl,-z,stack-size=8388608 \
 && /opt/wasi-vfs/bin/wasi-vfs pack /out/cxpy.raw.wasm \
      --mapdir /usr/local/lib/python3.13::/pack/usr/local/lib/python3.13 -o /out/cxpy.packed.wasm \
 && cx-wasm-strip < /out/cxpy.packed.wasm > /out/cxpy.wasm \
 && ls -l /out/cxpy.wasm && sha256sum /out/cxpy.wasm

FROM scratch AS export
COPY --from=build /out/cxpy.wasm /cxpy.wasm
