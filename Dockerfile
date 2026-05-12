# =============================================================================
# Dockerfile — Fuzzing Environment: zsv CSV Parser
# Target: https://github.com/liquidaty/zsv
# Branch: main
#
# Build strategy:
#   zsv uses a custom build system (./configure + make).  Rather than
#   fighting it, we compile zsv_lib directly from source with clang by
#   replicating what src/Makefile does for a single-TU build:
#
#     clang -c -fsanitize=... src/zsv.c   (which #includes zsv_internal.c)
#
#   We also need to generate include/zsv.h from include/zsv.h.in,
#   which is a trivial sed substitution.
# =============================================================================

FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        clang        \
        llvm         \
        git          \
        sed          \
        ca-certificates \
        && rm -rf /var/lib/apt/lists/*

ARG TARGET_REPO=https://github.com/liquidaty/zsv.git
ARG TARGET_VERSION=main
ARG TARGET_NAME=zsv
ARG FUZZER_MAX_LEN=65536

WORKDIR /fuzzer

RUN git clone --branch ${TARGET_VERSION} --depth 1 \
        ${TARGET_REPO} /fuzzer/${TARGET_NAME}

RUN sed 's/__ZSV_EXTRAS__DEFINE__//' \
        < /fuzzer/${TARGET_NAME}/include/zsv.h.in \
        > /fuzzer/${TARGET_NAME}/include/zsv.h && \
        echo "[builder] Generated include/zsv.h"

# ---------------------------------------------------------------------------
# Compile zsv as a single object.
# Important flags:
#   -DNO_UTF8_CHECK      skip the utf8 checker (no per-cell hash needed)
#   -DZSV_VERSION=\"fuzz\" satisfies the version string requirement
#   -msse2               enable the SSE2 fast-parser path (x86_64 only)
#   -fsigned-char        zsv uses __attribute__((vector_size)) on signed chars
# ---------------------------------------------------------------------------
RUN clang -c \
        -g -O1 \
        -fsanitize=address,undefined \
        -fno-sanitize-recover=undefined \
        -fsigned-char \
        -msse2 \
        -DZSV_VERSION=\"fuzz\" \
        -DNDEBUG \
        -DNO_UTF8_CHECK \
        -DHAVE_MEMMEM \
        -DHAVE___BUILTIN_EXPECT \
        -I /fuzzer/${TARGET_NAME}/include \
        -I /fuzzer/${TARGET_NAME}/src \
        -I /fuzzer/${TARGET_NAME}/app/external/sqlite3 \
        /fuzzer/${TARGET_NAME}/src/zsv.c \
        -o /fuzzer/zsv.o && \
        echo "[builder] zsv.o compiled OK"

COPY harness.cpp ./harness.cpp
COPY corpus/     ./corpus/

# ---------------------------------------------------------------------------
# Link harness + zsv.o into a single fuzz binary
# ---------------------------------------------------------------------------
RUN clang++ \
        -fsanitize=fuzzer,address,undefined \
        -fno-sanitize-recover=undefined \
        -g -O1 -std=c++11 \
        -fsigned-char \
        -msse2 \
        "-Drestrict=__restrict" \
        -I /fuzzer/zsv/include \
        /fuzzer/harness.cpp \
        /fuzzer/zsv.o \
        -o /fuzzer/fuzzer_bin && \
        echo "[builder] fuzzer_bin linked OK"

# =============================================================================
# STAGE 2: RUNNER
# =============================================================================
FROM ubuntu:22.04 AS runner

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        libasan6  \
        libubsan1 \
        libllvm14 \
        && rm -rf /var/lib/apt/lists/*

RUN useradd -m fuzzer

WORKDIR /home/fuzzer

COPY --from=builder --chown=fuzzer:fuzzer /fuzzer/fuzzer_bin ./fuzzer_bin
COPY --from=builder --chown=fuzzer:fuzzer /fuzzer/corpus/    ./corpus/
COPY --chown=fuzzer:fuzzer csv.dict ./fuzzer.dict

COPY --from=builder /usr/bin/llvm-symbolizer-14 /usr/local/bin/llvm-symbolizer
ENV ASAN_SYMBOLIZER_PATH=/usr/local/bin/llvm-symbolizer
ENV UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1

ARG FUZZER_MAX_LEN=65536
ENV FUZZER_MAX_LEN=${FUZZER_MAX_LEN}

COPY entrypoint.sh ./entrypoint.sh
RUN chmod +x ./entrypoint.sh && \
        mkdir -p /home/fuzzer/corpus_shared && \
        mkdir -p /home/fuzzer/logs/crashes && \
        chown -R fuzzer:fuzzer /home/fuzzer/corpus_shared /home/fuzzer/logs ./entrypoint.sh

USER fuzzer

CMD ["./entrypoint.sh"]
