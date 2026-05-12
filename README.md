# fuzz-zsv

libFuzzer harness for [zsv](https://github.com/liquidaty/zsv) — a fast CSV parser in C.

## Requirements

- Docker
- Docker Compose

## Usage

```bash
# Build the fuzzer image (pulls zsv from the configured branch)
docker compose build --no-cache

# Run with N parallel containers
docker compose up --scale fuzzer=4

# Crashes appear in logs_local/crashes/ on the host
```

## Configuration

Edit `.env` to change the target branch or fuzzing parameters:

```
TARGET_REPO=https://github.com/liquidaty/zsv.git
TARGET_VERSION=underflow-fix-v2
FUZZER_MAX_LEN=65536
FUZZER_MAX_TIME=0      # 0 = run indefinitely
FUZZER_JOBS=1
```

## Replay a crash

```bash
docker run --rm \
  --entrypoint /home/fuzzer/fuzzer_bin \
  -v "$(pwd)/logs_local/crashes:/crashes:ro" \
  fuzzer-zsv:pr612 \
  /crashes/<crash-file>
```
