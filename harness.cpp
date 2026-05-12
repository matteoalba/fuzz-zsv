/*
 * harness.cpp — libFuzzer harness for zsv (https://github.com/liquidaty/zsv)
 *
 * Attack surface exercised:
 *   1. Default engine  (ZSV_MODE_DELIM)      — standard delimiter-scan path
 *   2. Fast SIMD engine (scan_engine=3)       — branchless AVX2/SSE2 vectorized path
 *   3. Compat engine   (scan_engine=255)      — standard non-SIMD path
 *   4. Fixed-width mode (zsv_set_fixed_offsets)
 *   5. Custom delimiter byte
 *   6. zsv_next_row() pull API  — exercises the pull-mode state machine
 *   7. No-quotes mode
 *
 * API notes (public header, current main branch):
 *   - zsv_parse_bytes() public API takes only (parser, buff, len) — it is a
 *     PUSH function: feed data held in buff directly to the scanner without I/O.
 *     (The 2-arg internal version only exists in zsv.c, not in the public header.)
 *   - ZSV_MODE_DELIM_FAST and friends are internal constants; we use the
 *     scan_engine numeric values: 0=default, 3=fast, 255=compat.
 *   - 'restrict' in the public API is C99; compiling as C++ requires
 *     -D"restrict=__restrict" or simply suppressing the keyword.
 *
 * Compile flags required by the zsv headers:
 *   -fsigned-char   (zsv uses vector ops on signed char)
 *   -D"restrict=__restrict"  (C++ compatibility)
 *   -msse2          (enables fast SIMD scanner path)
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/*
 * zsv.h — generated from include/zsv.h.in in the Dockerfile build step.
 * With -I /fuzzer/zsv/include this resolves to include/zsv.h which pulls in
 * include/zsv/common.h and include/zsv/api.h.
 */
extern "C"
{
#include "zsv.h"
}

/* ---------------------------------------------------------------------------
 * Volatile sink — prevents the compiler from eliding cell reads.
 * --------------------------------------------------------------------------- */
static volatile size_t g_sink;

/* ---------------------------------------------------------------------------
 * Shared row callback — dumps all cells into the volatile sink.
 * --------------------------------------------------------------------------- */
static void row_handler(void *ctx)
{
    zsv_parser parser = (zsv_parser)ctx;
    size_t n = zsv_cell_count(parser);
    for (size_t i = 0; i < n; i++)
    {
        struct zsv_cell c = zsv_get_cell(parser, i);
        /* Touch every byte so ASan sees any OOB reads */
        for (size_t j = 0; j < c.len; j++)
            g_sink += c.str[j];
        g_sink += c.len;
        g_sink += (size_t)(unsigned char)c.quoted;
    }
    g_sink += zsv_row_is_blank(parser) ? 1 : 0;
}

/* ---------------------------------------------------------------------------
 * Dummy error printer to suppress warnings.
 * --------------------------------------------------------------------------- */
static int dummy_errprintf(void *ctx, const char *format, ...)
{
    return 0;
}

/* ---------------------------------------------------------------------------
 * Memory-backed "stream" — lets the pull parser read from a buffer.
 * --------------------------------------------------------------------------- */
struct membuf
{
    const uint8_t *data;
    size_t size;
    size_t pos;
};

/*
 * fread-compatible wrapper: zsv passes (buf, n, size, stream).
 * We return number of *elements* of size `size` that were read.
 */
static size_t membuf_read(void *dst, size_t n, size_t elem_size, void *stream)
{
    struct membuf *mb = (struct membuf *)stream;
    size_t want = n * elem_size;
    size_t avail = mb->size - mb->pos;
    size_t give = want < avail ? want : avail;
    if (give)
    {
        memcpy(dst, mb->data + mb->pos, give);
        mb->pos += give;
    }
    return (elem_size > 0) ? (give / elem_size) : 0;
}

/* ---------------------------------------------------------------------------
 * push-mode path: feed data via zsv_parse_bytes().
 *
 * scan_engine values exposed by the public API:
 *   0   → default (branchless or scalar depending on compile-time detection)
 *   3   → explicit fast/SIMD engine (ZSV_MODE_DELIM_FAST = 3)
 *   255 → compat/standard engine   (forces ZSV_MODE_DELIM regardless of HW)
 * --------------------------------------------------------------------------- */
static void fuzz_push(const uint8_t *data, size_t size,
                      unsigned char scan_engine,
                      char no_quotes,
                      char delimiter)
{
    struct zsv_opts opts;
    memset(&opts, 0, sizeof(opts));
    opts.max_columns = 256;
    opts.max_row_size = 4096;
    opts.scan_engine = scan_engine;
    opts.no_quotes = no_quotes;
    opts.keep_empty_header_rows = 1;
    opts.errprintf = dummy_errprintf;
    if (delimiter != 0 && delimiter != '\n' && delimiter != '\r' && delimiter != '"')
        opts.delimiter = delimiter;

    zsv_parser parser = zsv_new(&opts);
    if (!parser)
        return;

    zsv_set_row_handler(parser, row_handler);
    zsv_set_context(parser, parser);

    /* zsv_parse_bytes() public API: (parser, buff, len) — push, no I/O */
    zsv_parse_bytes(parser, data, size);
    zsv_finish(parser);
    zsv_delete(parser);
}

/* ---------------------------------------------------------------------------
 * fixed-width mode path.
 * --------------------------------------------------------------------------- */
static void fuzz_fixed(const uint8_t *data, size_t size)
{
    if (size < 8)
        return;

    /* Build a fixed-offset array from the first 4 bytes (1..64 bytes per col) */
    size_t offsets[4];
    size_t prev = 0;
    for (int i = 0; i < 4; i++)
    {
        size_t step = (data[i] & 0x3f) + 1;
        offsets[i] = prev + step;
        prev = offsets[i];
    }

    struct zsv_opts opts;
    memset(&opts, 0, sizeof(opts));
    opts.max_columns = 256;
    opts.max_row_size = 4096;
    opts.keep_empty_header_rows = 1;
    opts.errprintf = dummy_errprintf;

    zsv_parser parser = zsv_new(&opts);
    if (!parser)
        return;

    zsv_set_row_handler(parser, row_handler);
    zsv_set_context(parser, parser);

    if (zsv_set_fixed_offsets(parser, 4, offsets) == zsv_status_ok)
    {
        zsv_parse_bytes(parser, data + 4, size - 4);
        zsv_finish(parser);
    }
    zsv_delete(parser);
}

/* --------------------------------------------------------------------------- * chunked push-mode path: feeds data in fixed-size pieces to stress the
 * internal buffer-refill logic (the historical underflow bug class lives
 * in that code path; 17-byte chunks match the PR's own libfuzzer.c).
 * --------------------------------------------------------------------------- */
static void fuzz_push_chunked(const uint8_t *data, size_t size,
                               unsigned char scan_engine,
                               size_t chunk_size)
{
    struct zsv_opts opts;
    memset(&opts, 0, sizeof(opts));
    opts.max_columns = 256;
    opts.max_row_size = 4096;
    opts.scan_engine = scan_engine;
    opts.keep_empty_header_rows = 1;
    opts.errprintf = dummy_errprintf;

    zsv_parser parser = zsv_new(&opts);
    if (!parser)
        return;

    zsv_set_row_handler(parser, row_handler);
    zsv_set_context(parser, parser);

    size_t off = 0;
    while (off < size)
    {
        size_t chunk = size - off;
        if (chunk > chunk_size)
            chunk = chunk_size;
        zsv_parse_bytes(parser, data + off, chunk);
        off += chunk;
    }
    zsv_finish(parser);
    zsv_delete(parser);
}

/* --------------------------------------------------------------------------- * pull-parsing path (zsv_next_row API).
 * --------------------------------------------------------------------------- */
static void fuzz_pull(const uint8_t *data, size_t size, char no_quotes)
{
    struct membuf mb = {data, size, 0};

    struct zsv_opts opts;
    memset(&opts, 0, sizeof(opts));
    opts.max_columns = 256;
    opts.max_row_size = 4096;
    opts.no_quotes = no_quotes;
    opts.keep_empty_header_rows = 1;
    opts.errprintf = dummy_errprintf;
    opts.read = membuf_read;
    opts.stream = &mb;

    zsv_parser parser = zsv_new(&opts);
    if (!parser)
        return;

    enum zsv_status st;
    while ((st = zsv_next_row(parser)) == zsv_status_row)
    {
        size_t n = zsv_cell_count(parser);
        for (size_t i = 0; i < n; i++)
        {
            struct zsv_cell c = zsv_get_cell(parser, i);
            for (size_t j = 0; j < c.len; j++)
                g_sink += c.str[j];
            g_sink += c.len;
        }
    }

    zsv_delete(parser);
}

/* ---------------------------------------------------------------------------
 * Main entry point
 *
 * Control word (first byte):
 *   bits [2:0]  mode
 *     0 = push, default engine
 *     1 = push, fast SIMD engine (scan_engine=3)
 *     2 = push, compat engine (scan_engine=255)
 *     3 = push, alt delimiter (picked from data[1])
 *     4 = push, no-quotes
 *     5 = fixed-width mode
 *     6 = pull parsing
 *     7 = pull parsing, no-quotes
 *   bit 3 (0x08)  chunked flag
 *     0 = feed payload as one call to zsv_parse_bytes() (original behaviour)
 *     1 = feed payload in 17-byte chunks (exercises the buffer-refill path;
 *         matches the PR's own libfuzzer.c — also triggered by the historical
 *         PoC files whose control bytes have bit 3 set, e.g. 0x69 / 0x29)
 *   bits [7:4]   ignored (available for future expansion)
 * --------------------------------------------------------------------------- */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2)
        return 0;

    uint8_t ctrl = data[0];
    uint8_t mode = ctrl & 0x7;
    bool chunked = (ctrl & 0x8) != 0;  /* bit 3: feed in 17-byte chunks */

    const uint8_t *payload = data + 1;
    size_t payload_size = size - 1;

    switch (mode)
    {
    case 0:
        if (chunked)
            fuzz_push_chunked(payload, payload_size, 0, 17);
        else
            fuzz_push(payload, payload_size, 0, 0, 0);
        break;
    case 1:
        /* scan_engine=3 → fast SIMD path (ZSV_MODE_DELIM_FAST) */
        if (chunked)
            fuzz_push_chunked(payload, payload_size, 3, 17);
        else
            fuzz_push(payload, payload_size, 3, 0, 0);
        break;
    case 2:
        /* scan_engine=255 → compat/standard path */
        if (chunked)
            fuzz_push_chunked(payload, payload_size, 255, 17);
        else
            fuzz_push(payload, payload_size, 255, 0, 0);
        break;
    case 3:
        /* Alternate delimiter: grab from next payload byte, fall back to ';' */
        {
            char delim = payload_size > 0 ? (char)payload[0] : ';';
            fuzz_push(payload, payload_size, 0, 0, delim);
        }
        break;
    case 4:
        if (chunked)
            fuzz_push_chunked(payload, payload_size, 0, 17);
        else
            fuzz_push(payload, payload_size, 0, 1, 0);
        break;
    case 5:
        fuzz_fixed(payload, payload_size);
        break;
    case 6:
        fuzz_pull(payload, payload_size, 0);
        break;
    case 7:
        fuzz_pull(payload, payload_size, 1);
        break;
    }

    return 0;
}
