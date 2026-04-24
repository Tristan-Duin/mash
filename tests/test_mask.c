/* tests/test_mask.c - black-box tests of the mask engine.
 *
 * Verifies that the major categories are redacted, that user-added
 * literals are honored, and that cross-chunk boundaries in the streaming
 * API still catch matches. Run with `make check`.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mask.h"
#include "util.h"

static int failures = 0;

static void assert_masked(mask_engine_t *e, const char *needle,
                          const char *in, const char *label) {
    char *out = NULL; size_t n = 0;
    mask_apply(e, in, strlen(in), &out, &n);
    if (!out) { fprintf(stderr, "FAIL (%s): mask_apply returned NULL\n", label); failures++; return; }
    if (strstr(out, needle)) {
        fprintf(stderr, "FAIL (%s): raw value not masked in:\n  in : %s\n  out: %s\n",
                label, in, out);
        failures++;
    } else {
        printf("ok  %s\n", label);
    }
    free(out);
}

static void assert_kept(mask_engine_t *e, const char *expect_substr,
                        const char *in, const char *label) {
    char *out = NULL; size_t n = 0;
    mask_apply(e, in, strlen(in), &out, &n);
    if (!strstr(out, expect_substr)) {
        fprintf(stderr, "FAIL (%s): expected %s in output; got:\n  %s\n",
                label, expect_substr, out);
        failures++;
    } else {
        printf("ok  %s\n", label);
    }
    free(out);
}

/* Stream a payload through mask_stream_push in awkward chunk sizes and
 * verify the needle doesn't leak across boundaries. */
static void assert_stream_masked(mask_engine_t *e, const char *needle,
                                 const char *in, size_t chunk,
                                 const char *label) {
    mask_stream_t ms;
    mask_stream_init(&ms, e);
    strbuf_t out; strbuf_init(&out);
    size_t n = strlen(in);
    for (size_t i = 0; i < n; i += chunk) {
        size_t k = (i + chunk <= n) ? chunk : (n - i);
        mask_stream_push(&ms, in + i, k, &out);
    }
    mask_stream_finish(&ms, &out);
    if (strstr(out.data ? out.data : "", needle)) {
        fprintf(stderr, "FAIL stream (%s): raw value not masked; out=%.*s\n",
                label, (int)out.len, out.data ? out.data : "");
        failures++;
    } else {
        printf("ok  stream %s (chunk=%zu)\n", label, chunk);
    }
    strbuf_free(&out);
    mask_stream_free(&ms);
}

int main(void) {
    mask_engine_t *e = mask_engine_new();
    /* Seed hard-coded patterns plus a custom literal. */
    mash_mask_init_defaults(e);
    mask_add_literal(e, MASK_CAT_CUSTOM, "supersecret-token-42");

    assert_masked(e, "user@example.com",
                  "contact me at user@example.com please",
                  "email");
    assert_masked(e, "10.0.0.42",
                  "my ip is 10.0.0.42 today",
                  "ipv4");
    assert_masked(e, "de:ad:be:ef:12:34",
                  "mac=de:ad:be:ef:12:34",
                  "mac");
    assert_masked(e, "AKIAIOSFODNN7EXAMPLE",
                  "cred AKIAIOSFODNN7EXAMPLE here",
                  "aws");
    assert_masked(e, "4242424242424242",
                  "cc 4242424242424242 !",
                  "creditcard");
    assert_masked(e, "123-45-6789",
                  "ssn 123-45-6789 tax",
                  "ssn");
    assert_masked(e, "550e8400-e29b-41d4-a716-446655440000",
                  "id=550e8400-e29b-41d4-a716-446655440000",
                  "uuid");
    assert_masked(e, "supersecret-token-42",
                  "my token: supersecret-token-42",
                  "literal");

    /* A plain word should pass through. */
    assert_kept(e, "hello", "hello world", "passthrough");

    /* Streaming: the masked literal is split across chunk boundaries. */
    assert_stream_masked(e, "supersecret-token-42",
                         "prefix supersecret-token-42 suffix\n",
                         1,
                         "literal across byte chunks");
    assert_stream_masked(e, "user@example.com",
                         "see user@example.com please\n",
                         3,
                         "email across 3-byte chunks");

    mask_engine_free(e);

    if (failures) {
        fprintf(stderr, "%d FAILURES\n", failures);
        return 1;
    }
    printf("all tests passed\n");
    return 0;
}
