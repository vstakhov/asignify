#ifndef CHACHA_H
#define CHACHA_H

#include <stddef.h>

#ifndef CHACHA_ALIGN
# if defined(_MSC_VER)
#  define CHACHA_ALIGN(x) __declspec(align(x))
# else
#  define CHACHA_ALIGN(x) __attribute__((aligned(x)))
# endif
#endif

#if defined(__cplusplus)
extern "C" {
#endif

CHACHA_ALIGN( 64 ) typedef struct chacha_state_t {
	unsigned char opaque[128];
} chacha_state;

typedef struct chacha_key_t {
	unsigned char b[32];
} chacha_key;

typedef struct chacha_iv_t {
	unsigned char b[8];
} chacha_iv;

typedef struct chacha_iv24_t {
	unsigned char b[24];
} chacha_iv24;

void chacha_init(chacha_state *S, const chacha_key *key, const chacha_iv *iv, size_t rounds);
size_t chacha_update(chacha_state *S, const unsigned char *in, unsigned char *out, size_t inlen);
size_t chacha_final(chacha_state *S, unsigned char *out);

#if defined(__cplusplus)
}
#endif

#endif /* CHACHA_H */

