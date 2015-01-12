
/*
 * Public domain by Andrew Moon: https://github.com/floodyberry/chacha-opt
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "chacha.h"
#include "asignify_internal.h"

enum chacha_constants {
	CHACHA_BLOCKBYTES = 64,
};

CHACHA_ALIGN( 64 ) typedef struct chacha_state_internal_t {
	unsigned char s[48];
	size_t rounds;
	size_t leftover;
	unsigned char buffer[CHACHA_BLOCKBYTES];
} chacha_state_internal;

typedef uint32_t chacha_int32;

/* interpret four 8 bit unsigned integers as a 32 bit unsigned integer in little endian */
static chacha_int32
U8TO32(const unsigned char *p) {
	return
	(((chacha_int32)(p[0])      ) |
	 ((chacha_int32)(p[1]) <<  8) |
	 ((chacha_int32)(p[2]) << 16) |
	 ((chacha_int32)(p[3]) << 24));
}

/* store a 32 bit unsigned integer as four 8 bit unsigned integers in little endian */
static void
U32TO8(unsigned char *p, chacha_int32 v) {
	p[0] = (v      ) & 0xff;
	p[1] = (v >>  8) & 0xff;
	p[2] = (v >> 16) & 0xff;
	p[3] = (v >> 24) & 0xff;
}

/* 32 bit left rotate */
static chacha_int32
ROTL32(chacha_int32 x, int k) {
	return ((x << k) | (x >> (32 - k))) & 0xffffffff;
}

/* "expand 32-byte k", as 4 little endian 32-bit unsigned integers */
static const chacha_int32 chacha_constants[4] = {
	0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
};

static void
chacha_blocks(chacha_state_internal *state, const unsigned char *in,
	unsigned char *out, size_t bytes)
{
	CHACHA_ALIGN( 64 ) chacha_int32 x[16], j[12];
	chacha_int32 t;
	unsigned char *ctarget = out, tmp[64];
	size_t i, r;

	if (!bytes) return;

	j[0] = U8TO32(state->s + 0);
	j[1] = U8TO32(state->s + 4);
	j[2] = U8TO32(state->s + 8);
	j[3] = U8TO32(state->s + 12);
	j[4] = U8TO32(state->s + 16);
	j[5] = U8TO32(state->s + 20);
	j[6] = U8TO32(state->s + 24);
	j[7] = U8TO32(state->s + 28);
	j[8] = U8TO32(state->s + 32);
	j[9] = U8TO32(state->s + 36);
	j[10] = U8TO32(state->s + 40);
	j[11] = U8TO32(state->s + 44);

	r = state->rounds;

	for (;;) {
		if (bytes < 64) {
			if (in) {
				for (i = 0; i < bytes; i++) tmp[i] = in[i];
				in = tmp;
			}
			ctarget = out;
			out = tmp;
		}

		x[0] = chacha_constants[0];
		x[1] = chacha_constants[1];
		x[2] = chacha_constants[2];
		x[3] = chacha_constants[3];
		x[4] = j[0];
		x[5] = j[1];
		x[6] = j[2];
		x[7] = j[3];
		x[8] = j[4];
		x[9] = j[5];
		x[10] = j[6];
		x[11] = j[7];
		x[12] = j[8];
		x[13] = j[9];
		x[14] = j[10];
		x[15] = j[11];

		#define quarter(a,b,c,d) \
			a += b; t = d^a; d = ROTL32(t,16); \
			c += d; t = b^c; b = ROTL32(t,12); \
			a += b; t = d^a; d = ROTL32(t, 8); \
			c += d; t = b^c; b = ROTL32(t, 7);

		#define doubleround() \
			quarter( x[0], x[4], x[8],x[12]) \
			quarter( x[1], x[5], x[9],x[13]) \
			quarter( x[2], x[6],x[10],x[14]) \
			quarter( x[3], x[7],x[11],x[15]) \
			quarter( x[0], x[5],x[10],x[15]) \
			quarter( x[1], x[6],x[11],x[12]) \
			quarter( x[2], x[7], x[8],x[13]) \
			quarter( x[3], x[4], x[9],x[14])

		i = r;
		do {
			doubleround()
			i -= 2;
		} while (i);

		x[0] += chacha_constants[0];
		x[1] += chacha_constants[1];
		x[2] += chacha_constants[2];
		x[3] += chacha_constants[3];
		x[4] += j[0];
		x[5] += j[1];
		x[6] += j[2];
		x[7] += j[3];
		x[8] += j[4];
		x[9] += j[5];
		x[10] += j[6];
		x[11] += j[7];
		x[12] += j[8];
		x[13] += j[9];
		x[14] += j[10];
		x[15] += j[11];

		if (in) {
			U32TO8(out +  0,  x[0] ^ U8TO32(in +  0));
			U32TO8(out +  4,  x[1] ^ U8TO32(in +  4));
			U32TO8(out +  8,  x[2] ^ U8TO32(in +  8));
			U32TO8(out + 12,  x[3] ^ U8TO32(in + 12));
			U32TO8(out + 16,  x[4] ^ U8TO32(in + 16));
			U32TO8(out + 20,  x[5] ^ U8TO32(in + 20));
			U32TO8(out + 24,  x[6] ^ U8TO32(in + 24));
			U32TO8(out + 28,  x[7] ^ U8TO32(in + 28));
			U32TO8(out + 32,  x[8] ^ U8TO32(in + 32));
			U32TO8(out + 36,  x[9] ^ U8TO32(in + 36));
			U32TO8(out + 40, x[10] ^ U8TO32(in + 40));
			U32TO8(out + 44, x[11] ^ U8TO32(in + 44));
			U32TO8(out + 48, x[12] ^ U8TO32(in + 48));
			U32TO8(out + 52, x[13] ^ U8TO32(in + 52));
			U32TO8(out + 56, x[14] ^ U8TO32(in + 56));
			U32TO8(out + 60, x[15] ^ U8TO32(in + 60));
			in += 64;
		} else {
			U32TO8(out +  0,  x[0]);
			U32TO8(out +  4,  x[1]);
			U32TO8(out +  8,  x[2]);
			U32TO8(out + 12,  x[3]);
			U32TO8(out + 16,  x[4]);
			U32TO8(out + 20,  x[5]);
			U32TO8(out + 24,  x[6]);
			U32TO8(out + 28,  x[7]);
			U32TO8(out + 32,  x[8]);
			U32TO8(out + 36,  x[9]);
			U32TO8(out + 40, x[10]);
			U32TO8(out + 44, x[11]);
			U32TO8(out + 48, x[12]);
			U32TO8(out + 52, x[13]);
			U32TO8(out + 56, x[14]);
			U32TO8(out + 60, x[15]);
		}

		/* increment the 64 bit counter, split in to two 32 bit halves */
		j[8]++;
		if (!j[8])
			j[9]++;

		if (bytes <= 64) {
			if (bytes < 64) for (i = 0; i < bytes; i++) ctarget[i] = out[i];

			/* store the counter back to the state */
			U32TO8(state->s + 32, j[8]);
			U32TO8(state->s + 36, j[9]);
			return;
		}
		bytes -= 64;
		out += 64;
	}
}

/* is the pointer aligned on a word boundary? */
static int
chacha_is_aligned(const void *p) {
	return ((size_t)p & (sizeof(size_t) - 1)) == 0;
}

/* initialize the state */
void
chacha_init(chacha_state *S, const chacha_key *key, const chacha_iv *iv, size_t rounds)
{
	chacha_state_internal *state = (chacha_state_internal *)S;
	memcpy(state->s + 0, key, 32);
	memset(state->s + 32, 0, 8);
	memcpy(state->s + 40, iv, 8);
	state->rounds = rounds;
	state->leftover = 0;
}

/* processes inlen bytes (can do partial blocks), handling input/ouput alignment */
static void
chacha_consume(chacha_state_internal *state, const unsigned char *in, unsigned char *out, size_t inlen)
{
	unsigned char buffer[16 * CHACHA_BLOCKBYTES];
	int in_aligned, out_aligned;

	/* it's ok to call with 0 bytes */
	if (!inlen)
		return;

	/* if everything is aligned, handle directly */
	in_aligned = chacha_is_aligned(in);
	out_aligned = chacha_is_aligned(out);
	if (in_aligned && out_aligned) {
		chacha_blocks(state, in, out, inlen);
		return;
	}

	/* copy the unaligned data to an aligned buffer and process in chunks */
	while (inlen) {
		const size_t bytes = (inlen > sizeof(buffer)) ? sizeof(buffer) : inlen;
		const unsigned char *src = in;
		unsigned char *dst = (out_aligned) ? out : buffer;
		if (!in_aligned) {
			memcpy(buffer, in, bytes);
			src = buffer;
		}
		chacha_blocks(state, src, dst, bytes);
		if (!out_aligned)
			memcpy(out, buffer, bytes);
		if (in) in += bytes;
		out += bytes;
		inlen -= bytes;
	}
}


/* update, returns number of bytes written to out */
size_t
chacha_update(chacha_state *S, const unsigned char *in, unsigned char *out, size_t inlen)
{
	chacha_state_internal *state = (chacha_state_internal *)S;
	unsigned char *out_start = out;
	size_t bytes;

	/* enough for at least one block? */
	if ((state->leftover + inlen) >= CHACHA_BLOCKBYTES) {
		/* handle the previous data */
		if (state->leftover) {
			bytes = (CHACHA_BLOCKBYTES - state->leftover);
			if (in) {
				memcpy(state->buffer + state->leftover, in, bytes);
				in += bytes;
			}
			chacha_consume(state, (in) ? state->buffer : NULL, out, CHACHA_BLOCKBYTES);
			inlen -= bytes;
			out += CHACHA_BLOCKBYTES;
			state->leftover = 0;
		}

		/* handle the direct data */
		bytes = (inlen & ~(CHACHA_BLOCKBYTES - 1));
		if (bytes) {
			chacha_consume(state, in, out, bytes);
			inlen -= bytes;
			if (in) in += bytes;
			out += bytes;
		}
	}

	/* handle leftover data */
	if (inlen) {
		if (in) memcpy(state->buffer + state->leftover, in, inlen);
		else memset(state->buffer + state->leftover, 0, inlen);
		state->leftover += inlen;
	}

	return out - out_start;
}

/* finalize, write out any leftover data */
size_t
chacha_final(chacha_state *S, unsigned char *out) {
	chacha_state_internal *state = (chacha_state_internal *)S;
	if (state->leftover) {
		if (chacha_is_aligned(out)) {
			chacha_blocks(state, state->buffer, out, state->leftover);
		} else {
			chacha_blocks(state, state->buffer, state->buffer, state->leftover);
			memcpy(out, state->buffer, state->leftover);
		}
	}
	explicit_memzero(S, sizeof(chacha_state));

	return state->leftover;
}
