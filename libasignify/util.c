/* Copyright (c) 2015, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#ifdef HAVE_OPENSSL
#include <openssl/rand.h>
#include <openssl/evp.h>
#endif
#ifdef HAVE_BSD_STDLIB_H
#include <bsd/stdlib.h>
#endif

#include "sha2.h"
#include "blake2.h"

#include "asignify_internal.h"

const char* err_str[ASIGNIFY_ERROR_MAX] = {
	[ASIGNIFY_ERROR_OK] = "No error",
	[ASIGNIFY_ERROR_FILE] = "File IO error",
	[ASIGNIFY_ERROR_FORMAT] = "Incorrect data format",
	[ASIGNIFY_ERROR_MISUSE] = "Library is used incorrectly",
	[ASIGNIFY_ERROR_VERIFY] = "Signature verification error",
	[ASIGNIFY_ERROR_VERIFY_DIGEST] = "Digest verification error",
	[ASIGNIFY_ERROR_SIZE] = "Size missmatch"
};

#ifdef HAVE_WEAK_SYMBOLS
__attribute__((weak)) void
_dummy_symbol_to_prevent_lto(void * const pnt, const size_t len)
{
	(void) pnt;
	(void) len;
}
#endif

void explicit_memzero(void * const pnt, const size_t len)
{
#if defined(HAVE_MEMSET_S)
	if (memset_s(pnt, (rsize_t) len, 0, (rsize_t) len) != 0) {
		abort();
	}
#elif defined(HAVE_EXPLICIT_BZERO)
	explicit_bzero(pnt, len);
#elif HAVE_WEAK_SYMBOLS
	memset(pnt, 0, len);
	_dummy_symbol_to_prevent_lto(pnt, len);
#else
	volatile unsigned char *pnt_ = (volatile unsigned char *) pnt;
	size_t i = (size_t) 0U;
	while (i < len) {
		pnt_[i++] = 0U;
	}
#endif
}


void
randombytes(unsigned char *buf, uint64_t len)
{
#ifdef HAVE_ARC4RANDOM
	arc4random_buf(buf, len);
#elif defined(HAVE_OPENSSL)
	if (RAND_bytes(buf, len) != 1) {
		abort();
	}
#else
# error No random numbers can be generated on your system
#endif
}


FILE *
xfopen(const char *fname, const char *mode)
{
	struct stat sb;
	FILE *res = NULL;

	if (fname == NULL || mode == NULL) {
		return (NULL);
	}

	if (strcmp(fname, "-") == 0) {
		if (strchr(mode, 'w') != NULL) {
			return (stdout);
		}
		else {
			return (stdin);
		}
	}
	else {
		if (stat(fname, &sb) == -1) {
			return (NULL);
		}
		else if (S_ISDIR(sb.st_mode)) {
			errno = EINVAL;
		}
		else {
			res = fopen(fname, mode);
		}
	}

	return (res);
}

void *
xmalloc(size_t len)
{
	void *p;

	if (len >= SIZE_MAX / 2) {
		abort();
	}

	if (!(p = malloc(len))) {
		abort();
	}
	return (p);
}

void *
xmalloc0(size_t len)
{
	void *p = xmalloc(len);

	memset(p, 0, len);

	return (p);
}

const char *
xerr_string(enum asignify_error code)
{
	if (code < ASIGNIFY_ERROR_OK || code >= ASIGNIFY_ERROR_MAX) {
		return (NULL);
	}

	return (err_str[code]);
}

/* Derived from original code by CodesInChaos */

int
hex2bin(unsigned char * const bin, const size_t bin_maxlen,
    const char * const hex, const size_t hex_len,
    size_t * const bin_len, const char ** const hex_end)
{
	size_t bin_pos = (size_t) 0U;
	size_t hex_pos = (size_t) 0U;
	int ret = 0;
	unsigned char c;
	unsigned char c_acc = 0U;
	unsigned char c_num;
	unsigned char c_val;
	unsigned char state = 0U;

	while (hex_pos < hex_len) {
		c = (unsigned char) hex[hex_pos];
		if ((c_num = c ^ 48U) < 10U) {
			c_val = c_num;
		}
		else if ((c_num = (c & ~32U)) > 64 && c_num < 71U) {
			c_val = c_num - 55U;
		}
		else {
			break;
		}
		if (bin_pos >= bin_maxlen) {
			ret = -1;
			errno = ERANGE;
			break;
		}
		if (state == 0U) {
			c_acc = c_val * 16U;
		}
		else {
			bin[bin_pos++] = c_acc | c_val;
		}
		state = ~state;
		hex_pos++;
	}

	if (state != 0U) {
		hex_pos--;
	}

	if (hex_end != NULL) {
		*hex_end = &hex[hex_pos];
	}

	if (bin_len != NULL) {
		*bin_len = bin_pos;
	}

	return ret;
}

char *
bin2hex(char * const hex, const size_t hex_maxlen,
               const unsigned char * const bin, const size_t bin_len)
{
    size_t       i = (size_t) 0U;
    unsigned int x;
    int          b;
    int          c;

    if (bin_len >= SIZE_MAX / 2 || hex_maxlen < bin_len * 2U) {
        abort();
    }
    while (i < bin_len) {
        c = bin[i] & 0xf;
        b = bin[i] >> 4;
        x = (unsigned char) (87 + c + (((c - 10) >> 31) & -39)) << 8 |
            (unsigned char) (87 + b + (((b - 10) >> 31) & -39));
        hex[i * 2U] = (char) x;
        x >>= 8;
        hex[i * 2U + 1U] = (char) x;
        i++;
    }
    hex[i * 2U] = 0;

    return hex;
}


unsigned int
asignify_digest_len(enum asignify_digest_type type)
{
	unsigned int ret;

	switch(type) {
	case ASIGNIFY_DIGEST_SHA512:
		ret = SHA512_DIGEST_LENGTH;
		break;
	case ASIGNIFY_DIGEST_SHA256:
		ret = SHA256_DIGEST_LENGTH;
		break;
	case ASIGNIFY_DIGEST_BLAKE2:
		ret = BLAKE2B_OUTBYTES;
		break;
	default:
		ret = 0;
		break;
	}

	return (ret);
}

static void *
asignify_digest_init(enum asignify_digest_type type)
{
#ifdef HAVE_OPENSSL
	EVP_MD_CTX *mdctx;
#else
	SHA2_CTX *st;
#endif
	blake2b_state *bst;

	void *res = NULL;

	switch(type) {
	case ASIGNIFY_DIGEST_SHA512:
#ifdef HAVE_OPENSSL
		mdctx = EVP_MD_CTX_create();
		EVP_DigestInit_ex(mdctx, EVP_sha512(), NULL);
		res = mdctx;
#else
		st = xmalloc(sizeof(*st));
		SHA512Init(&st);
		res = st;
#endif
		break;
	case ASIGNIFY_DIGEST_SHA256:
#ifdef HAVE_OPENSSL
		mdctx = EVP_MD_CTX_create();
		EVP_DigestInit(mdctx, EVP_sha256());
		res = mdctx;
#else
		st = xmalloc(sizeof(*st));
		SHA256Init(&st);
		res = st;
#endif
		break;
	case ASIGNIFY_DIGEST_BLAKE2:
		bst = xmalloc(sizeof(*bst));
		blake2b_init(bst, BLAKE2B_OUTBYTES);
		res = bst;
		break;
	default:
		abort();
		break;
	}

	return (res);
}

static void
asignify_digest_update(enum asignify_digest_type type, void *ctx,
	const unsigned char *buf, size_t len)
{
#ifdef HAVE_OPENSSL
	EVP_MD_CTX *mdctx;
#else
	SHA2_CTX *st;
#endif
	blake2b_state *bst;

	switch(type) {
		case ASIGNIFY_DIGEST_SHA512:
#ifdef HAVE_OPENSSL
			mdctx = (EVP_MD_CTX *)ctx;
			EVP_DigestUpdate(mdctx, buf, len);
#else
			st = (SHA2_CTX *)ctx;
			SHA512Update(ctx, buf, len);
#endif
			break;
		case ASIGNIFY_DIGEST_SHA256:
#ifdef HAVE_OPENSSL
			mdctx = (EVP_MD_CTX *)ctx;
			EVP_DigestUpdate(mdctx, buf, len);
#else
			st = (SHA2_CTX *)ctx;
			SHA256Update(ctx, buf, len);
#endif
			break;
		case ASIGNIFY_DIGEST_BLAKE2:
			bst = (blake2b_state *)ctx;
			blake2b_update(bst, buf, len);
			break;
		default:
			abort();
			break;
	}

}

static unsigned char*
asignify_digest_final(enum asignify_digest_type type, void *ctx)
{
	unsigned int len = asignify_digest_len(type);
	unsigned char *res;
#ifdef HAVE_OPENSSL
	EVP_MD_CTX *mdctx;
#else
	SHA2_CTX *st;
#endif
	blake2b_state *bst;

	res = xmalloc(len);
	switch(type) {
		case ASIGNIFY_DIGEST_SHA512:
#ifdef HAVE_OPENSSL
			mdctx = (EVP_MD_CTX *)ctx;
			EVP_DigestFinal(mdctx, res, &len);
			EVP_MD_CTX_destroy(mdctx);
#else
			st = (SHA2_CTX *)ctx;
			SHA512Final(res, st);
			free(st);
#endif
			break;
		case ASIGNIFY_DIGEST_SHA256:
#ifdef HAVE_OPENSSL
			mdctx = (EVP_MD_CTX *)ctx;
			EVP_DigestFinal(mdctx, res, &len);
			EVP_MD_CTX_destroy(mdctx);
#else
			st = (SHA2_CTX *)ctx;
			SHA256Final(res, st);
			free(st);
#endif
			break;
		case ASIGNIFY_DIGEST_BLAKE2:
			bst = (blake2b_state *)ctx;
			blake2b_final(bst, res, len);
			free(bst);
			break;
		default:
			abort();
			break;
	}

	return (res);
}

unsigned char*
asignify_digest_fd(enum asignify_digest_type type, int fd)
{
	int r;
#if BUFSIZ >= 2048
	unsigned char buf[BUFSIZ];
#else
	/* BUFSIZ is insanely small */
	unsigned char buf[4096];
#endif
	void *dgst;

	if (fd == -1 || type >= ASIGNIFY_DIGEST_SIZE ||
			(dgst = asignify_digest_init(type)) == NULL) {
		return (NULL);
	}

	if (lseek(fd, 0, SEEK_SET) == (off_t)-1) {
		/* XXX: not correct if openssl is used */
		free(dgst);
		return (NULL);
	}

	while ((r = read(fd, buf, sizeof(buf))) > 0) {
		asignify_digest_update(type, dgst, buf, r);
	}

	return (asignify_digest_final(type, dgst));
}
