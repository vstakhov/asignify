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
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <ctype.h>

#include "blake2.h"
#include "sha2.h"
#include "asignify.h"
#include "asignify_internal.h"
#include "khash.h"
#include "kvec.h"

struct asignify_verify_digest {
	enum asignify_digest_type digest_type;
	unsigned char *digest;
	struct asignify_verify_digest *next;
};

struct asignify_verify_file {
	char *fname;
	struct asignify_verify_digest *digests;
	uint64_t size;
};

KHASH_INIT(asignify_verify_hnode, const char *, struct asignify_verify_file *, 1,
	kh_str_hash_func, kh_str_hash_equal);

struct asignify_verify_ctx {
	struct asignify_pubkey *pk;
	khash_t(asignify_verify_hnode) *files;
	const char *error;
};

static unsigned char *
asignify_verify_load_sig(struct asignify_verify_ctx *ctx, FILE *f, size_t *len)
{
	const size_t maxlen = 1 << 30;
	struct stat st;
	int r;
#if BUFSIZ >= 2048
	unsigned char buf[BUFSIZ];
#else
	/* BUFSIZ is insanely small */
	unsigned char buf[4096];
#endif
	kvec_t(unsigned char) res;

	if (ctx == NULL || f == NULL || fstat(fileno(f), &st) == -1) {
		return (NULL);
	}

	if (S_ISREG(st.st_mode) && st.st_size > maxlen) {
		ctx->error = xerr_string(ASIGNIFY_ERROR_FILE);
		return (NULL);
	}

	kv_init(res);

	while ((r = fread(buf, 1, sizeof(buf), f)) > 0) {
		kv_push_a(unsigned char, res, buf, r);
	}

	*len = kv_size(res);

	return (res.a);
}

static enum asignify_digest_type
asignify_verify_parse_digest_type(const char *data, ssize_t dlen)
{
	if (dlen == sizeof("SHA512") - 1) {
		if (strncasecmp(data, "sha512", dlen) == 0) {
			return (ASIGNIFY_DIGEST_SHA512);
		}
		else if (strncasecmp(data, "sha256", dlen) == 0) {
			return (ASIGNIFY_DIGEST_SHA256);
		}
		else if (strncasecmp(data, "blake2", dlen) == 0) {
			return (ASIGNIFY_DIGEST_BLAKE2);
		}
	}
	else if (dlen == sizeof("SIZE") - 1) {
		if (strncasecmp(data, "size", dlen) == 0) {
			return (ASIGNIFY_DIGEST_SIZE);
		}
	}

	return (ASIGNIFY_DIGEST_MAX);
}

static bool
asignify_verify_parse_digest(const char *data, ssize_t dlen,
	enum asignify_digest_type type, struct asignify_verify_file *f)
{
	const unsigned int digests_sizes[ASIGNIFY_DIGEST_MAX] = {
		[ASIGNIFY_DIGEST_SHA512] = SHA512_DIGEST_STRING_LENGTH - 1,
		[ASIGNIFY_DIGEST_SHA256] = SHA256_DIGEST_STRING_LENGTH - 1,
		[ASIGNIFY_DIGEST_BLAKE2] = BLAKE2B_OUTBYTES * 2,
		[ASIGNIFY_DIGEST_SIZE] = 0
	};
	char *errstr;
	uint64_t flen;
	struct asignify_verify_digest *dig;
	unsigned int dig_len;

	if (dlen <= 0 || type >= ASIGNIFY_DIGEST_MAX || f == NULL) {
		return (false);
	}

	if (digests_sizes[type] > 0 && digests_sizes[type] != dlen) {
		return (false);
	}

	if (type == ASIGNIFY_DIGEST_SIZE) {
		/* Special case for size */
		errno = 0;
		flen = strtoumax (data, &errstr, 10);
		if (errstr != data + dlen || errno != 0) {
			return (false);
		}
		f->size = flen;
	}
	else {
		dig = xmalloc(sizeof(*dig));
		dig->digest_type = type;
		dig_len = asignify_digest_len(type);

		if (dig_len == 0) {
			free(dig);
			return (false);
		}

		dig->digest = xmalloc(dig_len);

		if (hex2bin(dig->digest, dig_len, data, dlen, NULL, NULL) != 0) {
			free(dig->digest);
			free(dig);
			return (false);
		}

		dig->next = f->digests;
		f->digests = dig;
	}

	return (true);
}

static bool
asignify_verify_parse_files(struct asignify_verify_ctx *ctx, const char *data,
	size_t dlen)
{
	enum stm_st {
		PARSE_START = 0,
		PARSE_ALG,
		PARSE_OBRACE,
		PARSE_FILE,
		PARSE_EQSIGN,
		PARSE_HASH,
		PARSE_SPACES,
		PARSE_ERROR,
		PARSE_FINISH
	} state = PARSE_START, next_state = PARSE_START;
	const char *p, *end, *c;
	char *fbuf;
	khiter_t k;
	int r;
	struct asignify_verify_file *cur_file = NULL;
	enum asignify_digest_type dig_type = ASIGNIFY_DIGEST_MAX;

	p = data;
	end = p + dlen;
	c = p;

	while (p <= end) {
		switch (state) {
		case PARSE_START:
			cur_file = NULL;
			if (*p == '\0') {
				state = PARSE_FINISH;
			}
			else if (isspace(*p)) {
				next_state = PARSE_ALG;
				state = PARSE_SPACES;
			}
			else {
				/* We have algorithm definition */
				c = p;
				state = PARSE_ALG;
			}
			break;
		case PARSE_ALG:
			if (isgraph(*p)) {
				p ++;
			}
			else {
				if (*p == ' ') {
					/* Check algorithm */
					dig_type = asignify_verify_parse_digest_type(c, p - c);
					if (dig_type == ASIGNIFY_DIGEST_MAX) {
						state = PARSE_ERROR;
					}
					else {
						state = PARSE_SPACES;
						next_state = PARSE_OBRACE;
					}
				}
				else {
					state = PARSE_ERROR;
				}
			}
			break;
		case PARSE_OBRACE:
			if (*p == '(') {
				p++;
				c = p;
				state = PARSE_FILE;
			}
			else {
				state = PARSE_ERROR;
			}
			break;
		case PARSE_FILE:
			if (isgraph(*p) && *p != ')') {
				p ++;
			}
			else {
				if (*p == ')') {
					/* Check file */
					if (p - c > 0) {

						fbuf = xmalloc(p - c + 1);
						memcpy(fbuf, c, p - c);
						fbuf[p - c] = '\0';
						k = kh_get(asignify_verify_hnode, ctx->files, fbuf);

						if (k != kh_end(ctx->files)) {
							/* We already have the node */
							free(fbuf);
							fbuf = NULL;
							cur_file = kh_value(ctx->files, k);
						}
						else {
							cur_file = xmalloc0(sizeof(*cur_file));
							cur_file->fname = fbuf;
							fbuf = NULL;
							k = kh_put(asignify_verify_hnode, ctx->files,
								fbuf, &r);
							if (r == -1) {
								state = PARSE_ERROR;
							}
							else {
								kh_value(ctx->files, k) = cur_file;
							}
						}
						if (state != PARSE_ERROR) {
							p ++;
							c = p;
							next_state = PARSE_EQSIGN;
							state = PARSE_SPACES;
						}
					}
					else {
						state = PARSE_ERROR;
					}
				}
			}
			break;
		case PARSE_EQSIGN:
			if (*p == '=') {
				p++;
				c = p;
				state = PARSE_SPACES;
				next_state = PARSE_HASH;
			}
			else {
				state = PARSE_ERROR;
			}
			break;
		case PARSE_HASH:
			if (isxdigit(*p)) {
				p ++;
			}
			else if (*p == '\n' || *p == '\0') {
				if (!asignify_verify_parse_digest(c, p - c, dig_type, cur_file)) {
					state = PARSE_ERROR;
				}
				else {
					state = PARSE_START;
				}
			}
			break;
		case PARSE_SPACES:
			if (isspace(*p)) {
				p ++;
			}
			else {
				c = p;
				state = next_state;
			}
			break;

		case PARSE_FINISH:
			/* All done */
			return (true);
			break;

		case PARSE_ERROR:
		default:
			ctx->error = xerr_string(ASIGNIFY_ERROR_FORMAT);
			return (false);
			break;
		}
	}

	return (false);
}

asignify_verify_t*
asignify_verify_init(void)
{
	asignify_verify_t *nctx;

	nctx = xmalloc0(sizeof(*nctx));

	return (nctx);
}


bool
asignify_verify_load_pubkey(asignify_verify_t *ctx, const char *pubf)
{
	FILE *f;
	bool ret = false;

	if (ctx == NULL) {
		return (false);
	}

	f = xfopen(pubf, "r");
	if (f == NULL) {
		ctx->error = xerr_string(ASIGNIFY_ERROR_FILE);
	}
	else {
		ctx->pk = asignify_pubkey_load(f);
		if (ctx->pk == NULL) {
			ctx->error = xerr_string(ASIGNIFY_ERROR_FORMAT);
		}
		else {
			ret = true;
		}
	}

	return (ret);
}

bool
asignify_verify_load_signature(asignify_verify_t *ctx, const char *sigf)
{
	struct asignify_signature *sig;
	unsigned char *data;
	size_t dlen;
	FILE *f;

	if (ctx == NULL || ctx->pk == NULL) {
		if (ctx) {
			ctx->error = xerr_string(ASIGNIFY_ERROR_MISUSE);
		}
		return (false);
	}

	f = xfopen(sigf, "r");
	if (f == NULL) {
		ctx->error = xerr_string(ASIGNIFY_ERROR_FILE);
	}
	else {
		sig = asignify_signature_load(f);
		if (ctx->pk == NULL) {
			ctx->error = xerr_string(ASIGNIFY_ERROR_FORMAT);
		}
		else {
			data = asignify_verify_load_sig(ctx, f, &dlen);
			if (data == NULL || dlen == 0) {
				return (false);
			}

			if (!asignify_pubkey_check_signature(ctx->pk, sig, data, dlen)) {
				return (false);
			}

			/* We are now safe to parse digests */
			if (!asignify_verify_parse_files(ctx, (const char *)data, dlen)) {
				return (false);
			}
		}
	}

	return (false);
}

bool
asignify_verify_file(asignify_verify_t *ctx, const char *checkf)
{
	return (false);
}


const char*
asignify_verify_get_error(asignify_verify_t *ctx)
{
	if (ctx == NULL) {
		return (xerr_string(ASIGNIFY_ERROR_MISUSE));
	}

	return (ctx->error);
}

void
asignify_verify_free(asignify_verify_t *ctx)
{
	khiter_t k;
	struct asignify_verify_digest *d, *dtmp;
	struct asignify_verify_file *f;

	if (ctx) {
		asignify_pubkey_free(ctx->pk);

		for (k = kh_begin(ctx->files); k != kh_end(ctx->files); ++k) {
			if (kh_exist(ctx->files, k)) {
				f = kh_value(ctx->files, k);
				for(d = f->digests; d && (dtmp = d->next, 1); d = dtmp) {
					free(d->digest);
					free(d);
				}
				free(f->fname);
				free(f);
			}
		}

		kh_destroy(asignify_verify_hnode, ctx->files);
	}
}
