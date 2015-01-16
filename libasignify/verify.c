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
#include <fcntl.h>

#include "blake2.h"
#include "sha2.h"
#include "asignify.h"
#include "asignify_internal.h"
#include "khash.h"
#include "kvec.h"

KHASH_INIT(asignify_verify_hnode, const char *, struct asignify_file *, 1,
	kh_str_hash_func, kh_str_hash_equal);

struct asignify_pubkey_chain {
	struct asignify_public_data *pk;
	struct asignify_pubkey_chain *next;
};

struct asignify_verify_ctx {
	struct asignify_pubkey_chain *pk_chain;
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
	kv_push(unsigned char, res, '\0');

	return (res.a);
}

enum asignify_digest_type
asignify_digest_from_str(const char *data, ssize_t dlen)
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
	enum asignify_digest_type type, struct asignify_file *f)
{
	const unsigned int digests_sizes[ASIGNIFY_DIGEST_MAX] = {
		[ASIGNIFY_DIGEST_SHA512] = SHA512_DIGEST_STRING_LENGTH - 1,
		[ASIGNIFY_DIGEST_SHA256] = SHA256_DIGEST_STRING_LENGTH - 1,
		[ASIGNIFY_DIGEST_BLAKE2] = BLAKE2B_OUTBYTES * 2,
		[ASIGNIFY_DIGEST_SIZE] = 0
	};
	char *errstr;
	uint64_t flen;
	struct asignify_file_digest *dig;
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
	const unsigned char *p, *end, *c;
	char *fbuf;
	khiter_t k;
	int r;
	struct asignify_file *cur_file = NULL;
	enum asignify_digest_type dig_type = ASIGNIFY_DIGEST_MAX;

	p = (unsigned char *)data;
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
				next_state = PARSE_START;
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
					dig_type = asignify_digest_from_str((const char *)c, p - c);
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
							k = kh_put(asignify_verify_hnode, ctx->files,
								cur_file->fname, &r);
							fbuf = NULL;

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
				if (!asignify_verify_parse_digest((const char *)c, p - c,
						dig_type, cur_file)) {
					state = PARSE_ERROR;
				}
				else {
					state = PARSE_START;
				}
			}
			break;
		case PARSE_SPACES:
			if (*p != '\0' && isspace(*p)) {
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
	bool ret = true;
	struct asignify_public_data *pk;
	struct asignify_pubkey_chain *chain;

	if (ctx == NULL) {
		return (false);
	}

	f = xfopen(pubf, "r");
	if (f == NULL) {
		ctx->error = xerr_string(ASIGNIFY_ERROR_FILE);
	}
	else {
		pk = asignify_pubkey_load(f);
		if (pk == NULL) {
			ctx->error = xerr_string(ASIGNIFY_ERROR_FORMAT);
			ret = false;
		}
		else if (ret) {
			chain = xmalloc(sizeof(*chain));
			chain->pk = pk;
			chain->next = ctx->pk_chain;
			ctx->pk_chain = chain;
		}
		fclose(f);
	}

	return (ret);
}

bool
asignify_verify_load_signature(asignify_verify_t *ctx, const char *sigf)
{
	struct asignify_public_data *sig;
	struct asignify_pubkey_chain *chain;
	unsigned char *data;
	size_t dlen;
	FILE *f;
	bool ret = false;

	if (ctx == NULL || ctx->pk_chain == NULL) {
		CTX_MAYBE_SET_ERR(ctx, ASIGNIFY_ERROR_MISUSE);
		return (false);
	}

	f = xfopen(sigf, "r");
	if (f == NULL) {
		ctx->error = xerr_string(ASIGNIFY_ERROR_FILE);
	}
	else {
		/* XXX: we assume that all pk in chain are the same */
		sig = asignify_signature_load(f, ctx->pk_chain->pk);
		if (ctx->pk_chain == NULL) {
			ctx->error = xerr_string(ASIGNIFY_ERROR_FORMAT);
		}
		else {
			data = asignify_verify_load_sig(ctx, f, &dlen);
			if (data == NULL || dlen == 0) {
				fclose(f);
				return (false);
			}

			chain = ctx->pk_chain;
			while (chain != NULL && !ret) {
				ret = asignify_pubkey_check_signature(chain->pk, sig, data, dlen);
				chain = chain->next;
			}
			if (!ret) {
				asignify_public_data_free(sig);
				free(data);
				ctx->error = xerr_string(ASIGNIFY_ERROR_VERIFY);
				fclose(f);
				return (false);
			}

			/* We are now safe to parse digests */
			asignify_public_data_free(sig);
			ctx->files = kh_init(asignify_verify_hnode);

			if (asignify_verify_parse_files(ctx, (const char *)data, dlen)) {
				ret = true;
			}
			free(data);
		}
		fclose(f);
	}

	return (ret);
}

bool
asignify_verify_file(asignify_verify_t *ctx, const char *checkf)
{
	khiter_t k;
	struct stat st;
	int fd, check;
	struct asignify_file *f;
	struct asignify_file_digest *d;
	unsigned char *calc_digest;

	if (ctx == NULL || ctx->files == NULL) {
		CTX_MAYBE_SET_ERR(ctx, ASIGNIFY_ERROR_MISUSE);
		return (false);
	}

	k = kh_get(asignify_verify_hnode, ctx->files, checkf);

	if (k != kh_end(ctx->files)) {
		fd = xopen(checkf, O_RDONLY, 0);

		f = kh_value(ctx->files, k);

		if (fstat(fd, &st) == -1 || S_ISDIR(st.st_mode)) {
			close(fd);
			ctx->error = xerr_string(ASIGNIFY_ERROR_FILE);
			return (false);
		}

		if (f->size > 0 && f->size != st.st_size) {
			ctx->error = xerr_string(ASIGNIFY_ERROR_VERIFY_SIZE);
			close(fd);
			return (false);
		}

		d = f->digests;
		while (d) {
			calc_digest = asignify_digest_fd(d->digest_type, fd);

			if (calc_digest == NULL) {
				close(fd);
				ctx->error = xerr_string(ASIGNIFY_ERROR_SIZE);
				return (false);
			}
			else {
				check = memcmp(calc_digest, d->digest,
					asignify_digest_len(d->digest_type));
				free(calc_digest);

				if (check != 0) {
					ctx->error = xerr_string(ASIGNIFY_ERROR_VERIFY_DIGEST);
					close(fd);
					return (false);
				}
			}
			d = d->next;
		}

		close(fd);

		return (true);
	}
	else {
		ctx->error = xerr_string(ASIGNIFY_ERROR_NO_DIGEST);
	}

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
	struct asignify_file_digest *d, *dtmp;
	struct asignify_file *f;
	struct asignify_pubkey_chain *chain, *ctmp;

	if (ctx) {

		chain = ctx->pk_chain;

		while (chain != NULL) {
			asignify_public_data_free(chain->pk);
			ctmp = chain;
			chain = chain->next;
			free(ctmp);
		}

		if (ctx->files) {
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
		}

		kh_destroy(asignify_verify_hnode, ctx->files);
		free(ctx);
	}
}
