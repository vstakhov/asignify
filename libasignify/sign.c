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
#include "tweetnacl.h"
#include "khash.h"
#include "kvec.h"

struct asignify_sign_ctx {
	struct asignify_private_data *privk;
	kvec_t(struct asignify_file) files;
	const char *error;
};

asignify_sign_t*
asignify_sign_init(void)
{
	asignify_sign_t *nctx;

	nctx = xmalloc0(sizeof(*nctx));

	return (nctx);
}

bool
asignify_sign_load_privkey(asignify_sign_t *ctx, const char *privf,
	asignify_password_cb password_cb, void *d)
{
	FILE *f;
	bool ret = false;
	int error = ASIGNIFY_ERROR_FORMAT;

	if (ctx == NULL || privf == NULL) {
		CTX_MAYBE_SET_ERR(ctx, ASIGNIFY_ERROR_MISUSE);
		return (false);
	}

	f = xfopen(privf, "r");
	if (f == NULL) {
		ctx->error = xerr_string(ASIGNIFY_ERROR_FILE);
	}
	else {
		ctx->privk = asignify_private_data_load(f, &error, password_cb, d);
		if (ctx->privk == NULL) {
			ctx->error = xerr_string(error);
		}
		else {
			ret = true;
		}
		fclose(f);
	}

	return (ret);
}

bool
asignify_sign_add_file(asignify_sign_t *ctx, const char *f,
	enum asignify_digest_type dt)
{
	int fd;
	struct stat st;
	unsigned char *calc_digest;
	struct asignify_file check_file;
	struct asignify_file_digest *dig;

	if (ctx == NULL || f == NULL || dt >= ASIGNIFY_DIGEST_MAX) {
		CTX_MAYBE_SET_ERR(ctx, ASIGNIFY_ERROR_MISUSE);
		return (false);
	}

	fd = xopen(f, O_RDONLY, 0);
	if (fd == -1) {
		ctx->error = xerr_string(ASIGNIFY_ERROR_FILE);
		return (false);
	}

	check_file.fname = xstrdup(f);

	if (dt == ASIGNIFY_DIGEST_SIZE) {
		fstat(fd, &st);
		check_file.size = st.st_size;
		check_file.digests = 0;
	}
	else {
		calc_digest = asignify_digest_fd(dt, fd);

		if (calc_digest == NULL) {
			close(fd);
			ctx->error = xerr_string(ASIGNIFY_ERROR_SIZE);
			return (false);
		}
		dig = xmalloc0(sizeof(*dig));
		dig->digest_type = dt;
		dig->digest = calc_digest;
		check_file.size = 0;
		check_file.digests = dig;
		close(fd);
	}

	kv_push(struct asignify_file, ctx->files, check_file);

	return (true);
}

bool
asignify_sign_write_signature(asignify_sign_t *ctx, const char *sigf)
{
	kvec_t(char) out;
	char sig_pad[crypto_sign_BYTES + sizeof(unsigned int)];
	char line[PATH_MAX + 256], hex[256];
	struct asignify_file *f;
	int i, r;
	bool ret = false;
	struct asignify_public_data *sig = NULL;
	FILE *outf;

	if (ctx == NULL || ctx->privk == NULL || kv_size(ctx->files) == 0) {
		CTX_MAYBE_SET_ERR(ctx, ASIGNIFY_ERROR_MISUSE);
		return (false);
	}

	kv_init(out);
	kv_reserve(char, out, kv_size(ctx->files) * PATH_MAX + crypto_sign_BYTES);

	memset(sig_pad, 0, sizeof(sig_pad));
	memcpy(sig_pad + crypto_sign_BYTES, &ctx->privk->version,
		sizeof(unsigned int));
	kv_push_a(char, out, sig_pad, sizeof(sig_pad));

	for (i = 0; i < kv_size(ctx->files); i ++) {
		f = &kv_A(ctx->files, i);
		if (f->size != 0) {
			r = snprintf(line, sizeof(line), "SIZE (%s) = %zu\n", f->fname,
				f->size);
			if (r >= sizeof(line)) {
				ctx->error = xerr_string(ASIGNIFY_ERROR_SIZE);
				kv_destroy(out);
				return (false);
			}
		}
		else {
			bin2hex(hex, sizeof(hex) - 1, f->digests->digest,
				asignify_digest_len(f->digests->digest_type));
			r = snprintf(line, sizeof(line), "%s (%s) = %s\n",
				asignify_digest_name(f->digests->digest_type),
				f->fname,
				hex);
			if (r >= sizeof(line)) {
				ctx->error = xerr_string(ASIGNIFY_ERROR_SIZE);
				kv_destroy(out);
				return (false);
			}
		}
		kv_push_a(char, out, line, r);
	}

	sig = asignify_private_data_sign(ctx->privk, (unsigned char *)out.a,
		kv_size(out));

	if (sig != NULL) {
		outf = xfopen(sigf, "w");

		if (outf == NULL) {
			ctx->error = xerr_string(ASIGNIFY_ERROR_FILE);
		}
		else {
			ret = asignify_signature_write(sig, out.a + sizeof(sig_pad),
				kv_size(out) - sizeof(sig_pad), outf);
		}
		fclose(outf);
	}
	else {
		ctx->error = xerr_string(ASIGNIFY_ERROR_MISUSE);
	}

	kv_destroy(out);

	return (ret);
}

const char*
asignify_sign_get_error(asignify_sign_t *ctx)
{
	if (ctx == NULL) {
		return (xerr_string(ASIGNIFY_ERROR_MISUSE));
	}

	return (ctx->error);
}

void
asignify_sign_free(asignify_sign_t *ctx)
{
	struct asignify_file *f;
	int i;

	if (ctx) {
		asignify_private_data_free(ctx->privk);

		for (i = 0; i < kv_size(ctx->files); i ++) {
			f = &kv_A(ctx->files, i);
			if (f->digests) {
				free(f->digests->digest);
				free(f->digests);
			}
			free(f->fname);
		}
		kv_destroy(ctx->files);
		free(ctx);
	}
}
