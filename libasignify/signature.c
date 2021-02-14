/*
 * Copyright (c) 2015, Vsevolod Stakhov
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in the
 *	   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR ''AS IS'' AND ANY
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "asignify.h"
#include "asignify_internal.h"
#include "tweetnacl.h"

#define SIG_MAGIC "asignify-sig:"
#define OBSD_SIGALG "Ed"
#define SIG_VER_MAX 1
#define SIG_LEN crypto_sign_ed25519_BYTES

struct obsd_signature {
	uint8_t sigalg[2];
	uint8_t keynum[8];
	uint8_t sig[crypto_sign_ed25519_BYTES];
};


static bool
asignify_sig_try_obsd(const char *buf, size_t buflen,
	struct asignify_public_data **sig)
{
	struct obsd_signature osig;
	struct asignify_public_data *res;

	if (buflen >= sizeof(OBSD_COMMENTHDR) - 1 &&
			memcmp(buf, OBSD_COMMENTHDR, sizeof(OBSD_COMMENTHDR) - 1) == 0) {
		/*
		 * XXX:
		 * For now we do not use openbsd hints about keys for this specific
		 * signature.
		 */
		return (true);
	}

	if (b64_pton(buf, (unsigned char *)&osig, sizeof(osig)) == sizeof(osig)) {
		if (memcmp(osig.sigalg, OBSD_SIGALG, sizeof(osig.sigalg)) == 0) {
			res = xmalloc0(sizeof(*res));
			/* OpenBSD version code */
			res->version = 0;
			res->data_len = sizeof(osig.sig);
			res->id_len = sizeof(osig.keynum);
			asignify_alloc_public_data_fields(res);
			memcpy(res->data, osig.sig, res->data_len);
			memcpy(res->id, osig.keynum, res->id_len);

			*sig = res;
		}
	}

	return (false);
}

struct asignify_public_data*
asignify_signature_load(FILE *f, struct asignify_public_data *pk)
{
	struct asignify_public_data *res = NULL;
	char *buf = NULL;
	size_t buflen = 0;
	ssize_t r;
	bool first = true;

	if (f == NULL) {
		abort();
	}

	while ((r = getline(&buf, &buflen, f)) != -1) {
		if (first && r > sizeof(SIG_MAGIC)) {
			first = false;

			if (memcmp(buf, SIG_MAGIC, sizeof(SIG_MAGIC) - 1) == 0) {
				res = asignify_public_data_load(buf, r,
					SIG_MAGIC, sizeof(SIG_MAGIC) - 1,
					SIG_VER_MAX, SIG_VER_MAX,
					pk->id_len, SIG_LEN);
				break;
			}
		}
		if (!asignify_sig_try_obsd(buf, r, &res)) {
			break;
		}
	}

	return (res);
}

struct asignify_public_data*
asignify_private_data_sign(struct asignify_private_data *privk,
	unsigned char *buf, size_t len)
{
	struct asignify_public_data *res = NULL;
	unsigned long long outlen = len;

	if (buf != NULL && len > 0 && privk != NULL) {
		res = xmalloc0(sizeof(*res));
		res->version = privk->version;
		res->id_len = privk->id_len;
		res->data_len = crypto_sign_BYTES;

		asignify_alloc_public_data_fields(res);

		if (privk->id_len > 0) {
			memcpy(res->id, privk->id, res->id_len);
		}

		crypto_sign(buf, &outlen, buf + crypto_sign_BYTES, len - crypto_sign_BYTES,
			privk->data);
		memcpy(res->data, buf, res->data_len);
	}

	return (res);
}

bool
asignify_signature_write(struct asignify_public_data *sig, const void *buf,
	size_t len, FILE *f)
{
	char *b64data, *b64id = NULL;
	bool ret = false;

	if (sig == NULL || f == NULL || buf == NULL) {
		return (false);
	}

	if (sig->version == 1) {
		if (sig->id_len > 0) {
			b64id = xmalloc(sig->id_len * 2);
			b64_ntop(sig->id, sig->id_len, b64id, sig->id_len * 2);
		}
		b64data = xmalloc(sig->data_len * 2);
		b64_ntop(sig->data, sig->data_len, b64data, sig->data_len * 2);

		if (b64id != NULL) {
			ret = (fprintf(f, "%s1:%s:%s\n", SIG_MAGIC, b64id, b64data) > 0);
			free(b64id);
		}
		else {
			ret = (fprintf(f, "%s1::%s\n", SIG_MAGIC, b64data) > 0);
		}
		free(b64data);
	}
	else if (sig->version == 0) {
		/* XXX: support openbsd signatures format */
	}

	if (ret) {
		ret = (fwrite(buf, len, 1, f) > 0);
	}

	return (ret);
}
