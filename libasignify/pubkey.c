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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "asignify.h"
#include "asignify_internal.h"
#include "tweetnacl.h"

#define PUBKEY_MAGIC "asignify-pubkey:"
#define OBSD_PKALG "Ed"
#define PUBKEY_VER_MAX 1
#define PUBKEY_ID_LEN 8
#define PUBKEY_KEY_LEN crypto_sign_ed25519_PUBLICKEYBYTES

struct obsd_pubkey {
	uint8_t pkalg[2];
	uint8_t keynum[8];
	uint8_t pubkey[crypto_sign_ed25519_PUBLICKEYBYTES];
};

static void
asignify_alloc_pkey_fields(struct asignify_pubkey *pk)
{
	pk->data = xmalloc(pk->data_len);
	pk->id = xmalloc(pk->id_len);
}

static bool
asignify_pubkey_try_obsd(const char *buf, size_t buflen,
	struct asignify_pubkey **pk)
{
	struct obsd_pubkey opk;
	struct asignify_pubkey *res;

	if (buflen >= sizeof(OBSD_COMMENTHDR) - 1 &&
			memcmp(buf, OBSD_COMMENTHDR, sizeof(OBSD_COMMENTHDR) - 1) == 0) {
		/* Skip comments */
		return (true);
	}

	if (b64_pton(buf, (unsigned char *)&opk, sizeof(opk)) == sizeof(opk)) {
		if (memcmp(opk.pkalg, OBSD_PKALG, sizeof(opk.pkalg)) == 0) {
			res = xmalloc(sizeof(*res));
			/* OpenBSD version code */
			res->version = 0;
			res->data_len = sizeof(opk.pubkey);
			res->id_len = sizeof(opk.keynum);
			asignify_alloc_pkey_fields(res);
			memcpy(res->data, opk.pubkey, res->data_len);
			memcpy(res->id, opk.keynum, res->id_len);

			*pk = res;
		}
	}

	/*
	 * We stop processing on the first non-comment line. If we have a key,
	 * then we set *pk to some openbsd key, otherwise this variable is not
	 * touched
	 */
	return (false);
}

/*
 * Native format is:
 * <PUBKEY_MAGIC>:<version>:<id>:<pkey>
 */
static struct asignify_pubkey*
asignify_pubkey_load_native(const char *buf, size_t buflen)
{
	char *errstr;
	const char *p = buf;
	unsigned int version;
	size_t remain = buflen, blen;
	struct asignify_pubkey *res = NULL;

	/* Skip PUBKEY_MAGIC and goto version */
	p += sizeof(PUBKEY_MAGIC) - 1;
	remain -= sizeof(PUBKEY_MAGIC) - 1;

	version = strtoul(p, &errstr, 10);
	if (errstr == NULL || *errstr != ':'
			|| version == 0 || version > PUBKEY_VER_MAX) {
		return (NULL);
	}

	if (version == 1) {
		res = xmalloc(sizeof(*res));
		res->version = 1;
		res->data_len = PUBKEY_ID_LEN;
		res->id_len = PUBKEY_KEY_LEN;
		asignify_alloc_pkey_fields(res);

		/* Read ID */
		blen = b64_pton_stop(p, res->id, res->id_len, ":");
		if (blen != res->id_len || (p = strchr(p, ':')) == NULL) {
			asignify_pubkey_free(res);
			return (NULL);
		}

		p ++;

		/* Read key */
		blen = b64_pton_stop(p, res->data, res->data_len, "");
		if (blen != res->data_len) {
			asignify_pubkey_free(res);
			return (NULL);
		}
	}

	return (res);
}

struct asignify_pubkey*
asignify_pubkey_load(FILE *f)
{
	struct asignify_pubkey *res = NULL;
	char *buf = NULL;
	size_t buflen = 0;
	bool first = true;

	if (f == NULL) {
		abort();
	}

	while (getline(&buf, &buflen, f) != -1) {
		if (first && buflen > sizeof(PUBKEY_MAGIC)) {
			first = false;

			/* Check for asignify pubkey */
			if (memcmp(buf, PUBKEY_MAGIC, sizeof(PUBKEY_MAGIC) - 1) == 0) {
				res = asignify_pubkey_load_native(buf, buflen);
				break;
			}
			else {
				/* We can have either openbsd pubkey or some garbadge */
				if (!asignify_pubkey_try_obsd(buf, buflen, &res)) {
					break;
				}
			}
		}
		if (!asignify_pubkey_try_obsd(buf, buflen, &res)) {
			break;
		}
	}

	return (res);
}

bool
asignify_pubkey_check_signature(struct asignify_pubkey *pk,
	struct asignify_signature *sig, const unsigned char *data, size_t dlen)
{
	if (pk == NULL || sig == NULL) {
		return (false);
	}

	/* Check sanity */
	if (pk->version != sig->version ||
		pk->id_len != sig->id_len ||
		memcmp(pk->id, sig->id, sig->id_len) != 0) {
		return (false);
	}

	if (pk->version == 1) {
		/* ED25519 */

		/* XXX: implement detached sigs */
		uint8_t *sigbuf, *dummybuf;
		unsigned long long siglen, dummylen;

		siglen = sig->data_len + dlen;
		sigbuf = xmalloc(siglen);
		dummybuf = xmalloc(siglen);
		memcpy(sigbuf, sig->data, sig->data_len);
		memcpy(sigbuf + sig->data_len, data, dlen);

		if (crypto_sign_ed25519_open(dummybuf, &dummylen, sigbuf, siglen,
			pk->data)) {
			return (true);
		}
	}

	return (false);
}

void
asignify_pubkey_free(struct asignify_pubkey *pk)
{
	if (pk) {
		free(pk->data);
		free(pk->id);
		pk->data = NULL;
		pk->id = NULL;
		free(pk);
	}
}