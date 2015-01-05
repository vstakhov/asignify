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
#include "sha2.h"
#include "blake2.h"

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
				/* We can have either openbsd pubkey or some garbage */
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
	blake2b_state hs;
	SHA2_CTX sh;
	unsigned char h[crypto_sign_HASHBYTES];

	if (pk == NULL || sig == NULL) {
		return (false);
	}

	/* Check sanity */
	if (pk->version != sig->version ||
		pk->id_len != sig->id_len ||
		memcmp(pk->id, sig->id, sig->id_len) != 0) {
		return (false);
	}

	if (pk->version == sig->version) {
		switch (pk->version) {
		case 0:
			if (pk->data_len == crypto_sign_PUBLICKEYBYTES &&
					sig->data_len == crypto_sign_BYTES) {
				SHA512Init(&sh);
				SHA512Update(&sh, sig->data, 32);
				SHA512Update(&sh, pk->data, 32);
				SHA512Update(&sh, data, dlen);
				SHA512Final(h, &sh);

				if (crypto_sign_ed25519_verify_detached(sig->data, h, pk->data) == 0) {
					return (true);
				}
			}
			break;
		case 1:
			if (pk->data_len == crypto_sign_PUBLICKEYBYTES &&
					sig->data_len == crypto_sign_BYTES) {
				/* ED25519 */
				blake2b_init(&hs, crypto_sign_HASHBYTES);
				/* ed25519 nonce */
				blake2b_update(&hs, sig->data, 32);
				/* public key */
				blake2b_update(&hs, pk->data, pk->data_len);
				/* version to prevent versioning attacks */
				blake2b_update(&hs, (const uint8_t *)&sig->version,
					sizeof(sig->version));
				/* id of key */
				blake2b_update(&hs, pk->id, pk->id_len);
				/* data part */
				blake2b_update(&hs, data, dlen);
				blake2b_final(&hs, h, sizeof(h));

				if (crypto_sign_ed25519_verify_detached(sig->data, h, pk->data) == 0) {
					return (true);
				}
			}
			break;
		default:
			break;
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

bool
asignify_pubkey_write(struct asignify_pubkey *pk, FILE *f)
{
	char *b64data, *b64id;
	bool ret = false;

	if (pk == NULL || f == NULL) {
		return (false);
	}

	if (pk->version == 1) {
		b64id = xmalloc(pk->id_len * 2);
		b64_ntop(pk->id, pk->id_len, b64id, pk->id_len * 2);
		b64data = xmalloc(pk->data_len * 2);
		b64_ntop(pk->data, pk->data_len, b64data, pk->data_len * 2);
		ret = (fprintf(f, "%s:1:%s:%s\n", PUBKEY_MAGIC, b64id, b64data) > 0);
		free(b64id);
		free(b64data);
	}
	else if (pk->version == 0) {
		/* XXX: support openbsd pubkeys format */
	}

	return (ret);
}
