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

#include <assert.h>
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
#define PUBKEY_KEY_LEN crypto_sign_ed25519_PUBLICKEYBYTES

#define SSH_KEY_MAGIC "ssh-ed25519"

struct obsd_pubkey {
	uint8_t pkalg[2];
	uint8_t keynum[8];
	uint8_t pubkey[crypto_sign_ed25519_PUBLICKEYBYTES];
};

static bool
asignify_pubkey_try_obsd(const char *buf, size_t buflen,
	struct asignify_public_data **pk)
{
	struct obsd_pubkey opk;
	struct asignify_public_data *res;

	if (buflen >= sizeof(OBSD_COMMENTHDR) - 1 &&
			memcmp(buf, OBSD_COMMENTHDR, sizeof(OBSD_COMMENTHDR) - 1) == 0) {
		/* Skip comments */
		return (true);
	}

	if (b64_pton(buf, (unsigned char *)&opk, sizeof(opk)) != sizeof(opk)) {
		return (false);
	}
	if (memcmp(opk.pkalg, OBSD_PKALG, sizeof(opk.pkalg)) != 0) {
		return (false);
	}

	res = xmalloc0(sizeof(*res));
	/* OpenBSD version code */
	res->version = 0;
	res->data_len = sizeof(opk.pubkey);
	res->id_len = sizeof(opk.keynum);
	asignify_alloc_public_data_fields(res);
	memcpy(res->data, opk.pubkey, res->data_len);
	memcpy(res->id, opk.keynum, res->id_len);

	*pk = res;

	/*
	 * We stop processing on the first non-comment line. If we have a key,
	 * then we set *pk to some openbsd key, otherwise this variable is not
	 * touched
	 */
	return (false);
}

static bool
asignify_pubkey_try_ssh(const char *buf, size_t buflen,
	struct asignify_public_data **pk)
{
	unsigned char pkbuf[crypto_sign_ed25519_PUBLICKEYBYTES * 2];
	const unsigned char *tok, *bpos;
	const char *p = buf;
	unsigned int tlen;
	int remain;
	struct asignify_public_data *res;

	p = buf + sizeof(SSH_KEY_MAGIC) - 1;

	if (*p != ' ') {
		return (false);
	}

	p ++;

	if ((remain = b64_pton_stop(p, pkbuf, sizeof(pkbuf), " ")) <= 0) {
		return (false);
	}

	bpos = pkbuf;
	if ((tok = asignify_ssh_read_string(bpos, &tlen, remain, &bpos)) == NULL) {
		return (false);
	}

	/* First of all the algorithm name is encoded */
	if (tlen != sizeof(SSH_KEY_MAGIC) - 1 || memcmp(tok, SSH_KEY_MAGIC,
			sizeof(SSH_KEY_MAGIC) - 1) != 0) {
		/* Wrong blob */
		return (false);
	}

	remain -= tlen + 4;

	if ((tok = asignify_ssh_read_string(bpos, &tlen, remain, &bpos)) == NULL) {
		return (false);
	}

	if (tlen != crypto_sign_ed25519_PUBLICKEYBYTES) {
		return (true);
	}

	res = xmalloc(sizeof(*res));
	res->version = 1;
	res->data_len = crypto_sign_ed25519_PUBLICKEYBYTES;
	res->id_len = 0;
	asignify_alloc_public_data_fields(res);
	memcpy(res->data, tok, res->data_len);

	*pk = res;

	return (true);
}

struct asignify_public_data*
asignify_pubkey_load(FILE *f)
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
		if (r > sizeof(PUBKEY_MAGIC)) {
			if (first && memcmp(buf, PUBKEY_MAGIC, sizeof(PUBKEY_MAGIC) - 1) == 0) {
				res = asignify_public_data_load(buf, r,
						PUBKEY_MAGIC, sizeof(PUBKEY_MAGIC) - 1,
						PUBKEY_VER_MAX, PUBKEY_VER_MAX,
						KEY_ID_LEN, PUBKEY_KEY_LEN);
				/* XXX: should we stop after the first public key read? */
				break;
			}
		}
		if (r > sizeof(SSH_KEY_MAGIC) &&
				memcmp(buf, SSH_KEY_MAGIC, sizeof (SSH_KEY_MAGIC) - 1) == 0) {
			/* Try ssh pubkey */
			if (asignify_pubkey_try_ssh(buf, r, &res)) {
				/* XXX: need to read all SSH keys */
				break;
			}
		}
		else if (!asignify_pubkey_try_obsd(buf, r, &res)) {
			break;
		}

		first = false;
	}

	return (res);
}

bool
asignify_pubkey_check_signature(struct asignify_public_data *pk,
	struct asignify_public_data *sig, const unsigned char *data, size_t dlen)
{
	SHA2_CTX sh;
	unsigned char h[crypto_sign_HASHBYTES];

	if (pk == NULL || sig == NULL) {
		return (false);
	}

	/* Check sanity */
	if (pk->version != sig->version ||
		pk->id_len != sig->id_len ||
		(pk->id_len > 0 && memcmp(pk->id, sig->id, sig->id_len) != 0)) {
		return (false);
	}

	assert(pk->version == sig->version);

	switch (pk->version) {
	case 0:
		if (pk->data_len != crypto_sign_PUBLICKEYBYTES ||
				sig->data_len != crypto_sign_BYTES) {
			break;
		}

		SHA512Init(&sh);
		SHA512Update(&sh, sig->data, 32);
		SHA512Update(&sh, pk->data, 32);
		SHA512Update(&sh, data, dlen);
		SHA512Final(h, &sh);

		if (crypto_sign_ed25519_verify_detached(sig->data, h, pk->data) == 0) {
			return (true);
		}
		break;
	case 1:
		if (pk->data_len != crypto_sign_PUBLICKEYBYTES ||
				sig->data_len != crypto_sign_BYTES) {
			break;
		}

		/* ED25519 */
		SHA512Init(&sh);
		SHA512Update(&sh, sig->data, 32);
		SHA512Update(&sh, pk->data, 32);
		SHA512Update(&sh, (const uint8_t *)&sig->version,
							sizeof(sig->version));
		SHA512Update(&sh, data, dlen);
		SHA512Final(h, &sh);

		if (crypto_sign_ed25519_verify_detached(sig->data, h, pk->data) == 0) {
			return (true);
		}

		break;
	default:
		break;
	}

	return (false);
}

bool
asignify_pubkey_write(struct asignify_public_data *pk, FILE *f)
{
	char *b64data, *b64id;
	bool ret = false;

	if (pk == NULL || f == NULL) {
		return (false);
	}

	if (pk->version == 0) {
		/* XXX: support openbsd pubkeys format */
		return (false);
	}
	if (pk->version != 1) {
		/* Future formats . */
		return (false);
	}

	b64id = xmalloc(pk->id_len * 2);
	b64_ntop(pk->id, pk->id_len, b64id, pk->id_len * 2);
	b64data = xmalloc(pk->data_len * 2);
	b64_ntop(pk->data, pk->data_len, b64data, pk->data_len * 2);
	ret = (fprintf(f, "%s1:%s:%s\n", PUBKEY_MAGIC, b64id, b64data) > 0);
	free(b64id);
	free(b64data);

	return (ret);
}
