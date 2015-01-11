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
#include <errno.h>

#ifdef HAVE_MLOCK
#include <sys/mman.h>
#endif

#include "asignify.h"
#include "asignify_internal.h"
#include "blake2.h"
#include "tweetnacl.h"

static bool
asignify_encrypt_privkey(struct asignify_private_key *privk, unsigned int rounds,
		asignify_password_cb password_cb, void *d)
{
	unsigned char canary[10];
	unsigned char xorkey[crypto_sign_SECRETKEYBYTES];
	char password[1024];
	int r;

	privk->checksum = xmalloc(BLAKE2B_OUTBYTES);
	privk->salt = xmalloc(SALT_LEN);
	privk->rounds = rounds;
	privk->pbkdf_alg = PBKDF_ALG;
	randombytes(privk->salt, SALT_LEN);
	blake2b(privk->checksum, privk->encrypted_blob, NULL, BLAKE2B_OUTBYTES,
			crypto_sign_SECRETKEYBYTES, 0);

	randombytes(canary, sizeof(canary));
	memcpy(password + sizeof(password) - sizeof(canary), canary,
			sizeof(canary));
	r = password_cb(password, sizeof(password) - sizeof(canary), d);
	if (r <= 0 || r > sizeof(password) - sizeof(canary) ||
			memcmp(password + sizeof(password) - sizeof(canary), canary, sizeof(canary)) != 0) {
		return (false);
	}

	if (pkcs5_pbkdf2(password, r, privk->salt, SALT_LEN, xorkey, sizeof(xorkey),
			privk->rounds) == -1) {
		return (false);
	}

	explicit_memzero(password, sizeof(password));

	for (r = 0; r < sizeof(xorkey); r ++) {
		privk->encrypted_blob[r] ^= xorkey[r];
	}

	explicit_memzero(xorkey, sizeof(xorkey));

	return (true);
}

static bool
asignify_generate_v1(FILE *privf, FILE *pubf, unsigned int rounds,
		asignify_password_cb password_cb, void *d)
{

	struct asignify_private_key *privk;
	struct asignify_public_data *pubk;
	bool ret = true;

	if (privf == NULL || pubf == NULL ||
			(password_cb != NULL && rounds < PBKDF_MINROUNDS)) {
		return (false);
	}

	privk = xmalloc0(sizeof(*privk));
	pubk = xmalloc0(sizeof(*pubk));

	privk->version = 1;
	pubk->version = 1;
	privk->id = xmalloc(KEY_ID_LEN);
	pubk->id = xmalloc(KEY_ID_LEN);
	pubk->id_len = KEY_ID_LEN;
	randombytes(privk->id, KEY_ID_LEN);
	memcpy(pubk->id, privk->id, KEY_ID_LEN);

	privk->encrypted_blob = xmalloc(crypto_sign_SECRETKEYBYTES);
	pubk->data = xmalloc(crypto_sign_PUBLICKEYBYTES);
	pubk->data_len = crypto_sign_PUBLICKEYBYTES;
	crypto_sign_keypair(pubk->data, privk->encrypted_blob);

	if (password_cb != NULL) {
		if (!asignify_encrypt_privkey(privk, rounds, password_cb, d)) {
			goto cleanup;
		}
	}

	ret = asignify_pubkey_write(pubk, pubf);
	if (ret) {
		ret = asignify_privkey_write(privk, privf);
	}

cleanup:
	asignify_public_data_free(pubk);
	explicit_memzero(privk->encrypted_blob, crypto_sign_SECRETKEYBYTES);

	free(privk->salt);
	free(privk->checksum);
	free(privk->encrypted_blob);

	fclose(pubf);
	fclose(privf);

	return (ret);
}

#define HEX_OUT_PRIVK(privk, field, name, size, f) do {						\
		hexdata = xmalloc((size) * 2 + 1);									\
		if(bin2hex(hexdata, (size) * 2 + 1, privk->field, (size)) == NULL) { \
			abort();														\
		}																	\
		fprintf(f, "%s: %s\n", (name), hexdata);							\
		free(hexdata);														\
	} while (0)

bool
asignify_privkey_write(struct asignify_private_key *privk, FILE *f)
{
	char *hexdata;
	bool ret = false;

	if (privk == NULL || f == NULL) {
		return (false);
	}

	if (privk->version == 1) {
		fprintf(f, PRIVKEY_MAGIC "\n" "version: %u\n", privk->version);
		HEX_OUT_PRIVK(privk, encrypted_blob, "data", crypto_sign_SECRETKEYBYTES, f);

		if (privk->id) {
			HEX_OUT_PRIVK(privk, id, "id", KEY_ID_LEN, f);
		}

		/* Encrypted privkey */
		if (privk->pbkdf_alg != NULL) {
			fprintf(f, "kdf: %s\n", privk->pbkdf_alg);
			fprintf(f, "rounds: %u\n", privk->rounds);
			HEX_OUT_PRIVK(privk, salt, "salt", SALT_LEN, f);
			HEX_OUT_PRIVK(privk, checksum, "checksum", BLAKE2B_OUTBYTES, f);
		}
		ret = true;
	}

	return (ret);
}

bool
asignify_generate(const char *privkf, const char *pubkf, unsigned int version,
		unsigned int rounds, asignify_password_cb password_cb, void *d)
{
	FILE *privf, *pubf;


	if (version == 1) {
		privf = xfopen(privkf, "w");
		pubf = xfopen(pubkf, "w");

		if (!privf || !pubf) {
			return (false);
		}

		return (asignify_generate_v1(privf, pubf, rounds, password_cb, d));
	}

	return (false);
}

bool
asignify_privkey_from_ssh(const char *sshkf, const char *privkf,
		unsigned int version, unsigned int rounds,
		asignify_password_cb password_cb, void *d)
{
	FILE *privf, *sshf;
	struct asignify_private_data *privd = NULL;
	struct asignify_private_key privk;
	bool ret = false;

	if (version == 1) {
		sshf = xfopen(sshkf, "r");

		if (!sshf) {
			return (false);
		}

		privd = asignify_ssh_privkey_load(sshf, NULL);

		if (privd == NULL) {
			return (false);
		}

		privf = xfopen(privkf, "w");
		if (privf == NULL) {
			asignify_private_data_free(privd);
			return (false);
		}

		privk.encrypted_blob = privd->data;
		privk.version = version;
		privk.id = NULL;

		if (password_cb != NULL) {
			if (!asignify_encrypt_privkey(&privk, rounds, password_cb, d)) {
				asignify_private_data_free(privd);
				return (false);
			}
		}

		ret = asignify_privkey_write(&privk, privf);
	}

	asignify_private_data_free(privd);

	return (ret);
}
