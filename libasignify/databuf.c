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
#include <errno.h>
#include <ctype.h>

#ifdef HAVE_MLOCK
#include <sys/mman.h>
#endif

#include "asignify.h"
#include "asignify_internal.h"
#include "blake2.h"
#include "tweetnacl.h"
#include "kvec.h"

#define SSH_PRIVKEY_START "-----BEGIN OPENSSH PRIVATE KEY-----"
#define SSH_PRIVKEY_END "-----END OPENSSH PRIVATE KEY-----"
#define SSH_PRIVKEY_MAGIC "openssh-key-v1"

enum asignify_privkey_field {
	PRIVKEY_FIELD_STRING,
	PRIVKEY_FIELD_UINT,
	PRIVKEY_FIELD_HEX
};

struct asignify_privkey_parser {
	const char *field_name;
	enum asignify_privkey_field field_type;
	long struct_offset;
	unsigned int required_len;
};

/*
 * Keep sorted by field name
 */
const static struct asignify_privkey_parser parser_fields[] = {
	{
		.field_name = "checksum",
		.field_type = PRIVKEY_FIELD_HEX,
		.struct_offset = STRUCT_OFFSET(struct asignify_private_key, checksum),
		.required_len = BLAKE2B_OUTBYTES
	},
	{
		.field_name = "data",
		.field_type = PRIVKEY_FIELD_HEX,
		.struct_offset = STRUCT_OFFSET(struct asignify_private_key, encrypted_blob),
		.required_len = crypto_sign_SECRETKEYBYTES
	},
	{
		.field_name = "id",
		.field_type = PRIVKEY_FIELD_HEX,
		.struct_offset = STRUCT_OFFSET(struct asignify_private_key, id),
		.required_len = KEY_ID_LEN
	},
	{
		.field_name = "kdf",
		.field_type = PRIVKEY_FIELD_STRING,
		.struct_offset = STRUCT_OFFSET(struct asignify_private_key, pbkdf_alg),
		.required_len = 0
	},
	{
		.field_name = "rounds",
		.field_type = PRIVKEY_FIELD_UINT,
		.struct_offset = STRUCT_OFFSET(struct asignify_private_key, rounds)
	},
	{
		.field_name = "salt",
		.field_type = PRIVKEY_FIELD_HEX,
		.struct_offset = STRUCT_OFFSET(struct asignify_private_key, salt),
		.required_len = SALT_LEN
	},
	{
		.field_name = "version",
		.field_type = PRIVKEY_FIELD_UINT,
		.struct_offset = STRUCT_OFFSET(struct asignify_private_key, version),
		.required_len = 0
	}
};

void
asignify_public_data_free(struct asignify_public_data *d)
{
	if (d) {
		free(d->data);
		free(d->id);
		free(d->aux);
		d->data = NULL;
		d->id = NULL;
		d->aux = 0;
		free(d);
	}
}

void
asignify_alloc_public_data_fields(struct asignify_public_data *pk)
{
	pk->data = xmalloc(pk->data_len);

	if (pk->id_len > 0) {
		pk->id = xmalloc(pk->id_len);
	}
	if (pk->aux_len > 0) {
		pk->aux = xmalloc(pk->aux_len);
	}
}

/*
 * Native format is:
 * <PUBKEY_MAGIC>:<version>:<id>:<pkey>
 */
struct asignify_public_data*
asignify_public_data_load(const char *buf, size_t buflen, const char *magic,
	size_t magiclen, unsigned int ver_min, unsigned int ver_max,
	unsigned int id_len, unsigned int data_len)
{
	char *errstr;
	const char *p = buf;
	unsigned int version;
	size_t blen;
	struct asignify_public_data *res = NULL;

	if (buflen <= magiclen || memcmp (buf, magic, magiclen) != 0) {
		return (NULL);
	}

	p += magiclen;

	version = strtoul(p, &errstr, 10);
	if (errstr == NULL || *errstr != ':'
			|| version < ver_min || version > ver_max) {
		return (NULL);
	}

	res = xmalloc0(sizeof(*res));
	res->version = version;
	res->data_len = data_len;
	res->id_len = id_len;
	asignify_alloc_public_data_fields(res);

	/* Read ID */
	p = errstr + 1;
	blen = b64_pton_stop(p, res->id, res->id_len, ":");
	if (blen != res->id_len || (p = strchr(p, ':')) == NULL) {
		asignify_public_data_free(res);
		return (NULL);
	}

	p ++;

	/* Read data */
	blen = b64_pton_stop(p, res->data, res->data_len, ":");
	if (blen != res->data_len) {
		asignify_public_data_free(res);
		return (NULL);
	}

	if ((p = strchr(p, ':')) == NULL) {
		return (res);
	}

	/* We have some aux data for this line */
	p ++;
	res->aux_len = strcspn(p, "\n\r");
	if (res->aux_len > 0) {
		res->aux = xmalloc(res->aux_len + 1);
		memcpy(res->aux, p, res->aux_len);
		res->aux[res->aux_len] = '\0';
	}

	return (res);
}

struct field_search_key {
	const char *begin;
	size_t len;
};

static int
asignify_parser_fields_cmp(const void *k, const void *st)
{
	const struct asignify_privkey_parser *p =
					(const struct asignify_privkey_parser *)st;
	struct field_search_key *key = (struct field_search_key *)k;

	return (strncmp(key->begin, p->field_name, key->len));
}

static void
asignify_privkey_cleanup(struct asignify_private_key *privk)
{
	if (privk == NULL) {
		return;
	}

	free(privk->checksum);
	if (privk->encrypted_blob) {
		explicit_memzero(privk->encrypted_blob, crypto_sign_SECRETKEYBYTES);
	}
	free(privk->encrypted_blob);
	free(privk->id);
	free(privk->pbkdf_alg);
	free(privk->salt);
	explicit_memzero(privk, sizeof(*privk));
}

static bool
asignify_private_data_parse_value(const char *val, size_t len,
	const struct asignify_privkey_parser *parser,
	struct asignify_private_key *privk)
{
	unsigned char **desth;
	char **dests;
	unsigned int *destui;

	switch(parser->field_type) {
	case PRIVKEY_FIELD_STRING:
		dests = STRUCT_MEMBER_PTR(char *, privk, parser->struct_offset);
		*dests = xmalloc(len + 1);
		memcpy(*dests, val, len);
		**dests = '\0';
		break;
	case PRIVKEY_FIELD_HEX:
		if (len / 2 != parser->required_len) {
			return (false);
		}

		desth = STRUCT_MEMBER_PTR(unsigned char *, privk, parser->struct_offset);
		*desth = xmalloc(len / 2);
		if (hex2bin(*desth, len / 2, val, len, NULL, NULL) == -1) {
			free(*desth);
			*desth = NULL;
			return (false);
		}
		break;
	case PRIVKEY_FIELD_UINT:
		destui = STRUCT_MEMBER_PTR(unsigned int, privk, parser->struct_offset);
		errno = 0;
		*destui = strtoul(val, NULL, 10);
		if (errno != 0) {
			return (false);
		}
		break;
	}

	return (true);
}

static bool
asignify_private_data_parse_line(const char *buf, size_t buflen,
	struct asignify_private_key *privk)
{
	const unsigned char *p, *end, *c;
	enum {
		PARSE_NAME = 0,
		PARSE_SEMICOLON,
		PARSE_VALUE,
		PARSE_SPACES,
		PARSE_ERROR
	} state = 0, next_state = 0;
	const struct asignify_privkey_parser *parser = NULL;
	struct field_search_key k;

	p = (unsigned char *)buf;
	end = p + buflen;
	c = p;

	while (p < end) {
		switch (state) {
		case PARSE_NAME:
			if (*p == ':') {
				if (p - c > 0) {
					k.begin = (const char *)c;
					k.len = p - c;
					parser = bsearch(&k, parser_fields,
						sizeof(parser_fields) / sizeof(parser_fields[0]),
						sizeof(parser_fields[0]), asignify_parser_fields_cmp);

					if (parser == NULL) {
						state = PARSE_ERROR;
					}
					else {
						state = PARSE_SEMICOLON;
					}
				}
				else {
					state = PARSE_ERROR;
				}
			}
			else if (!isgraph(*p)) {
				state = PARSE_ERROR;
			}
			else {
				p ++;
			}
			break;
		case PARSE_SEMICOLON:
			if (*p == ':') {
				p ++;
				state = PARSE_SPACES;
				next_state = PARSE_VALUE;
			}
			else {
				state = PARSE_ERROR;
			}
			break;
		case PARSE_VALUE:
			if (parser == NULL) {
				state = PARSE_ERROR;
			}
			else if (*p == '\n') {
				if (!asignify_private_data_parse_value((const char *)c, p - c,
						parser, privk)) {
					state = PARSE_ERROR;
				}
				else {
					state = PARSE_SPACES;
					next_state = PARSE_NAME;
				}
				parser = NULL;
			}
			else if (parser->field_type == PRIVKEY_FIELD_UINT && !isdigit(*p)) {
				state = PARSE_ERROR;
			}
			else if (parser->field_type == PRIVKEY_FIELD_HEX && !isxdigit(*p)) {
				state = PARSE_ERROR;
			}
			else {
				p ++;
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
		case PARSE_ERROR:
			return (false);
		}
	}

	return (state == PARSE_SPACES);
}

static bool
asignify_private_key_is_sane(struct asignify_private_key *privk)
{
	if (!privk->pbkdf_alg || strcmp(privk->pbkdf_alg, PBKDF_ALG) != 0) {
		/* Unencrypted key */
		return (privk->version == 1 && privk->encrypted_blob != NULL);
	}

	if (privk->rounds < PBKDF_MINROUNDS) {
		return (false);
	}

	if (privk->salt == NULL || privk->version != 1) {
		return (false);
	}

	return (privk->encrypted_blob != NULL && privk->checksum != NULL);
}

static void
asignify_pkey_to_private_data(struct asignify_private_key *privk,
		struct asignify_private_data *priv)
{
	priv->version = privk->version;
	priv->data = xmalloc(crypto_sign_SECRETKEYBYTES);
	priv->data_len = crypto_sign_SECRETKEYBYTES;
	memcpy(priv->data, privk->encrypted_blob, crypto_sign_SECRETKEYBYTES);
	explicit_memzero(privk->encrypted_blob, crypto_sign_SECRETKEYBYTES);

	if (privk->id != NULL) {
		priv->id = xmalloc(KEY_ID_LEN);
		priv->id_len = KEY_ID_LEN;
		memcpy(priv->id, privk->id, KEY_ID_LEN);
	}
}

struct asignify_private_data*
asignify_private_data_unpack_key(struct asignify_private_key *privk, int *error,
	asignify_password_cb password_cb, void *d)
{
	unsigned char canary[10];
	char password[1024];
	struct asignify_private_data *priv;
	unsigned char xorkey[crypto_sign_SECRETKEYBYTES];
	unsigned char res_checksum[BLAKE2B_OUTBYTES];
	int r;
	bool ok = false;

	priv = xmalloc(sizeof(*priv));
	if (privk->pbkdf_alg == NULL) {
		goto done;
	}

	/* We need to derive key */
	if (password_cb == NULL) {
		goto cleanup;
	}

	/* Some buffer overflow protection */
	randombytes(canary, sizeof(canary));
	memcpy(password + sizeof(password) - sizeof(canary), canary,
			sizeof(canary));
	r = password_cb(password, sizeof(password) - sizeof(canary), d);
	if (r <= 0 || r > sizeof(password) - sizeof(canary) ||
		memcmp(password + sizeof(password) - sizeof(canary), canary, sizeof(canary)) != 0) {
		goto cleanup;
	}

	if (pkcs5_pbkdf2(password, r, privk->salt, SALT_LEN, xorkey, sizeof(xorkey),
		privk->rounds) == -1) {
		goto cleanup;
	}

	explicit_memzero(password, sizeof(password));

	for (r = 0; r < sizeof(xorkey); r ++) {
		privk->encrypted_blob[r] ^= xorkey[r];
	}

	explicit_memzero(xorkey, sizeof(xorkey));
	blake2b(res_checksum, privk->encrypted_blob, NULL, BLAKE2B_OUTBYTES,
		sizeof(xorkey), 0);

	if (memcmp(res_checksum, privk->checksum, sizeof(res_checksum)) != 0) {
		if (error != NULL) {
			*error = ASIGNIFY_ERROR_PASSWORD;
		}

		goto cleanup;
	}

done:
	ok = true;
	asignify_pkey_to_private_data(privk, priv);

cleanup:
	explicit_memzero(password, sizeof(password));
	asignify_privkey_cleanup(privk);
	if (!ok) {
		free(priv);
		priv = NULL;
	}
	return (priv);
}

struct asignify_private_data*
asignify_private_data_load(FILE *f, int *error,
	asignify_password_cb password_cb, void *d)
{
	char *buf = NULL;
	size_t buflen = 0;
	struct asignify_private_data *pkeyd;
	struct asignify_private_key privk;
	bool first = true;
	ssize_t r;

	memset(&privk, 0, sizeof(privk));
	pkeyd = NULL;

	while ((r = getline(&buf, &buflen, f)) != -1) {
		if (first) {
			/* Check magic */
			if (memcmp(buf, PRIVKEY_MAGIC, sizeof(PRIVKEY_MAGIC) - 1) != 0) {
				return (NULL);
			}

			first = false;
			continue;
		}

		if (!asignify_private_data_parse_line(buf, r, &privk)) {
			goto cleanup;
		}
	}

	if (!asignify_private_key_is_sane(&privk)) {
		goto cleanup;
	}

	pkeyd = asignify_private_data_unpack_key(&privk, error, password_cb, d);
cleanup:
	asignify_privkey_cleanup(&privk);
	return (pkeyd);
}

void
asignify_private_data_free(struct asignify_private_data *d)
{
	if (d == NULL) {
		return;
	}

	free(d->id);
	d->id = NULL;
	explicit_memzero(d->data, d->data_len);
#ifdef HAVE_MLOCK
	munlock(d->data, d->data_len);
#endif
	free(d->data);
	free(d);
}

const unsigned char *
asignify_ssh_read_string(const unsigned char *buf, unsigned int *str_len,
		unsigned int remain, unsigned char const **npos)
{
	unsigned int token_len;
	unsigned const char *p = buf;

	if (buf == NULL || remain < 4) {
		return (NULL);
	}

	/* Decode from little endian */
	token_len = (p[0] << 3 | p[1] << 2 | p[2] << 1 | p[3]);

	if (remain < token_len + 4) {
		return (NULL);
	}

	p += 4;
	if (npos != NULL) {
		*npos = p + token_len;
	}

	if (str_len != NULL) {
		*str_len = token_len;
	}

	return (p);
}

#define SAFE_MEMCMP(in, pat, inlen) ((inlen) >= sizeof(pat) && memcmp(in, pat, sizeof(pat)) == 0)
#define SAFE_STRCMP(in, pat, inlen) ((inlen) >= sizeof(pat) - 1 && memcmp(in, pat, sizeof(pat) - 1) == 0)

struct asignify_private_data*
asignify_ssh_privkey_load(FILE *f, int *error)
{
	char *line = NULL;
	size_t buflen = 0;
	int r;
	kvec_t(char) data;
	unsigned char *decoded,
		pk[crypto_sign_PUBLICKEYBYTES], sk[crypto_sign_SECRETKEYBYTES];
	const unsigned char *tok, *p;
	bool key_read = false;
	unsigned int tlen;
	struct asignify_private_data* res = NULL;

	if (f == NULL) {
		return (NULL);
	}

	if ((r = getline(&line, &buflen, f)) <= 0) {
		return (NULL);
	}

	if (r < sizeof(SSH_PRIVKEY_START) - 1 || memcmp(line, SSH_PRIVKEY_START,
			sizeof(SSH_PRIVKEY_START) - 1) != 0) {
		if (error) {
			*error = ASIGNIFY_ERROR_FORMAT;
		}

		return (NULL);
	}

	kv_init(data);

	while ((r = getline(&line, &buflen, f)) > 0) {
		if (r >= sizeof(SSH_PRIVKEY_END) - 1 && memcmp(line, SSH_PRIVKEY_END,
				sizeof(SSH_PRIVKEY_END) - 1) == 0) {
			key_read = true;
			break;
		}

		kv_push_a(char, data, line, r);
	}

	free(line);

	if (!key_read) {
		kv_destroy(data);

		if (error) {
			*error = ASIGNIFY_ERROR_FORMAT;
		}

		return (NULL);
	}

	decoded = xmalloc(kv_size(data));
	r = b64_pton(data.a, decoded, kv_size(data));
	explicit_memzero(data.a, kv_size(data));

	if (r == -1) {
		if (error) {
			*error = ASIGNIFY_ERROR_FORMAT;
		}

		goto cleanup;
	}

	p = decoded;
	/* openssh magic is a null terminated string */
	if (!SAFE_MEMCMP(p, SSH_PRIVKEY_MAGIC, r)) {
		if (error) {
			*error = ASIGNIFY_ERROR_FORMAT;
		}

		goto cleanup;
	}

	p += sizeof(SSH_PRIVKEY_MAGIC);
	r -= sizeof(SSH_PRIVKEY_MAGIC);

	/* KDF and encryption alg should be "none" */
	tok = asignify_ssh_read_string(p, &tlen, r, &p);
	if (tok == NULL || !SAFE_STRCMP(tok, "none", tlen)) {
		if (error) {
			*error = ASIGNIFY_ERROR_FORMAT;
		}

		goto cleanup;
	}
	r -= tlen + 4;
	tok = asignify_ssh_read_string(p, &tlen, r, &p);
	if (tok == NULL || !SAFE_STRCMP(tok, "none", tlen)) {
		if (error) {
			*error = ASIGNIFY_ERROR_FORMAT;
		}

		goto cleanup;
	}
	r -= tlen + 4;

	/* Now we have 3 uint32_t that we do not care about */
	if (r <= sizeof(uint32_t) * 3) {
		if (error) {
			*error = ASIGNIFY_ERROR_FORMAT;
		}

		goto cleanup;
	}

	p += sizeof(uint32_t) * 3;
	r -= sizeof(uint32_t) * 3;

	/*
	 * Read pubkey and privkey parts here and reconstruct the full
	 * ed25519 privkey
	 */
	tok = asignify_ssh_read_string(p, &tlen, r, &p);
	if (tok == NULL || !SAFE_STRCMP(tok, "ssh-ed25519", tlen)) {
		if (error) {
			*error = ASIGNIFY_ERROR_FORMAT;
		}

		goto cleanup;
	}
	r -= tlen + 4;

	tok = asignify_ssh_read_string(p, &tlen, r, &p);
	if (tok == NULL || tlen != sizeof(pk)) {
		if (error) {
			*error = ASIGNIFY_ERROR_FORMAT;
		}

		goto cleanup;
	}
	r -= tlen + 4;
	memcpy(pk, tok, tlen);

	/*
	 * After public key we have an ssh blob with the following structure:
	 * <total_length> 4 bytes
	 * <uint32>
	 * <uint32>
	 * <length_string> = "ssh-ed25519"
	 * <length_blob> = ssh *public* key part
	 * <length_blob> = ssh private key part
	 *
	 * We skip 12 bytes as we do not care about their sanity as it is meaningful
	 * merely for encrypted privkeys
	 *
	 * We also skip the whole public key as we have read it already
	 */
	if (r <= sizeof(uint32_t) * 3) {
		if (error) {
			*error = ASIGNIFY_ERROR_FORMAT;
		}

		goto cleanup;
	}

	p += sizeof(uint32_t) * 3;
	r -= sizeof(uint32_t) * 3;

	tok = asignify_ssh_read_string(p, &tlen, r, &p);
	if (tok == NULL || !SAFE_STRCMP(tok, "ssh-ed25519", tlen)) {
		if (error) {
			*error = ASIGNIFY_ERROR_FORMAT;
		}

		goto cleanup;
	}
	r -= tlen + 4;

	/* Pubkey part, thank you, openssh developers */
	tok = asignify_ssh_read_string(p, &tlen, r, &p);
	if (tok == NULL || tlen != sizeof(pk)) {
		if (error) {
			*error = ASIGNIFY_ERROR_FORMAT;
		}

		goto cleanup;
	}
	r -= tlen + 4;

	tok = asignify_ssh_read_string(p, &tlen, r, &p);
	if (tok == NULL || tlen != sizeof(sk)) {
		if (error) {
			*error = ASIGNIFY_ERROR_FORMAT;
		}

		goto cleanup;
	}
	r -= tlen + 4;

	memcpy(sk, tok, tlen);

	res = xmalloc0(sizeof(*res));
	res->id_len = 0;
	res->version = 1;
	res->data_len = crypto_sign_SECRETKEYBYTES;
	res->data = xmalloc(res->data_len);
	memcpy(res->data, sk, res->data_len);

	if (error) {
		*error = ASIGNIFY_ERROR_OK;
	}

cleanup:
	explicit_memzero(decoded, r);
	explicit_memzero(sk, sizeof(sk));
	free(decoded);

	return (res);
}
