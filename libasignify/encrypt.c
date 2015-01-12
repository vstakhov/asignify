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
#include "chacha.h"
#include "asignify.h"
#include "asignify_internal.h"
#include "tweetnacl.h"

#define ENCRYPTED_MAGIC "asignify-encrypted"
#define ENCRYPTED_SIGNATURE_MAGIC "chacha20"
#define CHACHA_ROUNDS 20

struct asignify_encrypt_ctx {
	struct asignify_private_data *privk;
	struct asignify_public_data *pubk;
	const char *error;
};

asignify_encrypt_t*
asignify_encrypt_init(void)
{
	asignify_encrypt_t *nctx;

	nctx = xmalloc0(sizeof(*nctx));

	return (nctx);
}

bool
asignify_encrypt_load_privkey(asignify_encrypt_t *ctx, const char *privf,
	asignify_password_cb password_cb, void *d)
{
	FILE *f;
	bool ret = false;
	int error = ASIGNIFY_ERROR_FORMAT;

	if (ctx == NULL || privf == NULL) {
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
	}

	return (ret);
}

bool
asignify_encrypt_load_pubkey(asignify_encrypt_t *ctx, const char *pubf)
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
		ctx->pubk = asignify_pubkey_load(f);
		if (ctx->pubk == NULL) {
			ctx->error = xerr_string(ASIGNIFY_ERROR_FORMAT);
		}
		else {
			ret = true;
		}
	}

	return (ret);
}

#define ENCRYPTED_PAYLOAD_LEN crypto_box_NONCEBYTES + crypto_box_ZEROBYTES + 8 + 32

bool
asignify_encrypt_crypt_file(asignify_encrypt_t *ctx, unsigned int version,
	const char *inf, const char *outf)
{
	FILE *in, *out;
	int out_fd, r;
	off_t sig_pos = 0;
	struct stat st;
	unsigned char curvepk[crypto_box_PUBLICKEYBYTES],
		curvesk[crypto_box_SECRETKEYBYTES],
		session_key[ENCRYPTED_PAYLOAD_LEN], *p,
		dig[BLAKE2B_OUTBYTES + crypto_sign_BYTES + sizeof(ENCRYPTED_SIGNATURE_MAGIC) - 1];
	char *b64;
	blake2b_state sh;
	chacha_state enc_st;
	bool ret = false;
	unsigned long long outlen;
#if BUFSIZ >= 2048
	unsigned char buf[BUFSIZ], outbuf[BUFSIZ];
#else
	/* BUFSIZ is insanely small */
	unsigned char buf[4096], outbuf[4096];
#endif

	if (ctx == NULL || ctx->privk == NULL || ctx->pubk == NULL || version != 1) {
		ctx->error = xerr_string(ASIGNIFY_ERROR_MISUSE);
		return (false);
	}

	/* Ensure that we are not trying to encrypt using the related keypair */
	if (ctx->pubk->id_len == ctx->privk->id_len && ctx->privk->id_len > 0) {
		if (memcmp(ctx->pubk->id, ctx->privk->id, ctx->privk->id_len) == 0) {
			ctx->error = xerr_string(ASIGNIFY_ERROR_WRONG_KEYPAIR);
			return (false);
		}

	}

	in = xfopen(inf, "r");

	if (in == NULL) {
		ctx->error = xerr_string(ASIGNIFY_ERROR_FILE);
		return (false);
	}

	out = xfopen(outf, "w");
	if (out == NULL) {
		ctx->error = xerr_string(ASIGNIFY_ERROR_FILE);
		fclose(in);
		return (false);
	}

	/* Since we need to seek, we must ensure that the file is a normal file */
	out_fd = fileno(out);
	if (fstat(out_fd, &st) == -1 || !S_ISREG(st.st_mode)) {
		fclose(out);
		ctx->error = xerr_string(ASIGNIFY_ERROR_FILE);

		return (false);
	}

	crypto_sign_ed25519_sk_to_curve25519(curvesk, ctx->privk->data);
	crypto_sign_ed25519_pk_to_curve25519(curvepk, ctx->pubk->data);

	/* Generate session key */
	p = session_key;
	randombytes(p, crypto_box_NONCEBYTES);
	p += crypto_box_NONCEBYTES;
	memset(p, 0, crypto_box_ZEROBYTES);
	p += crypto_box_ZEROBYTES;
	randombytes(p, 8);
	p += 8;
	randombytes(p, 32);

	chacha_init(&enc_st, (chacha_key *)p, (chacha_iv *)(p - 8), CHACHA_ROUNDS);

	/* Encrypt now the session key */
	crypto_box(session_key + crypto_box_NONCEBYTES, /* begin of cryptobox */
		session_key + crypto_box_NONCEBYTES + crypto_box_ZEROBYTES, /* begin of decrypted session key */
		crypto_stream_NONCEBYTES + crypto_stream_KEYBYTES, /* session key + session nonce */
		session_key, /* session nonce */
		curvepk, curvesk);

	/* Write key header */
	memset(dig, 0, crypto_sign_BYTES);
	b64 = xmalloc(ENCRYPTED_PAYLOAD_LEN * 2);
	b64_ntop(session_key, ENCRYPTED_PAYLOAD_LEN, b64, ENCRYPTED_PAYLOAD_LEN * 2);
	fprintf(out, "%s:%d:%s:", ENCRYPTED_MAGIC, version, b64);

	/* Write fake signature */
	sig_pos = ftell(out);
	b64_ntop(dig, crypto_sign_BYTES, b64, ENCRYPTED_PAYLOAD_LEN * 2);
	fprintf(out, "%s\n", b64);

	blake2b_init(&sh, BLAKE2B_OUTBYTES);

	while((r = fread(buf, 1, sizeof(buf), in)) > 0) {
		blake2b_update(&sh, buf, r);
		chacha_update(&enc_st, buf, outbuf, r);

		if (fwrite(outbuf, 1, r, out) != r) {
			ctx->error = xerr_string(ASIGNIFY_ERROR_FILE);

			goto cleanup;
		}
	}

	if ((r = chacha_final(&enc_st, outbuf)) > 0) {
		if (fwrite(outbuf, 1, r, out) != r) {
			ctx->error = xerr_string(ASIGNIFY_ERROR_FILE);

			goto cleanup;
		}
	}

	/* Now we need to calculate signature */
	p = dig;
	memset(p, 0, sizeof(crypto_sign_BYTES));
	p += crypto_sign_BYTES;
	memcpy(p, ENCRYPTED_SIGNATURE_MAGIC, sizeof(ENCRYPTED_SIGNATURE_MAGIC) - 1);
	p += sizeof(ENCRYPTED_SIGNATURE_MAGIC) - 1;
	blake2b_final(&sh, p, BLAKE2B_OUTBYTES);

	outlen = sizeof(dig);
	crypto_sign(dig, &outlen,
		dig + crypto_sign_BYTES,
		sizeof(dig) - crypto_sign_BYTES,
		ctx->privk->data);

	fflush(out);
	/* Now rewind to the signature place and overwrite the fake signature */
	if (fseek(out, sig_pos, SEEK_SET) != 0) {
		ctx->error = xerr_string(ASIGNIFY_ERROR_FILE);

		goto cleanup;
	}

	b64_ntop(dig, crypto_sign_BYTES, b64, ENCRYPTED_PAYLOAD_LEN * 2);
	fprintf(out, "%s", b64);

	fclose(out);
	fclose(in);

	ret = true;

cleanup:
	explicit_memzero(&enc_st, sizeof(enc_st));
	return (ret);
}
