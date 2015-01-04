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
#define SIG_KEY_ID_LEN 8
#define SIG_LEN crypto_sign_ed25519_BYTES

struct obsd_signature {
	uint8_t sigalg[2];
	uint8_t keynum[8];
	uint8_t sig[crypto_sign_ed25519_BYTES];
};

static void
asignify_alloc_sig_fields(struct asignify_signature *sig)
{
	sig->data = xmalloc(sig->data_len);
	sig->id = xmalloc(sig->id_len);
}

static bool
asignify_sig_try_obsd(const char *buf, size_t buflen,
	struct asignify_signature **sig)
{
	struct obsd_signature osig;
	struct asignify_signature *res;

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
			res = xmalloc(sizeof(*res));
			/* OpenBSD version code */
			res->version = 0;
			res->data_len = sizeof(osig.sig);
			res->id_len = sizeof(osig.keynum);
			asignify_alloc_sig_fields(res);
			memcpy(res->data, osig.sig, res->data_len);
			memcpy(res->id, osig.keynum, res->id_len);

			*sig = res;
		}
	}

	return (false);
}

/*
 * Native format is:
 * <PUBKEY_MAGIC>:<version>:<key_id>:<signature>
 */
static struct asignify_signature*
asignify_sig_load_native(const char *buf, size_t buflen)
{
	char *errstr;
	const char *p = buf;
	unsigned int version;
	size_t remain = buflen, blen;
	struct asignify_signature *res = NULL;

	/* Skip PUBKEY_MAGIC and goto version */
	p += sizeof(SIG_MAGIC) - 1;
	remain -= sizeof(SIG_MAGIC) - 1;

	version = strtoul(p, &errstr, 10);
	if (errstr == NULL || *errstr != ':'
			|| version == 0 || version > SIG_VER_MAX) {
		return (NULL);
	}

	if (version == 1) {
		res = xmalloc(sizeof(*res));
		res->version = 1;
		res->data_len = SIG_KEY_ID_LEN;
		res->id_len = SIG_KEY_ID_LEN;
		asignify_alloc_sig_fields(res);

		/* Read ID */
		blen = b64_pton_stop(p, res->id, res->id_len, ":");
		if (blen != res->id_len || (p = strchr(p, ':')) == NULL) {
			asignify_signature_free(res);
			return (NULL);
		}

		p ++;

		/* Read key */
		blen = b64_pton_stop(p, res->data, res->data_len, "");
		if (blen != res->data_len) {
			asignify_signature_free(res);
			return (NULL);
		}
	}

	return (res);
}

struct asignify_signature*
asignify_signature_load(FILE *f)
{
	struct asignify_signature *res = NULL;
	char *buf = NULL;
	size_t buflen = 0;
	bool first = true;

	if (f == NULL) {
		abort();
	}

	while (getline(&buf, &buflen, f) != -1) {
		if (first && buflen > sizeof(SIG_MAGIC)) {
			first = false;

			if (memcmp(buf, SIG_MAGIC, sizeof(SIG_MAGIC) - 1) == 0) {
				res = asignify_sig_load_native(buf, buflen);
				break;
			}
			else {
				if (!asignify_sig_try_obsd(buf, buflen, &res)) {
					break;
				}
			}
		}
		if (!asignify_sig_try_obsd(buf, buflen, &res)) {
			break;
		}
	}

	return (res);
}

void
asignify_signature_free(struct asignify_signature *sig)
{
	if (sig) {
		free(sig->data);
		free(sig->id);
		sig->data = NULL;
		sig->id = NULL;
		free(sig);
	}
}
