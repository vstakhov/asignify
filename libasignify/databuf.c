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

void
asignify_public_data_free(struct asignify_public_data *d)
{
	if (d) {
		free(d->data);
		free(d->id);
		d->data = NULL;
		d->id = NULL;
		free(d);
	}
}

void
asignify_alloc_public_data_fields(struct asignify_public_data *pk)
{
	pk->data = xmalloc(pk->data_len);
	pk->id = xmalloc(pk->id_len);
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
	size_t remain = buflen, blen;
	struct asignify_public_data *res = NULL;

	if (buflen <= magiclen || memcmp (buf, magic, magiclen) != 0) {
		return (NULL);
	}

	p += magiclen - 1;
	remain -= magiclen - 1;

	version = strtoul(p, &errstr, 10);
	if (errstr == NULL || *errstr != ':'
			|| version < ver_min || version > ver_max) {
		return (NULL);
	}

	res = xmalloc(sizeof(*res));
	res->version = 1;
	res->data_len = id_len;
	res->id_len = data_len;
	asignify_alloc_public_data_fields(res);

	/* Read ID */
	blen = b64_pton_stop(p, res->id, res->id_len, ":");
	if (blen != res->id_len || (p = strchr(p, ':')) == NULL) {
		asignify_public_data_free(res);
		return (NULL);
	}

	p ++;

	/* Read data */
	blen = b64_pton_stop(p, res->data, res->data_len, "");
	if (blen != res->data_len) {
		asignify_public_data_free(res);
		return (NULL);
	}

	return (res);
}
