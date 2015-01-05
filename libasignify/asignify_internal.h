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
#ifndef ASIGNIFY_INTERNAL_H_
#define ASIGNIFY_INTERNAL_H_

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#include "asignify.h"

#define OBSD_COMMENTHDR "untrusted comment: "

struct asignify_pubkey {
	unsigned char *data;
	size_t data_len;
	unsigned char *id;
	size_t id_len;
	unsigned int version;
};

struct asignify_signature {
	unsigned char *data;
	size_t data_len;
	unsigned char *id;
	size_t id_len;
	unsigned int version;
};

void explicit_memzero(void * const pnt, const size_t len);
void randombytes(unsigned char *buf, uint64_t len);

FILE * xfopen(const char *fname, const char *mode);
void * xmalloc(size_t len);
void * xmalloc0(size_t len);

int b64_pton(char const *src, unsigned char *target, size_t targsize);
int b64_pton_stop(char const *src, unsigned char *target, size_t targsize, const char *stop);
int b64_ntop(unsigned char *src, size_t srclength, char *target,
	size_t targsize);

int hex2bin(unsigned char * const bin, const size_t bin_maxlen,
    const char * const hex, const size_t hex_len,
    size_t * const bin_len, const char ** const hex_end);

unsigned int asignify_digest_len(enum asignify_digest_type type);
unsigned char* asignify_digest_fd(enum asignify_digest_type type, int fd);

enum asignify_error {
	ASIGNIFY_ERROR_OK = 0,
	ASIGNIFY_ERROR_NO_PUBKEY,
	ASIGNIFY_ERROR_FILE,
	ASIGNIFY_ERROR_FORMAT,
	ASIGNIFY_ERROR_DECRYPT,
	ASIGNIFY_ERROR_PASSWORD,
	ASIGNIFY_ERROR_VERIFY,
	ASIGNIFY_ERROR_SIZE,
	ASIGNIFY_ERROR_VERIFY_DIGEST,
	ASIGNIFY_ERROR_MISUSE,
	ASIGNIFY_ERROR_MAX
};

const char * xerr_string(enum asignify_error code);

/*
 * Pubkey operations
 */
struct asignify_pubkey* asignify_pubkey_load(FILE *f);
bool asignify_pubkey_check_signature(struct asignify_pubkey *pk,
	struct asignify_signature *sig, const unsigned char *data, size_t dlen);
void asignify_pubkey_free(struct asignify_pubkey *pk);
bool asignify_pubkey_write(struct asignify_pubkey *pk, FILE *f);

/*
 * Signature operations
 */
struct asignify_signature* asignify_signature_load(FILE *f);
void asignify_signature_free(struct asignify_signature *sig);

#endif /* ASIGNIFY_INTERNAL_H_ */
