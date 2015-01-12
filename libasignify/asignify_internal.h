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

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <fcntl.h> /* for mode_t */

#include "asignify.h"

#define OBSD_COMMENTHDR "untrusted comment: "
#define PRIVKEY_MAGIC "asignify-private-key"
#define KEY_ID_LEN 8
#define SALT_LEN 16
#define PBKDF_ALG "pbkdf2-blake2"

#if defined(__GNUC__)  && __GNUC__ >= 4
#define STRUCT_OFFSET(struct_type, member)						\
      ((long) offsetof(struct_type, member))
#else
#define STRUCT_OFFSET(struct_type, member)						\
      ((long)((unsigned char*) &((struct_type*) 0)->member))
#endif
#define STRUCT_MEMBER_PTR(member_type, struct_p, struct_offset)   \
    ((member_type*)((void *)((unsigned char*)(struct_p) + (long)(struct_offset))))

struct asignify_public_data {
	unsigned char *data;
	size_t data_len;
	unsigned char *id;
	size_t id_len;
	unsigned char *aux;
	size_t aux_len;
	unsigned int version;
};

struct asignify_private_data {
	unsigned char *data;
	size_t data_len;
	unsigned char *id;
	size_t id_len;
	unsigned int version;
};

struct asignify_private_key {
	unsigned int version;
	char *pbkdf_alg;
	unsigned int rounds;
	unsigned char *salt;
	unsigned char *checksum;
	unsigned char *id;
	unsigned char *encrypted_blob;
};

struct asignify_file_digest {
	enum asignify_digest_type digest_type;
	unsigned char *digest;
	struct asignify_file_digest *next;
};

struct asignify_file {
	char *fname;
	struct asignify_file_digest *digests;
	uint64_t size;
};

void randombytes(unsigned char *buf, uint64_t len);

int pkcs5_pbkdf2(const char *pass, size_t pass_len, const uint8_t *salt,
    size_t salt_len, uint8_t *key, size_t key_len, unsigned int rounds);

FILE * xfopen(const char *fname, const char *mode);
int xopen(const char *fname, int oflags, mode_t mode);
void * xmalloc(size_t len);
void * xmalloc_aligned(size_t align, size_t len);
void * xmalloc0(size_t len);
char * xstrdup(const char *str);

int b64_pton(char const *src, unsigned char *target, size_t targsize);
int b64_pton_stop(char const *src, unsigned char *target, size_t targsize, const char *stop);
int b64_ntop(unsigned char *src, size_t srclength, char *target,
	size_t targsize);

int hex2bin(unsigned char * const bin, const size_t bin_maxlen,
    const char * const hex, const size_t hex_len,
    size_t * const bin_len, const char ** const hex_end);
char * bin2hex(char * const hex, const size_t hex_maxlen,
	const unsigned char * const bin, const size_t bin_len);

enum asignify_error {
	ASIGNIFY_ERROR_OK = 0,
	ASIGNIFY_ERROR_NO_PUBKEY,
	ASIGNIFY_ERROR_FILE,
	ASIGNIFY_ERROR_FORMAT,
	ASIGNIFY_ERROR_DECRYPT,
	ASIGNIFY_ERROR_PASSWORD,
	ASIGNIFY_ERROR_VERIFY,
	ASIGNIFY_ERROR_SIZE,
	ASIGNIFY_ERROR_VERIFY_SIZE,
	ASIGNIFY_ERROR_VERIFY_DIGEST,
	ASIGNIFY_ERROR_NO_DIGEST,
	ASIGNIFY_ERROR_MISUSE,
	ASIGNIFY_ERROR_WRONG_KEYPAIR,
	ASIGNIFY_ERROR_MAX
};

const char * xerr_string(enum asignify_error code);

/*
 * Common public data operations
 */
void asignify_alloc_public_data_fields(struct asignify_public_data *pk);
struct asignify_public_data* asignify_public_data_load(const char *buf,
	size_t buflen, const char *magic,
	size_t magiclen, unsigned int ver_min, unsigned int ver_max,
	unsigned int id_len, unsigned int data_len);
void asignify_public_data_free(struct asignify_public_data *d);

/*
 * Common secret data operations
 */
struct asignify_private_data* asignify_private_data_load(FILE *f, int *error,
	asignify_password_cb password_cb, void *d);
void asignify_private_data_free(struct asignify_private_data *d);
bool asignify_privkey_write(struct asignify_private_key *privk, FILE *f);
struct asignify_public_data* asignify_private_data_sign(
	struct asignify_private_data *privk, unsigned char *buf, size_t len);

/*
 * Pubkey operations
 */
struct asignify_public_data* asignify_pubkey_load(FILE *f);
bool asignify_pubkey_check_signature(struct asignify_public_data *pk,
	struct asignify_public_data *sig, const unsigned char *data, size_t dlen);
bool asignify_pubkey_write(struct asignify_public_data *pk, FILE *f);

/*
 * Signature operations
 */
struct asignify_public_data* asignify_signature_load(FILE *f,
		struct asignify_public_data *pk);
bool asignify_signature_write(struct asignify_public_data *sig, const void *buf,
	size_t len, FILE *f);

/*
 * SSH keys routines
 */
const unsigned char * asignify_ssh_read_string(const unsigned char *buf,
		unsigned int *str_len, unsigned int remain, unsigned char const **npos);
struct asignify_private_data* asignify_ssh_privkey_load(FILE *f, int *error);

#endif /* ASIGNIFY_INTERNAL_H_ */
