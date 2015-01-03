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

#ifndef libasignify_H
#define libasignify_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>


#if defined(__cplusplus)
extern "C" {
#endif

/*
 * Opaque structures
 */
struct asignify_verify_ctx;
struct asignify_sign_ctx;
typedef struct asignify_verify_ctx asignify_verify_t;
typedef struct asignify_sign_ctx asignify_sign_t;

typedef int (*asignify_password_cb)(char *buf, size_t len, void *d);

/**
 * Signature type
 */
enum asignify_digest_type {
	ASIGNIFY_DIGEST_SHA256 = 0,
	ASIGNIFY_DIGEST_SHA512,
	ASIGNIFY_DIGEST_BLAKE2,
	ASIGNIFY_DIGEST_MAX
};

/**
 * Initialize verify context
 * @return new verify context or NULL
 */
asignify_verify_t* asignify_verify_init(void);
/**
 * Load public key from a file
 * @param ctx verify context
 * @param pubf file name or '-' to read from stdin
 * @return true if a key has been successfully loaded
 */
bool asignify_verify_load_pubkey(asignify_verify_t *ctx, const char *pubf);

/**
 * Load and parse signature file
 * @param ctx verify context
 * @param sigf file name or '-' to read from stdin
 * @return true if a signature has been successfully loaded
 */
bool asignify_verify_load_signature(asignify_verify_t *ctx, const char *sigf);

/**
 * Verify file against parsed signature and pubkey
 * @param ctx verify context
 * @param checkf file name or '-' to read from stdin
 * @return true if a file is valid
 */
bool asignify_verify_file(asignify_verify_t *ctx, const char *checkf);

/**
 * Returns last error for verify context
 * @param ctx verify context
 * @return constant string corresponding to the last error occurred during verification
 */
const char* asignify_verify_get_error(asignify_verify_t *ctx);

/**
 * Free verify context
 * @param ctx verify context
 */
void asignify_verify_free(asignify_verify_t *ctx);

/**
 * Initialize sign context
 * @return new sign context or NULL
 */
asignify_sign_t* asignify_sign_init(void);

/**
 * Load private key from a file
 * @param ctx sign context
 * @param privf file name or '-' to read from stdin
 * @param password_cb function that is called to get password from a user
 * @param d opaque data pointer for password callback
 * @return true if a key has been successfully loaded
 */
bool asignify_sign_load_privkey(asignify_sign_t *ctx, const char *privf,
	asignify_password_cb password_cb, void *d);

/**
 * Add specified file to the signature context
 * @param ctx sign context
 * @param f file name or '-' to read from stdin
 * @param dt type of digest to be calculated
 * @return true if a file is valid
 */
bool asignify_sign_add_file(asignify_sign_t *ctx, const char *f,
	enum asignify_digest_type dt);

/**
 * Write the complete signature for this context
 * @param ctx sign context
 * @param sigf file name or '-' to write to stdout
 * @return true if a signature has been successfully written
 */
bool asignify_sign_write_signature(asignify_sign_t *ctx, const char *sigf);

/**
 * Returns last error for sign context
 * @param ctx sign context
 * @return constant string corresponding to the last error occurred during signing
 */
const char* asignify_sign_get_error(asignify_sign_t *ctx);

/**
 * Free sign context
 * @param ctx sign context
 */
void asignify_sign_free(asignify_sign_t *ctx);

#if defined(__cplusplus)
}
#endif

#endif
