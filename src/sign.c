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
#include <sys/param.h>
#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <getopt.h>

#include "asignify.h"
#include "cli.h"

#ifdef HAVE_READPASSPHRASE_H
#include <readpassphrase.h>
#elif defined(HAVE_BSD_READPASSPHRASE_H)
#include <bsd/readpassphrase.h>
#else
#include "readpassphrase_compat.h"
#endif

static int
read_password(char *buf, size_t len, void *d)
{
	char password[512];
	int l;

	if (readpassphrase("Password:", password, sizeof(password), 0) != NULL) {
		l = strlen(password);
		memcpy(buf, password, l);
		explicit_memzero(password, sizeof(password));

		return (l);
	}

	return (-1);
}

const char *
cli_sign_help(void)
{
	return ("sign [-n] [-d <digest>] secretkey signature [file1 [file2...]]");
}

int
cli_sign(int argc, char **argv)
{
	asignify_sign_t *sgn;
	const char *seckeyfile = NULL, *sigfile = NULL;
	int i;

	if (argc < 2) {
		return (0);
	}

	seckeyfile = argv[0];
	sigfile = argv[1];

	sgn = asignify_sign_init();

	if (!asignify_sign_load_privkey(sgn, seckeyfile, read_password, NULL)) {
		fprintf(stderr, "cannot load private key %s: %s", seckeyfile,
			asignify_sign_get_error(sgn));
		asignify_sign_free(sgn);
		return (-1);
	}

	for (i = 2; i < argc; i ++) {
		if (!asignify_sign_add_file(sgn, argv[i], ASIGNIFY_DIGEST_BLAKE2)) {
			fprintf(stderr, "cannot sign file %s: %s", argv[i],
				asignify_sign_get_error(sgn));
			asignify_sign_free(sgn);
			return (-1);
		}
	}

	if (!asignify_sign_write_signature(sgn, sigfile)) {
		fprintf(stderr, "cannot write sign file %s: %s", sigfile,
			asignify_sign_get_error(sgn));
		asignify_sign_free(sgn);
		return (-1);
	}

	asignify_sign_free(sgn);

	return (1);
}
