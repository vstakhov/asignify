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

const char *
cli_verify_help(void)
{
	return ("verify pubkey signature");
}

int
cli_verify(int argc, char **argv)
{
	asignify_verify_t *vrf;
	const char *pubkeyfile = NULL, *sigfile = NULL;

	if (argc != 2) {
		return (0);
	}

	pubkeyfile = argv[0];
	sigfile = argv[1];

	vrf = asignify_verify_init();
	if (!asignify_verify_load_pubkey(vrf, pubkeyfile)) {
		fprintf(stderr, "cannot load pubkey %s: %s", pubkeyfile,
			asignify_verify_get_error(vrf));
		asignify_verify_free(vrf);
		return (-1);
	}

	if (!asignify_verify_load_signature(vrf, sigfile)) {
		fprintf(stderr, "cannot verify signature %s: %s", sigfile,
			asignify_verify_get_error(vrf));
		asignify_verify_free(vrf);
		return (-1);
	}

	asignify_verify_free(vrf);

	return (1);
}

const char *
cli_check_help(void)
{
	return ("check pubkey signature file [file ...]");
}

int
cli_check(int argc, char **argv)
{
	asignify_verify_t *vrf;
	const char *pubkeyfile = NULL, *sigfile = NULL;
	int i;

	if (argc < 3) {
		return (0);
	}

	pubkeyfile = argv[0];
	sigfile = argv[1];

	vrf = asignify_verify_init();
	if (!asignify_verify_load_pubkey(vrf, pubkeyfile)) {
		fprintf(stderr, "cannot load pubkey %s: %s", pubkeyfile,
			asignify_verify_get_error(vrf));
		asignify_verify_free(vrf);
		return (-1);
	}

	if (!asignify_verify_load_signature(vrf, sigfile)) {
		fprintf(stderr, "cannot verify signature %s: %s", sigfile,
			asignify_verify_get_error(vrf));
		asignify_verify_free(vrf);
		return (-1);
	}

	for (i = 2; i < argc; i ++) {
		if (!asignify_verify_file(vrf, argv[i])) {
			fprintf(stderr, "cannot check file %s: %s", argv[i],
				asignify_verify_get_error(vrf));
			asignify_verify_free(vrf);
			return (-1);
		}
	}

	asignify_verify_free(vrf);

	return (1);
}
