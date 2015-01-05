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
#include <stdlib.h>
#include <err.h>
#include <unistd.h>
#include <string.h>
#include "asignify.h"

static void
usage(const char *error)
{
	if (error)
		fprintf(stderr, "%s\n", error);

	fprintf(stderr, "usage:"
	    "\tasignify -C [-q] -p pubkey -x sigfile [file ...]\n"
	    "\tasignify -G [-n] [-c comment] -p pubkey -s seckey\n"
	    "\tasignify -S [-e] [-x sigfile] -s seckey -m message\n"
	    "\tasignify -V [-eq] [-x sigfile] -p pubkey -m message\n");

	exit(EXIT_FAILURE);
}

int
main(int argc, char **argv)
{
	const char *pubkeyfile = NULL, *seckeyfile = NULL, *msgfile = NULL,
					*sigfile = NULL;
	int ch, rounds, i;
	char sigfilebuf[1024];
	int quiet = 0;
	asignify_verify_t *vrf;
	enum {
		NONE = 0,
		CHECK,
		GENERATE,
		SIGN,
		VERIFY
	} verb = NONE;


	rounds = 42;

	while ((ch = getopt(argc, argv, "CGSVc:em:np:qs:x:")) != -1) {
		switch (ch) {
		case 'C':
			if (verb) {
				usage(NULL);
			}
			verb = CHECK;
			break;
		case 'V':
			if (verb) {
				usage(NULL);
			}
			verb = VERIFY;
			break;
		case 'm':
			msgfile = optarg;
			break;
		case 'n':
			rounds = 0;
			break;
		case 'p':
			pubkeyfile = optarg;
			break;
		case 'q':
			quiet = 1;
			break;
		case 's':
			seckeyfile = optarg;
			break;
		case 'x':
			sigfile = optarg;
			break;
		default:
			usage(NULL);
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (!sigfile && msgfile) {
		int nr;
		if (strcmp(msgfile, "-") == 0) {
			usage("must specify sigfile with - message");
		}
		if ((nr = snprintf(sigfilebuf, sizeof(sigfilebuf), "%s.sig",
			msgfile)) == -1 || nr >= sizeof(sigfilebuf)) {
			errx(1, "path too long");
		}
		sigfile = sigfilebuf;
	}


	if (verb == CHECK || verb == VERIFY) {
		vrf = asignify_verify_init();
		if (!asignify_verify_load_pubkey(vrf, pubkeyfile)) {
			errx(1, "cannot load pubkey %s: %s", pubkeyfile,
				asignify_verify_get_error(vrf));
		}

		if (!asignify_verify_load_signature(vrf, sigfile)) {
			errx(1, "cannot load signature %s: %s", sigfile,
				asignify_verify_get_error(vrf));
		}

		if (verb == CHECK) {
			if (argc == 0) {
				usage(NULL);
			}
			for (i = 0; i < argc; i ++) {
				if (!asignify_verify_file(vrf, argv[i])) {
					errx(1, "cannot verify file %s: %s", argv[i],
						asignify_verify_get_error(vrf));
				}
			}
		}
	}

	return (EXIT_SUCCESS);
}
