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

#ifdef HAVE_READPASSPHRASE_H
#include <readpassphrase.h>
#elif defined(HAVE_BSD_READPASSPHRASE_H)
#include <bsd/readpassphrase.h>
#else
#include "readpassphrase_compat.h"
#endif

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

static int
read_password_verify(char *buf, size_t len, void *d)
{
	char password[512], repeat[512];
	int l1, l2;

	if (readpassphrase("Password:", password, sizeof(password), 0) != NULL) {
		if (readpassphrase("Verify:", repeat, sizeof(repeat), 0) != NULL) {
			l1 = strlen(password);
			l2 = strlen(repeat);
			if (l1 == l2 && l1 <= len) {
				if (memcmp(password, repeat, l1) == 0) {
					memcpy(buf, password, l1);
					explicit_memzero(password, sizeof(password));
					explicit_memzero(repeat, sizeof(repeat));

					return (l1);
				}
			}
		}
	}

	return (-1);
}

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

int
main(int argc, char **argv)
{
	const char *pubkeyfile = NULL, *seckeyfile = NULL, *msgfile = NULL,
					*sigfile = NULL;
	int ch, rounds, i;
	char sigfilebuf[1024];
	int quiet = 0;
	bool unencrypted = 0;
	asignify_verify_t *vrf;
	asignify_sign_t *sgn;
	enum {
		NONE = 0,
		CHECK,
		GENERATE,
		SIGN,
		VERIFY
	} verb = NONE;


	rounds = PBKDF_MINROUNDS * 5;

	while ((ch = getopt(argc, argv, "CGSVuc:em:np:qr:s:x:")) != -1) {
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
		case 'G':
			if (verb) {
				usage(NULL);
			}
			verb = GENERATE;
			break;
		case 'S':
			if (verb) {
				usage(NULL);
			}
			verb = SIGN;
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
		case 'r':
			rounds = strtoul(optarg, NULL, 10);
			if (rounds < PBKDF_MINROUNDS) {
				errx(1, "too few pbkdf rounds");
			}
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

	unencrypted = (rounds == 0);

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


	switch(verb) {
	case CHECK:
	case VERIFY:
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

		asignify_verify_free(vrf);
		break;

	case GENERATE:
		if (!pubkeyfile || !seckeyfile) {
			usage("must specify both public and secret keys to generate");
		}

		if (!unencrypted) {
			if (!asignify_generate(seckeyfile, pubkeyfile, 1, rounds,
					read_password_verify, NULL)) {
				errx(1, "Cannot generate keypair");
			}
		}
		else {
			if (!asignify_generate(seckeyfile, pubkeyfile, 1, 0,
					NULL, NULL)) {
				errx(1, "Cannot generate keypair");
			}
		}
		break;

	case SIGN:
		if (!seckeyfile || !sigfile) {
			usage("must specify both secret key and signature to generate");
		}
		if (argc == 0) {
			usage(NULL);
		}

		sgn = asignify_sign_init();

		if (unencrypted) {
			if (!asignify_sign_load_privkey(sgn, seckeyfile, NULL, NULL)) {
				errx(1, "cannot load private key %s: %s", seckeyfile,
					asignify_sign_get_error(sgn));
			}
		}
		else {
			if (!asignify_sign_load_privkey(sgn, seckeyfile, read_password, NULL)) {
				errx(1, "cannot load private key %s: %s", seckeyfile,
					asignify_sign_get_error(sgn));
			}
		}
		for (i = 0; i < argc; i ++) {
			if (!asignify_sign_add_file(sgn, argv[i], ASIGNIFY_DIGEST_BLAKE2)) {
				errx(1, "cannot sign file %s: %s", argv[i],
					asignify_sign_get_error(sgn));
			}
		}

		if (!asignify_sign_write_signature(sgn, sigfile)) {
			errx(1, "cannot write sign file %s: %s", sigfile,
				asignify_sign_get_error(sgn));
		}

		asignify_sign_free(sgn);
		break;

	default:
		usage(NULL);
		break;
	}

	return (EXIT_SUCCESS);
}
