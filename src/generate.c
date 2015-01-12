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
read_password_verify(char *buf, size_t len, void *d)
{
	char password[512], repeat[512];
	int l1, l2;

	if (readpassphrase("Password: ", password, sizeof(password), 0) != NULL) {
		if (readpassphrase("Verify: ", repeat, sizeof(repeat), 0) != NULL) {
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
			if (!quiet) {
				fprintf(stderr, "Password and verify mismatch\n");
			}
		}
	}

	return (-1);
}

const char *
cli_generate_help(bool full)
{
	const char *fullmsg = ""
		"asignify [global_opts] generate - generates a keypair\n\n"
		"Usage: asignify generate [-n] [-r <rounds>] [-s <sshkey> ] <secretkey> [<publickey>]\n"
		"\t-n           Do not encrypt secret key\n"
		"\t-r           Specify number of PBKDF rounds for secret key\n"
		"\t-s <sshkey>  Convert the specified ssh secret key to native secret key\n"
		"\tsecretkey    Path to a secret key\n"
		"\tpubkey       Path to a public key (default: <secretkey>.pub)\n";

	if (!full) {
		return ("generate [-n] [-r <rounds>] [-s <sshkey>] secretkey [publickey]");
	}

	return (fullmsg);
}

int
cli_generate(int argc, char **argv)
{
	int rounds = PBKDF_MINROUNDS * 10, ch;
	char pubkeybuf[PATH_MAX];
	const char *seckeyfile = NULL, *pubkeyfile = NULL, *sshkeyfile = NULL;
	static struct option long_options[] = {
		{"no-size",   no_argument,     0,  'n' },
		{"rounds", 	required_argument, 0,  'r' },
		{"ssh",     required_argument, 0,  's' },
		{0,         0,                 0,  0 }
	};

	while ((ch = getopt_long(argc, argv, "nr:s:", long_options, NULL)) != -1) {
		switch (ch) {
		case 'n':
			rounds = 0;
			break;
		case 'r':
			rounds = strtoul(optarg, NULL, 10);
			break;
		case 's':
			sshkeyfile = optarg;
			break;
		default:
			return (0);
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc == 1) {
		/* We have only a secret key specified */
		seckeyfile = argv[0];
		snprintf(pubkeybuf, sizeof(pubkeybuf), "%s.pub", seckeyfile);
		pubkeyfile = pubkeybuf;
	}
	else if (argc == 2) {
		seckeyfile = argv[0];
		pubkeyfile = argv[1];
	}
	else {
		return (0);
	}

	if (sshkeyfile) {
		if (rounds > 0) {
			if (!asignify_privkey_from_ssh(sshkeyfile, seckeyfile, 1, rounds,
					read_password_verify, NULL)) {
				fprintf(stderr, "Cannot convert ssh key\n");
				return (-1);
			}
		}
		else {
			if (!asignify_privkey_from_ssh(sshkeyfile, seckeyfile, 1, 0,
					NULL, NULL)) {
				fprintf(stderr, "Cannot convert ssh key\n");
				return (-1);
			}
		}

		if (!quiet) {
			printf("%s secret key is saved in %s\n",
					rounds > 0 ? "Encrypted" : "Unencrypted", seckeyfile);
		}
	}
	else {
		if (rounds > 0) {
			if (!asignify_generate(seckeyfile, pubkeyfile, 1, rounds,
					read_password_verify, NULL)) {
				fprintf(stderr, "Cannot generate keypair\n");
				return (-1);
			}
		}
		else {
			if (!asignify_generate(seckeyfile, pubkeyfile, 1, 0,
					NULL, NULL)) {
				fprintf(stderr, "Cannot generate keypair\n");
				return (-1);
			}
		}

		if (!quiet) {
			printf("%s keypair is saved in %s (private) and %s (public)\n",
					rounds > 0 ? "Encrypted" : "Unencrypted", seckeyfile, pubkeyfile);
		}
	}

	return (1);
}
