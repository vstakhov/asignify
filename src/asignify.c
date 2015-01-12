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

int quiet = 0;

static void
usage(const char *error)
{
	if (error)
		fprintf(stderr, "%s\n", error);

	fprintf(stderr, "usage:"
	    "\tasignify [-q] %s\n"
	    "\tasignify [-q] %s\n"
	    "\tasignify [-q] %s\n"
	    "\tasignify [-q] %s\n",
	    cli_verify_help(false), cli_check_help(false),
	    cli_sign_help(false), cli_generate_help(false));

	exit(EXIT_FAILURE);
}

static
void help(bool failed, int argc, char **argv)
{
	const char *ret = NULL;

	if (argc == 0) {
		usage(NULL);
	}
	else {
		if (strcasecmp(argv[0], "check") == 0) {
			ret = cli_check_help(true);
		}
		else if (strcasecmp(argv[0], "verify") == 0) {
			ret = cli_verify_help(true);
		}
		else if (strcasecmp(argv[0], "sign") == 0) {
			ret = cli_sign_help(true);
		}
		else if (strcasecmp(argv[0], "generate") == 0) {
			ret = cli_generate_help(true);
		}
		else if (strcasecmp(argv[0], "encrypt") == 0 ||
					strcasecmp(argv[0], "decrypt") == 0) {
			ret = cli_encrypt_help(true);
		}
		else {
			usage("unknown command");
		}

		if (ret != NULL) {
			if (failed) {
				fprintf(stderr, "%s", ret);
				exit(EXIT_FAILURE);
			}
			else {
				printf("%s", ret);
				exit(EXIT_SUCCESS);
			}
		}
	}

}

int
main(int argc, char **argv)
{
	int ch, ret = -1, i;
	static struct option long_options[] = {
		{"quiet",   no_argument,       0,  'q' },
		{"help", 	no_argument,       0,  'h' },
		{"version",	no_argument,       0,  'v' },
		{0,         0,                 0,  0 }
	};
	char **our_argv;
	int our_argc;

	/*
	 * Workaround to fix lack of brain of glibc authors:
	 * getopt_long there tries to eat everything not stopping on arguments,
	 * therefore, we need to stop that mess manually
	 */
	our_argv = malloc(argc * sizeof(char *));
	our_argv[0] = argv[0];
	our_argc = 1;

	for (i = 1; i < argc; i ++) {
		if (argv[i] != NULL && *argv[i] == '-') {
			our_argv[our_argc++] = argv[i];
		}
		else {
			break;
		}
	}

	while ((ch = getopt_long(our_argc, our_argv, "qhv", long_options, NULL)) != -1) {
		switch (ch) {
		case 'q':
			quiet = 1;
			break;
		case 'h':
		case 'v':
		default:
			usage(NULL);
			break;
		}
	}
	argc -= optind;
	argv += optind;

	/* Read command as the next argument */
	if (argc == 0) {
		usage("must specify at least one command");
	}

	/* reset getopt for the next call */
#ifdef __GLIBC__
	optind = 0;
#else
	optreset = 1;
	optind = 1;
#endif

	if (strcasecmp(argv[0], "check") == 0) {
		ret = cli_check(argc, argv);
	}
	else if (strcasecmp(argv[0], "verify") == 0) {
		ret = cli_verify(argc, argv);
	}
	else if (strcasecmp(argv[0], "sign") == 0) {
		ret = cli_sign(argc, argv);
	}
	else if (strcasecmp(argv[0], "generate") == 0) {
		ret = cli_generate(argc, argv);
	}
	else if (strcasecmp(argv[0], "encrypt") == 0 ||
					strcasecmp(argv[0], "decrypt") == 0) {
		ret = cli_encrypt(argc, argv);
	}
	else if (strcasecmp(argv[0], "help") == 0) {
		help(false, argc - 1, argv + 1);
	}

	if (ret == 0) {
		help(true, argc, argv);
	}
	else if (ret == -1) {
		exit(EXIT_FAILURE);
	}

	return (EXIT_SUCCESS);
}
