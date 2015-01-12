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
cli_encrypt_help(bool full)
{

	const char *fullmsg = ""
		"asignify [global_opts] encrypt/decrypt - encrypt or decrypt a file\n\n"
		"Usage: asignify encrypt [-d] <secretkey> <pubkey> <in> <out>\n"
		"\t-d            Perform decryption\n"
		"\tsecretkey     Path to a secret key file encrypt and sign\n"
		"\tpubkey        Path to a peer's public key (must not be related to secretkey)\n"
		"\tin            Path to input file\n"
		"\tout           Path to ouptut file (must be a regular file)\n";

	if (!full) {
		return ("encrypt [-d] <secretkey> <pubkey> <in> <out>");
	}

	return (fullmsg);
}

int
cli_encrypt(int argc, char **argv)
{
	asignify_encrypt_t *enc;
	const char *seckeyfile = NULL, *pubkeyfile = NULL,
				*infile = NULL, *outfile = NULL;
	int ch;
	bool decrypt = false;
	static struct option long_options[] = {
		{"no-size",   no_argument,     0,  'n' },
		{"digest", 	required_argument, 0,  'd' },
		{0,         0,                 0,  0 }
	};

	if (strcmp(argv[0], "decrypt") == 0) {
		decrypt = true;
	}

	while ((ch = getopt_long(argc, argv, "d", long_options, NULL)) != -1) {
		switch (ch) {
		case 'd':
			decrypt = true;
			break;
		default:
			return (0);
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 4) {
		return (0);
	}


	seckeyfile = argv[0];
	pubkeyfile = argv[1];
	infile = argv[2];
	outfile = argv[3];

	enc = asignify_encrypt_init();

	if (!asignify_encrypt_load_privkey(enc, seckeyfile, read_password, NULL)) {
		fprintf(stderr, "cannot load private key %s: %s\n", seckeyfile,
			asignify_encrypt_get_error(enc));
		asignify_encrypt_free(enc);
		return (-1);
	}

	if (!asignify_encrypt_load_pubkey(enc, pubkeyfile)) {
		fprintf(stderr, "cannot load public key %s: %s\n", pubkeyfile,
			asignify_encrypt_get_error(enc));
		asignify_encrypt_free(enc);
		return (-1);
	}

	if (decrypt) {
		if (!asignify_encrypt_decrypt_file(enc, infile, outfile)) {
			fprintf(stderr, "cannot decrypt file %s: %s\n", infile,
				asignify_encrypt_get_error(enc));
			unlink(outfile);
			asignify_encrypt_free(enc);
			return (-1);
		}
	}
	else {
		if (!asignify_encrypt_crypt_file(enc, 1, infile, outfile)) {
			fprintf(stderr, "cannot encrypt file %s: %s\n", infile,
				asignify_encrypt_get_error(enc));
			unlink(outfile);
			asignify_encrypt_free(enc);
			return (-1);
		}
	}

	asignify_encrypt_free(enc);

	if (!quiet) {
		if (decrypt) {
			printf("Decrypted and verified %s using local secret key %s and remote "
				"public key %s, result saved in %s\n",
				infile, seckeyfile, pubkeyfile, outfile);
		}
		else {
			printf("Encrypted and signed %s using local secret key %s and remote "
					"public key %s, result saved in %s\n",
				infile, seckeyfile, pubkeyfile, outfile);
		}
	}

	return (1);
}
