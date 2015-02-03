/*
 * Copyright (c) 2014 Kyle Isom <kyle@tyrfingr.is>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */


#include <err.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>


/*
 * usage prints an informational message describing the usage of this
 * program.
 */
static void
usage(void)
{
	fprintf(stderr, "schannel_keygen version %s\n", VERSION);
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "\tschannel_keygen basename\n");
	fprintf(stderr, "\t\tThis program will output a pair of files:\n");
	fprintf(stderr, "\t\t\t- basename.key: private signature (identity key)\n");
	fprintf(stderr, "\t\t\t- basename.pub: public signature (identity key)\n");
	fprintf(stderr, "\t\tThese files will be in the binary form that can be ");
	fprintf(stderr, "directly loaded into\n\t\tthe schannel_dial and");
	fprintf(stderr, "schannel_listen functions.\n\n");
}


/*
 * write_file attempts to write the buflen-sized buf to path, returning
 * false if the file couldn't be opened for writing or if a short write
 * occurred.
 */
static bool
write_file(const char *path, uint8_t *buf, size_t buflen)
{
	FILE	*file = NULL;
	bool	 ok = false;

	if (NULL == (file = fopen(path, "w"))) {
		warn("%s", path);
		return false;
	}

	if (buflen == fwrite(buf, 1, buflen, file)) {
		ok = true;	
	}

	fclose(file);
	return ok;
}


/*
 * schannel_keygen is a utility for generating the identity keys for
 * programs using the schannel library.
 */
int
main(int argc, char *argv[])
{
	uint8_t		filename[PATH_MAX+1];
	uint8_t		private[crypto_sign_SECRETKEYBYTES];
	uint8_t		public[crypto_sign_PUBLICKEYBYTES];

	if (argc != 2) {
		usage();
		exit(EXIT_FAILURE);
	}

	if (-1 == crypto_sign_keypair(public, private)) {
		fprintf(stderr, "Failed to generate keypair.\n");
		exit(EXIT_FAILURE);
	}

	if (-1 == snprintf((char *)filename, PATH_MAX+1, "%s.key", argv[1])) {
		sodium_memzero(private, crypto_sign_SECRETKEYBYTES);
		err(EXIT_FAILURE, "failed to create pathname");
	}

	if (!write_file((const char *)filename, private, crypto_sign_SECRETKEYBYTES)) {
		sodium_memzero(private, crypto_sign_SECRETKEYBYTES);
		err(EXIT_FAILURE, "failed to write private key");
	}

	sodium_memzero(private, crypto_sign_SECRETKEYBYTES);

	if (-1 == snprintf((char *)filename, PATH_MAX+1, "%s.pub", argv[1])) {
		err(EXIT_FAILURE, "failed to create pathname");
	}

	if (!write_file((const char *)filename, public, crypto_sign_PUBLICKEYBYTES)) {
		err(EXIT_FAILURE, "failed to write public key");
	}

	return EXIT_SUCCESS;
}
