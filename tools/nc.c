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


#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <err.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sodium.h>

#include "schannel/schannel.h"

#define BUFSIZE		SCHANNEL_BUFSIZE
#define REKEY_AFTER	281474976710656L


/* 
 * stay_open indicates that the listener should listen for
 * multiple sessions.
 */
static int	stay_open = 0;


/*
 * ident stores the signer and verification keys.
 */
struct {
	uint8_t	signer[crypto_sign_SECRETKEYBYTES];
	uint8_t peer[crypto_sign_PUBLICKEYBYTES];
	size_t	signerlen;
	size_t	peerlen;
} ident;


/*
 * zero_identity zeroises the private key stored in the ident structure.
 */
static void
zero_identity(void)
{
	sodium_memzero(ident.signer, ident.signerlen);
}


/*
 * sch_listener takes the socket, containing a descriptor for a TCP
 * connection to a connected client, and sets up a secure channel.
 * It reads data from the client until a shutdown message or error
 * occurs. Zeroisation of the private key will only occur if the
 * program shuts down in error.
 */
static void
sch_listener(int sockfd)
{
	struct schannel	 sch;
	uint8_t		 buf[BUFSIZE];
	size_t		 buflen;
	uint8_t		 mtype;
	uint8_t		*signer = NULL;
	uint8_t		*peer = NULL;

	if (0 != ident.signerlen) {
		signer = ident.signer;
	}

	if (0 != ident.peerlen) {
		peer = ident.peer;
	}

	if (!schannel_listen(&sch, sockfd, signer, ident.signerlen, peer,
			     ident.peerlen)) {
		warnx("key exchange failed");
		return;
	}

	fprintf(stderr, "secure channel established\n");

	while (1) {
		buflen = BUFSIZE;
		mtype = schannel_recv(&sch, buf, &buflen);
		switch (mtype) {
		case SCHANNEL_INVALID_MESSAGE:
			warn("receive failed");
			schannel_zero(&sch);
			return;
		case SCHANNEL_NORMAL:
			if (0 != buflen) {
				fwrite(buf, 1, buflen, stdout);
			}
			memset(buf, 0, buflen);
			break;
		case SCHANNEL_SHUTDOWN:
			fprintf(stderr, "secure channel shutdown\n");
			fprintf(stderr, "%lu bytes read\n", (size_t)sch.rdata);
			schannel_zero(&sch);
			return;
		case SCHANNEL_KEX:
			fprintf(stderr, "session keys rotated\n");
			break;
		default:
			zero_identity();
			errx(EXIT_FAILURE, "unknown message type %d", mtype);
		}

	}

	return;
}


/*
 * listener listens on INADDR_ANY on the specified port. When a client
 * connects, it will call sch_listener to set up a secure session. If
 * the stay_open option hasn't been specified, it will shutdown after
 * the session is complete. It will only run one session at a time.
 */
static void
listener(uint16_t port)
{
	struct sockaddr_in	sin;
	struct sockaddr_in	cin;
	size_t			cinlen = sizeof cin;
	int			sockfd = -1;
	int			clifd = -1;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1) {
		err(EXIT_FAILURE, "failed to set up socket");
	}

	memset(sin.sin_zero, '\0', sizeof sin.sin_zero);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = INADDR_ANY;

	if (-1 == bind(sockfd, (struct sockaddr *)&sin, sizeof sin)) {
		err(EXIT_FAILURE, "failed to bind to port");
	}

	if (-1 == listen(sockfd, 4)) {
		err(EXIT_FAILURE, "failed to set up backlog");
	}

	while (1) {
		clifd = accept(sockfd, (struct sockaddr *)&cin, (socklen_t *)&cinlen);
		if (-1 == clifd) {
			close(sockfd);
			zero_identity();
			err(EXIT_FAILURE, "failed to accept connection");
		}

		sch_listener(clifd);
		if (0 == stay_open) {
			zero_identity();
			break;
		}
	}
}


/*
 * sch_sender takes a socket descriptor for a TCP connection to a server,
 * and sets up a secure channel. It then sends the contents of stdin to
 * the server, and shuts down the connection.
 */
static void
sch_sender(int sockfd)
{
	struct schannel	 sch;
	uint8_t		 buf[BUFSIZE];
	size_t		 buflen = 0;	
	uint8_t		*signer = NULL;
	uint8_t		*peer = NULL;

	if (0 != ident.signerlen) {
		signer = ident.signer;
	}

	if (0 != ident.peerlen) {
		peer = ident.peer;
	}

	if (!schannel_dial(&sch, sockfd, signer, ident.signerlen, peer,
			   ident.peerlen)) {
		err(EXIT_FAILURE, "key exchange failed");
	}

	fprintf(stderr, "secure channel established\n");
	while (1) {
		if (sch.sdata > REKEY_AFTER) {
			fprintf(stderr, "rekey required\n");
			if (!schannel_rekey(&sch)) {
				fprintf(stderr, "rekey failed\n");
				zero_identity();
				exit(EXIT_FAILURE);
			}
			fprintf(stderr, "rekey complete\n");
		}

		buflen = fread(buf, 1, BUFSIZE, stdin);
		if (0 == buflen) {
			printf("\n");
			printf("secure channel shutdown\n");
			schannel_zero(&sch);
			zero_identity();
			exit(EXIT_SUCCESS);
		}

		if (!schannel_send(&sch, buf, buflen)) {
			zero_identity();
			errx(EXIT_FAILURE, "schannel_send failed.");
		}
		printf(".");

		if (buflen < BUFSIZE) {
			printf("\n");
			printf("secure channel shutdown\n");
			printf("%lu bytes written\n", (size_t)sch.sdata);
			schannel_close(&sch);
			return;
		}
	}
}


/*
 * sender connects to the host on the specified port. If the connection
 * is successful, it will set up a secure session.
 */
static void
sender(const char *host, uint16_t port)
{
	struct sockaddr_in	 sin;
	int			 sockfd;

	memset(sin.sin_zero, '\0', sizeof sin.sin_zero);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	if (-1 == inet_aton(host, &sin.sin_addr)) {
		zero_identity();
		err(EXIT_FAILURE, "failed to get address of peer");
	}

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (-1 == sockfd) {
		zero_identity();
		err(EXIT_FAILURE, "failed to set up socket");
	}

	if (-1 == connect(sockfd, (struct sockaddr *)&sin,
		    (socklen_t)(sizeof sin))) {
		zero_identity();
		err(EXIT_FAILURE, "failed to connect to remote");
	}

	sch_sender(sockfd);
	zero_identity();
}


/*
 * read_file attempts to read the buflen bytes into buf from path,
 * returning false if the file couldn't be opened for reading or
 * if a short read occurred.
 */
static bool
read_file(const char *path, uint8_t *buf, size_t buflen)
{
	FILE	*file = NULL;
	bool	 ok = false;

	if (NULL == (file = fopen(path, "r"))) {
		err(EXIT_FAILURE, "%s", path);		
	}

	if (buflen == fread(buf, 1, buflen, file)) {
		ok = true;
	}

	fclose(file);
	return ok;
}


/*
 * usage prints an informational message describing the usage of this
 * program.
 */
static void
usage(void)
{
	fprintf(stderr, "schannel_nc version %s\n", VERSION);
	fprintf(stderr, "Usage:\n\n");
	fprintf(stderr, "schannel_nc  [-hk] [-s signer] [-v verifier] host port\n");
	fprintf(stderr, "schannel_nc [-hkl] [-s signer] [-v verifier] port\n");
	fprintf(stderr, "\t-h\t\tprint this usage message and exit\n");
	fprintf(stderr, "\t-k\t\tforce the program to keep listening after the client\n");
	fprintf(stderr, "\t\t\tdisconnects. This must be used with -l.\n");
	fprintf(stderr, "\t-l\t\tlisten for an incoming connection\n");
	fprintf(stderr, "\t-s signer\tspecify the path to a signature key\n");
	fprintf(stderr, "\t-v verifier\tspecify the path to a verification key\n");
	fprintf(stderr, "\nIf a signature key is specified, it will be used to ");
	fprintf(stderr, "sign the key exchange. If a\nverification key is ");
	fprintf(stderr, "specified, it will be used to verify the signature on ");
	fprintf(stderr, "the\nkey exchange.\n\n");
}


/*
 * schannel_nc is a simple nc-like program that sets up a secure
 * channel between two peers to transfer data.
 */
int
main(int argc, char *argv[])
{
	int		opt;
	int		listen = 0;
	int		reqd = 2;
	uint16_t	port = 0;	

	while ((opt = getopt(argc, argv, "hkls:v:")) != -1) {
		switch (opt) {
		case 'h':
			usage();
			exit(EXIT_SUCCESS);
		case 'k':
			stay_open = 1;
			break;
		case 'l':
			listen = 1;
			break;
		case 's':
			if (!read_file(optarg, ident.signer, crypto_sign_SECRETKEYBYTES)) {
				err(EXIT_FAILURE, "failed to read signer key");
			}
			ident.signerlen = crypto_sign_SECRETKEYBYTES;
			break;
		case 'v':
			if (!read_file(optarg, ident.peer, crypto_sign_PUBLICKEYBYTES)) {
				err(EXIT_FAILURE, "failed to read peer key");
			}
			ident.peerlen = crypto_sign_PUBLICKEYBYTES;
			break;
		default:
			/* NOT REACHED */
			usage();
			exit(EXIT_FAILURE);
		}
	}

	argc -= optind;
	argv += optind;

	reqd -= listen;
	if (argc != reqd) {
		errx(EXIT_FAILURE, "Need %d arguments.", reqd);
	}

	if (!schannel_init()) {
		errx(EXIT_FAILURE, "Failed to initialise schannel.");
	}

	if (listen) {
		port = (uint16_t)atoi(argv[0]);
		listener(port);
	} else {
		port = (uint16_t)atoi(argv[1]);
		sender(argv[0], port);
	}
}

