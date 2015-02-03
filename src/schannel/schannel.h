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


#ifndef __SCHANNEL_H
#define __SCHANNEL_H


#include <stdbool.h>

#include <sodium.h>


/*
 * schannel_init prepares the library for initialisation. It returns
 * true if the initialisation was successful, and false otherwise.
 */
bool	schannel_init(void);


#ifndef SCHANNEL_BUFSIZE
/* SCHANNEL_BUFSIZE defines the size of a channel buffer. */
#define SCHANNEL_BUFSIZE	2097152 /* 2 * 1024 * 1024 */
#endif

/* SCHANNEL_OVERHEAD defines the amount of overhead for an encrypted message. */
#define SCHANNEL_OVERHEAD	(crypto_secretbox_NONCEBYTES+\
				 crypto_secretbox_MACBYTES+12)
/* SCHANNEL_IDKEYSIZE defines the size of an identity public key. */
#define SCHANNEL_IDKEYSIZE	crypto_sign_PUBLICKEYBYTES
/* SCHANNEL_IDPKEYSIZE defines the size of an identity private key. */
#define SCHANNEL_IDPKEYSIZE	crypto_sign_SECRETKEYBYTES

/* SCHANNEL_KEYSIZE defines the size of a shared encryption key. */
#define SCHANNEL_KEYSIZE		crypto_box_BEFORENMBYTES

/*
 * The following define the constants used for the different message
 * types.
 */
#define SCHANNEL_INVALID_MESSAGE	0
#define SCHANNEL_NORMAL			1
#define SCHANNEL_KEX			2
#define SCHANNEL_SHUTDOWN		3


/*
 * struct schannel defines a secure channel. It contains data and
 * message counters to track the need for a new key exchange, and
 * shared keys for both directions of communications.
 */
struct schannel {
	uint64_t	rdata;
	uint64_t	sdata;

	uint32_t	rctr;
	uint32_t	sctr;

	uint8_t		rkey[SCHANNEL_KEYSIZE];
	uint8_t		skey[SCHANNEL_KEYSIZE];
	uint8_t		buf[SCHANNEL_BUFSIZE+SCHANNEL_OVERHEAD+1];

	int		sockfd;
	bool		ready;
	bool		kexip;
};


__BEGIN_DECLS
bool	schannel_init(void);
bool	schannel_dial(struct schannel *, int, uint8_t *, size_t, uint8_t *,
		      size_t);
bool	schannel_listen(struct schannel *, int, uint8_t *, size_t, uint8_t *,
			size_t);
bool	schannel_send(struct schannel *, uint8_t *, size_t);
uint8_t	schannel_recv(struct schannel *, uint8_t *, size_t *);
bool	schannel_close(struct schannel *);
void	schannel_zero(struct schannel *);
bool	schannel_rekey(struct schannel *);
__END_DECLS

#endif
