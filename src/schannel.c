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
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>

#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include <sodium.h>

#include "schannel/schannel.h"


/* A key exchange key contains two Curve25519 keys. */
#define	SCHANNEL_KEX_PUBLEN	2*crypto_box_PUBLICKEYBYTES
#define	SCHANNEL_KEX_PRVLEN	2*crypto_box_SECRETKEYBYTES

/* SCHANNEL_SIGSIZE defines the size of a signature. */
#define SCHANNEL_SIGSIZE		crypto_sign_BYTES


/*
 * The struct schan_message is used as the envelope for encrypted
 * messages. It encapsulates a message, a sequence number, version
 * information, and a payload.
 */
struct schan_message {
	uint8_t		version;
	uint32_t	seqno;
	uint32_t	payload_length;
	uint8_t		mtype;
	uint8_t		payload[SCHANNEL_BUFSIZE];
};


bool		sign_kex(uint8_t *, uint8_t *, uint8_t *);
static bool	validate_keys(uint8_t *, size_t, uint8_t *, size_t);
static void	reset_counters(struct schannel *);
static void	initialise_schannel(struct schannel *);
static bool	generate_keypair(uint8_t *, uint8_t *);
static bool	verify_kex(uint8_t *, uint8_t *);
static bool	do_kex(struct schannel *, uint8_t *, uint8_t *, bool);
static bool	_schannel_send(struct schannel *, uint8_t, uint8_t *, size_t);
static bool	unpack_message(struct schannel *, struct schan_message *,
			       uint32_t);
static bool	schannel_recv_kex(struct schannel *, struct schan_message *);


/*
 * schannel_init prepares the library for initialisation. It returns
 * true if the initialisation was successful, and false otherwise.
 */
bool
schannel_init(void)
{
	struct rlimit		rlim;
	struct schannel 	sch;
	struct schan_message	m;

	if (sodium_init() == -1) {
		return false;
	}

	if (-1 == getrlimit(RLIMIT_STACK, &rlim)) {
		return false;
	}

	if (rlim.rlim_cur < ((sizeof sch)+(sizeof m)+SCHANNEL_BUFSIZE+
		    SCHANNEL_KEX_PUBLEN+SCHANNEL_SIGSIZE)) {
		return false;
	}
	return true;
}


/*
 * validate keys ensures that the keys passed in can be used, and have an
 * appropriate length.
 */
bool
validate_keys(uint8_t *signer, size_t signer_len, uint8_t *peer,
	      size_t peer_len)
{
	if (NULL != signer) {
		assert(SCHANNEL_IDPKEYSIZE == signer_len);
#ifdef NODEBUG
		if (SCHANNEL_IDPKEYSIZE != signer_len) {
			return false;
		}
#endif
	} else {
		assert(0 == signer_len);
#ifdef NODEBUG
		if (0 != signer_len) {
			return false;
		}
#endif
	}

	if (NULL != peer) {
		assert(SCHANNEL_IDKEYSIZE == peer_len);
#ifdef NODEBUG
		if (SCHANNEL_IDKEYSIZE != peer_len) {
			return false;
		}
#endif
	} else {
		assert(0 == peer_len);
#ifdef NODEBUG
		if (0 != peer_len) {
			return false;
		}
#endif
	}

	return true;
}


/*
 * reset_counters resets the send and receive message counters, and
 * resets the sent/received data counters.
 */
void
reset_counters(struct schannel *sch)
{
	assert(NULL != sch);
#ifdef NODEBUG
	if (NULL == sch) {
		return;
	}
#endif

	sch->rdata = 0;
	sch->sdata = 0;
	sch->rctr = 0;
	sch->sctr = 0;
}


/*
 * initialise_schannel gets the schannel into an appropriate initial
 * state.
 */
void
initialise_schannel(struct schannel *sch)
{
	assert(NULL != sch);
#ifdef NODEBUG
	if (NULL == sch) {
		return;
	}
#endif

	reset_counters(sch);
	sch->sockfd = -1;
	sch->ready = false;
	sch->kexip = false;
}


/*
 * generate_keypair creates a pair of Curve25519 keys for the key
 * exchange.
 */
bool
generate_keypair(uint8_t *sk, uint8_t *pk)
{
	int	rv = -1;

	assert(NULL != sk);
	assert(NULL != pk);
#ifdef NODEBUG
	if ((NULL == sk) || (NULL == pk)) {
		return false;
	}
#endif

	rv = crypto_box_keypair(pk, sk);
	if (0 == rv) {
		rv = crypto_box_keypair(pk+crypto_box_PUBLICKEYBYTES,
					sk+crypto_box_SECRETKEYBYTES);
	}

	if (0 == rv) {
		return true;
	}
	return false;
}


/*
 * sign_kex performs a signature on the key exchange if the signer is
 * not NULL.
 */
bool
sign_kex(uint8_t *public, uint8_t *signer, uint8_t *kex_sig)
{
	uint8_t	sig[2*crypto_sign_BYTES];
	int	rv = -1;

	if (NULL == signer) {
		return true;
	}

	assert(NULL != signer);
	assert(NULL != public);
	assert(NULL != kex_sig);
#ifdef NODEBUG
	if ((NULL == signer) || (NULL == public) || (NULL == kex_sig)) {
		return false;
	}
#endif
	
	rv = crypto_sign(sig, NULL, public, SCHANNEL_KEX_PUBLEN, signer);
	if (0 == rv) {
		memcpy(kex_sig, sig, crypto_sign_BYTES);
		return true;
	}
	return false;
}


/*
 * verify_kex verifies the signature on the public key if peer is
 * non-NULL.
 */
bool
verify_kex(uint8_t *peer_public, uint8_t *peer)
{
	if (NULL == peer) {
		return true;
	}
	
	assert(NULL != peer);
	assert(NULL != peer_public);
#ifdef NODEBUG
	if ((NULL == peer) || (NULL == peer_public)) {
		return false;
	}
#endif 

	if (0 != crypto_sign_verify_detached(peer_public+SCHANNEL_KEX_PUBLEN,
					     peer_public, SCHANNEL_KEX_PUBLEN,
					     peer))
	{
		return false;
	}
	
	return true;
}


/*
 * do_kex performs the local key exchange computation. The dialer
 * parameter determines the ordering of the keys; it should be true
 * for the side that initiated the key exchange, and false for the
 * other side.
 */
bool
do_kex(struct schannel *sch, uint8_t *sk, uint8_t *pk, bool dialer)
{
	size_t	rpoff = 0; /* receive public offset */
	size_t  spoff = 0; /* send public offset */
	size_t	rsoff = 0; /* receive secret offset */
	size_t	ssoff = 0; /* send secret offset */
	int	rv = -1;

	assert(NULL != sch);
	assert(NULL != sk);
	assert(NULL != pk);
#ifdef NODEBUG
	if ((NULL == sch) || (NULL == sk) || (NULL == pk)) {
		return false;
	}
#endif

	/*
	 * If this is called from the client, the first key is used as
	 * the send key, and the second key is used as the receive key.
	 * The server reverses this: the first key is used as the receive
	 * key and the second key is used as the send key.
	 */
	if (dialer) {
		rpoff = crypto_box_PUBLICKEYBYTES;
		rsoff = crypto_box_SECRETKEYBYTES;
	} else {
		spoff = crypto_box_PUBLICKEYBYTES;
		ssoff = crypto_box_SECRETKEYBYTES;
	}

	rv = crypto_box_beforenm(sch->skey, pk+spoff, sk+ssoff);
	if (0 == rv) {
		rv = crypto_box_beforenm(sch->rkey, pk+rpoff, sk+rsoff);
	}

	sodium_memzero(sk, SCHANNEL_KEX_PRVLEN);
	if (0 != rv) {
		return false;
	}

	reset_counters(sch);
	return true;
}


/*
 * schannel_dial sets up a key exchange with the remote host. This function
 * is called by the initiating client that connects to some server. The
 * socket descriptor must be a valid TCP connection. If signer or peer is
 * not NULL, their respective length variable must be appropriately sized.
 * See schannel/schannel.h and the validate_keys function for further details.
 */
bool
schannel_dial(struct schannel *sch, int sock, uint8_t *signer,
	      size_t signer_len, uint8_t *peer, size_t peer_len)
{
	uint8_t	private[SCHANNEL_KEX_PRVLEN];
	uint8_t public[SCHANNEL_KEX_PUBLEN+SCHANNEL_SIGSIZE];
	uint8_t peer_public[SCHANNEL_KEX_PUBLEN+SCHANNEL_SIGSIZE];
	ssize_t	datalen = 0;

	assert(NULL != sch);
	assert(-1 != sock);
#ifdef NODEBUG
	if ((NULL == sch) || (-1 == sock)) {
		return false;
	}
#endif

	if (!validate_keys(signer, signer_len, peer, peer_len)) {
		return false;
	}

	initialise_schannel(sch);
	if (-1 == sodium_mlock(private, SCHANNEL_KEX_PRVLEN)) {
		return false;
	}

	if (!generate_keypair(private, public)) {
		sodium_munlock(private, SCHANNEL_KEX_PRVLEN);
		return false;
	}

	if (!sign_kex(public, signer, public+SCHANNEL_KEX_PUBLEN)) {
		sodium_munlock(private, SCHANNEL_KEX_PRVLEN);
		return false;
	}
	
	datalen = send(sock, public, SCHANNEL_KEX_PUBLEN+SCHANNEL_SIGSIZE, 0);
	if (SCHANNEL_KEX_PUBLEN+SCHANNEL_SIGSIZE != datalen) {
		sodium_munlock(private, SCHANNEL_KEX_PRVLEN);
		return false;
	}

	datalen = recv(sock, peer_public, SCHANNEL_KEX_PUBLEN+
	    SCHANNEL_SIGSIZE, 0);
	if (SCHANNEL_KEX_PUBLEN+SCHANNEL_SIGSIZE != datalen) {
		sodium_munlock(private, SCHANNEL_KEX_PRVLEN);
		return false;
	}
	
	if (!verify_kex(peer_public, peer)) {
		sodium_munlock(private, SCHANNEL_KEX_PRVLEN);
		return false;
	}

	if (-1 == sodium_mlock(sch->skey, SCHANNEL_KEYSIZE)) {
		sodium_munlock(private, SCHANNEL_KEX_PRVLEN);
		return false;
	}

	if (-1 == sodium_mlock(sch->rkey, SCHANNEL_KEYSIZE)) {
		sodium_munlock(private, SCHANNEL_KEX_PRVLEN);
		sodium_munlock(sch->skey, SCHANNEL_KEYSIZE);
		return false;
	}

	if (!do_kex(sch, private, peer_public, true)) {
		sodium_munlock(private, SCHANNEL_KEX_PRVLEN);
		sodium_munlock(sch->skey, SCHANNEL_KEYSIZE);
		sodium_munlock(sch->rkey, SCHANNEL_KEYSIZE);
		return false;
	}
	
	sodium_munlock(private, SCHANNEL_KEX_PRVLEN);
	sch->sockfd = sock;
	sch->ready = true;
	return sch->ready;
}


/*
 * schannel_listen sets up a key exchange with the remote host. This function
 * is called by some server listening on a TCP port. The same conditions that
 * apply to schannel_dial apply here.
 */
bool
schannel_listen(struct schannel *sch, int sock, uint8_t *signer,
		size_t signer_len, uint8_t *peer, size_t peer_len)
{
	uint8_t	private[SCHANNEL_KEX_PRVLEN];
	uint8_t public[SCHANNEL_KEX_PUBLEN+SCHANNEL_SIGSIZE];
	uint8_t peer_public[SCHANNEL_KEX_PUBLEN+SCHANNEL_SIGSIZE];
	ssize_t	datalen = 0;

	assert(NULL != sch);
	assert(-1 != sock);
#ifdef NODEBUG
	if ((NULL == sch) || (-1 == sock)) {
		return false;
	}
#endif

	if (!validate_keys(signer, signer_len, peer, peer_len)) {
		return false;
	}

	initialise_schannel(sch);
	if (-1 == sodium_mlock(private, SCHANNEL_KEX_PRVLEN)) {
		return false;
	}

	if (!generate_keypair(private, public)) {
		sodium_munlock(private, SCHANNEL_KEX_PRVLEN);
		return false;
	}

	datalen = recv(sock, peer_public, SCHANNEL_KEX_PUBLEN+
	    SCHANNEL_SIGSIZE, 0);
	if (SCHANNEL_KEX_PUBLEN+SCHANNEL_SIGSIZE != datalen) {
		sodium_munlock(private, SCHANNEL_KEX_PRVLEN);
		return false;
	}
	
	if (!verify_kex(peer_public, peer)) {
		sodium_munlock(private, SCHANNEL_KEX_PRVLEN);
		return false;
	}

	if (!sign_kex(public, signer, public+SCHANNEL_KEX_PUBLEN)) {
		sodium_munlock(private, SCHANNEL_KEX_PRVLEN);
		return false;
	}
	
	datalen = send(sock, public, SCHANNEL_KEX_PUBLEN+
	    SCHANNEL_SIGSIZE, 0);
	if (SCHANNEL_KEX_PUBLEN+SCHANNEL_SIGSIZE != datalen) {
		sodium_munlock(private, SCHANNEL_KEX_PRVLEN);
		return false;
	}

	if (-1 == sodium_mlock(sch->skey, SCHANNEL_KEYSIZE)) {
		sodium_munlock(private, SCHANNEL_KEX_PRVLEN);
		return false;
	}

	if (-1 == sodium_mlock(sch->rkey, SCHANNEL_KEYSIZE)) {
		sodium_munlock(private, SCHANNEL_KEX_PRVLEN);
		sodium_munlock(sch->skey, SCHANNEL_KEYSIZE);
		return false;
	}

	if (!do_kex(sch, private, peer_public, false)) {
		sodium_munlock(private, SCHANNEL_KEX_PRVLEN);
		sodium_munlock(sch->skey, SCHANNEL_KEYSIZE);
		sodium_munlock(sch->rkey, SCHANNEL_KEYSIZE);
		return false;
	}
	
	sodium_munlock(private, SCHANNEL_KEX_PRVLEN);
	sch->sockfd = sock;
	sch->ready = true;

	return sch->ready;
}


/* This defines the current message format version. */
#define SCHANNEL_CURRENT_VERSION		1
/* This defines the size of the message structure sans payload. */
#define SCHANNEL_MESSAGE_OVERHEAD		66


/*
 * _schannel_send handles the mechanics of sending out a message with the
 * given message type. It is used to prevent duplication of code among the
 * shutdown, send, and rekey functions.
 */
bool
_schannel_send(struct schannel *sch, uint8_t mtype, uint8_t *buf, size_t buflen)
{
	struct schan_message	m;
	uint32_t		mlen = 0;
	int			rv = -1;

	assert(buflen > 0);
	assert(buflen <= SCHANNEL_BUFSIZE);
#ifdef NODEBUG
	if ((buflen == 0) || (buflen > SCHANNEL_BUFSIZE)) {
		return false;
	}
#endif

	sch->sctr++;
	memcpy(m.payload, buf, buflen);
	m.payload_length = htonl((uint32_t)buflen);
	m.mtype = mtype;
	m.seqno = htonl(sch->sctr);
	m.version = SCHANNEL_CURRENT_VERSION;

	randombytes_buf(sch->buf, crypto_secretbox_NONCEBYTES);
	rv = crypto_secretbox_easy(sch->buf+crypto_secretbox_NONCEBYTES,
				   (uint8_t *)&m,
				   buflen+SCHANNEL_MESSAGE_OVERHEAD,
				   sch->buf, sch->skey);
	sodium_memzero((uint8_t *)&m, SCHANNEL_MESSAGE_OVERHEAD+buflen);
	if (0 == rv) {
		sch->sdata += (uint64_t)buflen+SCHANNEL_MESSAGE_OVERHEAD;
		mlen = htonl((uint32_t)(buflen+SCHANNEL_OVERHEAD));
		rv = send(sch->sockfd, &mlen, sizeof(mlen), 0);
		if (rv == sizeof(mlen)) {
			mlen = (uint32_t)(buflen+SCHANNEL_OVERHEAD);
			rv = send(sch->sockfd, sch->buf, mlen, 0);
		}
	}

	if (rv == (int)mlen) {
		return true;
	}
	return false;
}


/*
 * schannel_send marks the message with a sequence number, encrypts and
 * authenticates it, then sends it out over the channel.
 */
bool
schannel_send(struct schannel *sch, uint8_t *buf, size_t buflen)
{
	return _schannel_send(sch, SCHANNEL_NORMAL, buf, buflen);
}


/*
 * unpack_message decrypts the channel buffer into the message structure,
 * performing some validation checks on the contents, and ensuring that
 * the fields are in useful condition (i.e. calling ntohl where
 * appropriate).
 */
bool
unpack_message(struct schannel *sch, struct schan_message *m, uint32_t mlen)
{
	int	rv = -1;

	assert(NULL != m);
	assert(NULL != sch);
#ifdef NODEBUG
	if ((NULL == m) || (NULL == sch)) {
		return false;
	}
#endif

	mlen -= crypto_secretbox_NONCEBYTES;

	rv = crypto_secretbox_open_easy((uint8_t *)m,
	    sch->buf+crypto_secretbox_NONCEBYTES,
	    mlen, sch->buf, sch->rkey);
	sodium_memzero(sch->buf, mlen);
	if (-1 == rv) {
		return false;
	}

	m->seqno = ntohl(m->seqno);
	if (m->seqno <= sch->rctr) {
		return false;
	}
	sch->rctr = m->seqno;
	m->payload_length = ntohl(m->payload_length);
	return true;
}


/*
 * schannel_recv_kex handles reading a peer kye from the message payload,
 * generating and sending a new key pair, and computing the shared key.
 */
bool
schannel_recv_kex(struct schannel *sch, struct schan_message *m)
{
	uint8_t	sk[SCHANNEL_KEX_PRVLEN];
	uint8_t pk[SCHANNEL_KEX_PUBLEN];
	bool	ok = false;

	assert(NULL != sch);
	assert(NULL != m);
	assert(false == sch->kexip);
	assert(true == sch->ready);
#ifdef NODEBUG
	if ((NULL == sch) || (NULL == m)) {
		return false;
	}

	if (sch->kexip || !sch->ready) {
		return false;
	}
#endif

	if (SCHANNEL_KEX_PUBLEN != m->payload_length) {
		return false;
	}

	if (-1 == sodium_mlock(sk, SCHANNEL_KEX_PRVLEN)) {
		return false;
	}

	if (!generate_keypair(sk, pk)) {
		sodium_munlock(sk, SCHANNEL_KEX_PRVLEN);
		return false;
	}

	if (!_schannel_send(sch, SCHANNEL_KEX, pk, SCHANNEL_KEX_PUBLEN)) {
		sodium_munlock(sk, SCHANNEL_KEX_PRVLEN);
		return false;
	}

	ok = do_kex(sch, sk, m->payload, false);	
	sodium_memzero(m->payload, m->payload_length);
	sodium_munlock(sk, SCHANNEL_KEX_PRVLEN);
	
	if (ok) {
		reset_counters(sch);
	}

	return ok;
}


/*
 * schannel_recv receives a new message from the network. The message
 * is authenticated, decrypted, and its sequence number is checked.
 * The function will return one of SCHANNEL_NORMAL or SCHANNEL_SHUTDOWN
 * for successfully decrypted messages, or SCHANNEL_INVALID_MESSAGE if
 * the message was invalid.
 */
uint8_t
schannel_recv(struct schannel *sch, uint8_t *buf, size_t *buflen)
{
	struct schan_message	m;
	uint32_t		mlen;
	int			rv = -1;

	assert(NULL != buf);
	assert(NULL != buflen);
	assert(sch->ready);
#ifdef NODEBUG
	if ((NULL == buf) || (NULL == buflen) || (!sch->ready)) {
		return SCHANNEL_INVALID_MESSAGE;
	}
#endif

	rv = recv(sch->sockfd, &mlen, sizeof(mlen), 0);
	if (sizeof(mlen) != rv) {
		return SCHANNEL_INVALID_MESSAGE;
	}

	mlen = ntohl(mlen);	
	if (mlen <= SCHANNEL_OVERHEAD) {
		return SCHANNEL_INVALID_MESSAGE;
	} else if (mlen >= (SCHANNEL_BUFSIZE+SCHANNEL_OVERHEAD)) {
		return SCHANNEL_INVALID_MESSAGE;
	} else if (mlen > ((*buflen)+SCHANNEL_OVERHEAD)) {
		return SCHANNEL_INVALID_MESSAGE;
	}

	rv = recv(sch->sockfd, sch->buf, mlen, 0);
	if (rv != (int)mlen) {
		return SCHANNEL_INVALID_MESSAGE;
	}

	if (!unpack_message(sch, &m, mlen)) {
		return SCHANNEL_INVALID_MESSAGE;
	}

	switch (m.mtype) {
	/* The following three types of messages are perfectly valid. */
	case SCHANNEL_NORMAL:
		if (sch->kexip) {
			sodium_memzero(&m.payload, m.payload_length);
			return SCHANNEL_INVALID_MESSAGE;
		}
		sch->rdata += (m.payload_length + SCHANNEL_OVERHEAD);
		break;
	case SCHANNEL_SHUTDOWN:
		sodium_memzero(&m.payload, m.payload_length);
		return m.mtype;
	case SCHANNEL_KEX:
		if (sch->kexip) {
			break;
		}

		if (!schannel_recv_kex(sch, &m)) {
		    return SCHANNEL_INVALID_MESSAGE;
		}
		return m.mtype;
	default:
		sodium_memzero(&m.payload, m.payload_length);
		return SCHANNEL_INVALID_MESSAGE;	
	}

	*buflen = (size_t)m.payload_length;
	memcpy(buf, m.payload, m.payload_length);
	sodium_memzero(m.payload, m.payload_length);
	return m.mtype;
}


/*
 * schannel_close sends a shutdown message over the secure channel
 * and zeroises the secure channel.
 */
bool
schannel_close(struct schannel *sch)
{
	uint8_t			buf[1];
	bool			ok = false;

	assert(NULL != sch);
	assert(sch->ready == true);
#ifdef NODEBUG
	if (NULL == sch) {
		return false;
	}

	if (!sch->ready) {
		return false;
	}
#endif

	buf[0] = 0;
	ok = _schannel_send(sch, SCHANNEL_SHUTDOWN, buf, 1);
	schannel_zero(sch);
	return ok;
}


/*
 * schannel_zero closes the channel socket and wipes the shared keys.
 */
void
schannel_zero(struct schannel *sch)
{
	assert(NULL != sch);
#ifdef NODEBUG
	if (NULL == sch) {
		return;
	}
#endif

	if (-1 != sch->sockfd) {
		close(sch->sockfd);
	}

	sodium_memzero(sch->skey, SCHANNEL_KEYSIZE);
	sodium_memzero(sch->rkey, SCHANNEL_KEYSIZE);
	if (sch->ready) {
		sodium_munlock(sch->skey, SCHANNEL_KEYSIZE);
		sodium_munlock(sch->skey, SCHANNEL_KEYSIZE);
	}
	initialise_schannel(sch);
}


/*
 * schannel_rekey iniiates a rekeying operation.
 */
bool
schannel_rekey(struct schannel *sch)
{
	uint8_t			private[SCHANNEL_KEX_PRVLEN];
	uint8_t			public[SCHANNEL_KEX_PUBLEN];
	uint8_t			peer[SCHANNEL_KEX_PUBLEN];
	size_t			peerlen = SCHANNEL_KEX_PUBLEN;
	bool			ok = false;

	assert(NULL != sch);
	assert(true == sch->ready);
#ifdef NODEBUG
	if ((NULL == sch) || (!sch->ready)) {
		return false;
	}
#endif

	if (-1 == sodium_mlock(private, SCHANNEL_KEX_PRVLEN)) {
		return false;
	}

	if (!generate_keypair(private, public)) {
		sodium_munlock(private, SCHANNEL_KEX_PRVLEN);
		return false;
	}
	
	if (!_schannel_send(sch, SCHANNEL_KEX, public, SCHANNEL_KEX_PUBLEN)) {
		sodium_munlock(private, SCHANNEL_KEX_PRVLEN);
		return false;
	}

	sch->kexip = true;
	if (SCHANNEL_KEX != schannel_recv(sch, peer, &peerlen)) {
		sodium_munlock(private, SCHANNEL_KEX_PRVLEN);
		return false;
	}

	ok = do_kex(sch, private, peer, sch->kexip);
	sodium_munlock(private, SCHANNEL_KEX_PRVLEN);
	sch->kexip = false;
	return ok;
}
