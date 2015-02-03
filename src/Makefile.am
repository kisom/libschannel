AM_CFLAGS=	-Wall -Wextra -pedantic -Wshadow -Wpointer-arith -Wcast-align
AM_CFLAGS+=	-Wwrite-strings -Wmissing-prototypes -Wmissing-declarations
AM_CFLAGS+=	-Wnested-externs -Winline -Wno-long-long  -Wunused-variable
AM_CFLAGS+=	-Wstrict-prototypes -Werror
AM_LDFLAGS=	-L.
CC=		clang

lib_LTLIBRARIES = libschannel.la
nobase_include_HEADERS = schannel/schannel.h

libschannel_la_SOURCES = schannel.c

analyze:
	$(CC) $(AM_CFLAGS) --analyze *.c
