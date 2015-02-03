AM_CFLAGS=	-Wall -Wextra -pedantic -Wshadow -Wpointer-arith -Wcast-align
AM_CFLAGS+=	-Wwrite-strings -Wmissing-prototypes -Wmissing-declarations
AM_CFLAGS+=	-Wnested-externs -Winline -Wno-long-long  -Wunused-variable
AM_CFLAGS+=	-Wstrict-prototypes -Werror -I../src/
AM_LDFLAGS=	-L../src
CC=		clang

bin_PROGRAMS = schannel_nc schannel_keygen
schannel_nc_SOURCES = nc.c
schannel_nc_LDADD = ../src/.libs/libschannel.a

schannel_keygen_SOURCES = keygen.c
schannel_keygen_LDADD = ../src/.libs/libschannel.a

../src/.libs/libschannel.a:
	cd ../src && make
analyze:
	$(CC) $(AM_CFLAGS) --analyze *.c
