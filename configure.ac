AC_PREREQ([2.59])
AC_INIT([libschannel],
        [1.0], 
        [kyle@tyrfingr.is],
        [libschannel],
        [])
AM_INIT_AUTOMAKE([1.11 foreign])
AC_CONFIG_SRCDIR([src/schannel/schannel.h])
AC_CHECK_HEADERS
AC_CANONICAL_HOST
AC_CONFIG_FILES([Makefile src/Makefile tools/Makefile doc/Makefile]) # test/Makefile])
AC_CONFIG_MACRO_DIR([m4])

LT_INIT
AC_PROG_CC
AC_PROG_INSTALL
AM_PROG_CC_C_O

AC_SEARCH_LIBS([sodium_init], [sodium], [], [AC_MSG_ERROR("libsodium cannot be found.")])

AC_OUTPUT
