AC_INIT(src/mfc_extract_keys.c)

PACKAGE=mfc_extract_keys
VERSION=0.2

AM_INIT_AUTOMAKE($PACKAGE, $VERSION)

AC_PROG_CXX

AC_CHECK_HEADERS([inttypes.h stdlib.h string.h unistd.h])

AC_TYPE_SIZE_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

AC_FUNC_MALLOC
AC_CHECK_FUNCS([memmove])

AC_OUTPUT(Makefile src/Makefile)
