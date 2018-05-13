#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.62])
AC_INIT([encryptify], [0.1.1], [robert@rescrv.net])
AM_INIT_AUTOMAKE(foreign dist-bzip2)
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AC_CONFIG_SRCDIR([encryptify.c])
AC_CONFIG_HEADERS([config.h])
AC_PROG_CC
AS_IF([make -h 2>/dev/null | grep no-print-directory > /dev/null], [make_no_print=yes])
AM_CONDITIONAL([MAKE_NO_PRINT_DIRECTORY], [test x"${make_no_print}" != x])
AC_CHECK_FUNC([strlcpy],[BSDLIB=],[BSDLIB=-lbsd])
AC_SUBST([BSDLIB], [$BSDLIB])
AC_CHECK_HEADER([bsd/string.h],[AC_DEFINE([HAVE_BSD_STRING_H],[1],[Define to 1 if you have the <bsd/string.h> header file.])],,)
AC_CHECK_HEADER([readpassphrase.h],[AC_DEFINE([HAVE_READPASSPHRASE_H],[1],[Define to 1 if you have the <readpassphrase.h> header file.])],,)
AC_CHECK_HEADER([bsd/readpassphrase.h],[AC_DEFINE([HAVE_BSD_READPASSPHRASE_H],[1],[Define to 1 if you have the <bsd/readpassphrase.h> header file.])],,)
AC_CHECK_HEADER([libutil.h],[AC_DEFINE([HAVE_LIBUTIL_H],[1],[Define to 1 if you have the <libutil.h> header file.])],,)
AC_CHECK_HEADER([bsd/libutil.h],[AC_DEFINE([HAVE_BSD_LIBUTIL_H],[1],[Define to 1 if you have the <bsd/libutil.h> header file.])],,)
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
