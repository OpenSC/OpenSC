# Process this file with automake to create Makefile.in

includedir = @includedir@/opensc

AM_CFLAGS = -I$(top_srcdir)/src/common

MAINTAINERCLEANFILES = Makefile.in
DISTCLEANFILES = lex-parse.c
EXTRA_DIST = Makefile.mak README.scconf lex-parse.l

include_HEADERS = scconf.h
noinst_HEADERS = internal.h

lib_LTLIBRARIES = libscconf.la
libscconf_la_SOURCES = scconf.c parse.c write.c sclex.c $(top_srcdir)/src/common/strlcpy.c
libscconf_la_LDFLAGS = -version-info @OPENSC_LT_CURRENT@:@OPENSC_LT_REVISION@:@OPENSC_LT_AGE@

noinst_PROGRAMS = test-conf

test_conf_SOURCES = test-conf.c
test_conf_LDADD = libscconf.la
