# Process this file with automake to create Makefile.in

MAINTAINERCLEANFILES = Makefile.in
EXTRA_DIST = Makefile.mak

noinst_LTLIBRARIES = libsmiso.la libsmeac.la

noinst_HEADERS = \
		 sm-iso-internal.h \
		 sm-iso.h \
		 sm-eac.h

if ENABLE_OPENSSL
noinst_LTLIBRARIES += libsm.la
endif
noinst_HEADERS += sm-common.h

AM_CFLAGS = $(OPTIONAL_OPENSSL_CFLAGS) $(OPTIONAL_READLINE_CFLAGS)
AM_CPPFLAGS = -I$(top_srcdir)/src -I$(top_builddir)/src/include

libsm_la_SOURCES = sm-common.c sm-common.h
libsm_la_LIBADD = $(OPENSSL_LIBS)
libsm_la_CFLAGS = $(OPENSSL_CFLAGS)

libsmiso_la_SOURCES = sm-iso.c

libsmeac_la_SOURCES = sm-eac.c
libsmeac_la_LIBADD = $(OPENPACE_LIBS) $(OPENSSL_LIBS) libsmiso.la
libsmeac_la_CFLAGS = $(OPENPACE_CFLAGS) $(OPENSSL_CFLAGS) -I$(top_srcdir)/src
