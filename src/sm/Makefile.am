# Process this file with automake to create Makefile.in

MAINTAINERCLEANFILES = Makefile.in
EXTRA_DIST = Makefile.mak

noinst_LTLIBRARIES = libsmiso.la libsmeac.la libsmidprime.la

noinst_HEADERS = \
		 sm-iso-internal.h \
		 sm-iso.h \
		 sm-eac.h \
		 sm-idprime.h

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

libsmidprime_la_SOURCES = sm-idprime.c sm-idprime.h
# NOTE: libsmiso.la is intentionally not in LIBADD here -- it's already
# pulled into libopensc via libsmeac.la, and a libtool convenience library
# (noinst_LTLIBRARIES) fully embeds its LIBADD members rather than linking
# them lazily, so adding it again causes duplicate-symbol errors when both
# libsmeac.la and libsmidprime.la are linked into the same target.
libsmidprime_la_LIBADD = $(OPENSSL_LIBS)
libsmidprime_la_CFLAGS = $(OPENSSL_CFLAGS) -I$(top_srcdir)/src
