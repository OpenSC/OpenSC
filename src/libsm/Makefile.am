# Process this file with automake to create Makefile.in

MAINTAINERCLEANFILES = Makefile.in
EXTRA_DIST = Makefile.mak

noinst_LTLIBRARIES = libsm.la
noinst_HEADERS = sm-common.h

AM_CFLAGS = $(OPTIONAL_OPENSSL_CFLAGS) $(OPTIONAL_READLINE_CFLAGS)
AM_CPPFLAGS = -I$(top_srcdir)/src -I$(top_builddir)/src/include

libsm_la_SOURCES = sm-common.c sm-common.h
