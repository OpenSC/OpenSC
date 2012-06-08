# Process this file with automake to create Makefile.in

MAINTAINERCLEANFILES = Makefile.in

EXTRA_DIST = Makefile.mak

AM_CFLAGS = $(OPTIONAL_OPENSSL_CFLAGS) $(OPTIONAL_READLINE_CFLAGS)
INCLUDES = -I$(top_srcdir)/src -I$(top_srcdir)/src/common -I$(top_builddir)/src/include
LIBS = $(top_builddir)/src/libopensc/libopensc.la $(top_builddir)/src/common/libcompat.la

lib_LTLIBRARIES = libsmm-local.la

libsmm_local_la_SOURCES = 
libsmm_local_la_LIBADD = ../libopensc/libopensc.la
libsmm_local_la_LDFLAGS = -version-info @OPENSC_LT_CURRENT@:@OPENSC_LT_REVISION@:@OPENSC_LT_AGE@

# noinst_HEADERS = sm.h
