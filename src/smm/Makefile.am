# Process this file with automake to create Makefile.in

MAINTAINERCLEANFILES = Makefile.in

EXTRA_DIST = Makefile.mak

AM_CFLAGS = $(OPTIONAL_OPENSSL_CFLAGS) $(OPTIONAL_READLINE_CFLAGS)
AM_CPPFLAGS = -I$(top_srcdir)/src -I$(top_srcdir)/src/common -I$(top_builddir)/src/include
LIBS = $(top_builddir)/src/libsm/libsm.la \
	$(top_builddir)/src/libopensc/libopensc.la \
	$(top_builddir)/src/common/libcompat.la

lib_LTLIBRARIES = libsmm-local.la

libsmm_local_la_SOURCES = smm-local.c sm-module.h \
	sm-global-platform.c sm-cwa14890.c \
	sm-card-authentic.c sm-card-iasecc.c \
	smm-local.exports
libsmm_local_la_LIBADD = $(OPTIONAL_OPENSSL_LIBS) ../libopensc/libopensc.la
libsmm_local_la_LDFLAGS = -version-info @OPENSC_LT_CURRENT@:@OPENSC_LT_REVISION@:@OPENSC_LT_AGE@

# noinst_HEADERS = sm.h
