# Process this file with automake to create Makefile.in

MAINTAINERCLEANFILES = Makefile.in

EXTRA_DIST = Makefile.mak smm-local.dll.manifest

AM_CFLAGS = $(OPTIONAL_OPENSSL_CFLAGS) $(OPTIONAL_READLINE_CFLAGS)
AM_CPPFLAGS = -I$(top_srcdir)/src -I$(top_srcdir)/src/common -I$(top_builddir)/src/include
LIBS = $(top_builddir)/src/sm/libsm.la \
	$(top_builddir)/src/libopensc/libopensc.la \
	$(top_builddir)/src/common/libcompat.la

if ENABLE_OPENSSL
if ENABLE_SHARED
lib_LTLIBRARIES = libsmm-local.la
endif
endif

libsmm_local_la_SOURCES = smm-local.c sm-module.h \
	sm-global-platform.c sm-cwa14890.c \
	sm-card-authentic.c sm-card-iasecc.c \
	smm-local.exports
libsmm_local_la_LIBADD = $(OPTIONAL_OPENSSL_LIBS)
libsmm_local_la_LDFLAGS = -module -shared -no-undefined -version-info @OPENSC_LT_CURRENT@:@OPENSC_LT_REVISION@:@OPENSC_LT_AGE@

# noinst_HEADERS = sm.h
