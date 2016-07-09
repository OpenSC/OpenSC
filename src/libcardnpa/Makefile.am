EXTRA_DIST = Makefile.mak cardnpa.exports

libcardnpa_la_SOURCES = card-npa.c
libcardnpa_la_LIBADD = $(OPENPACE_LIBS) \
					   $(top_builddir)/src/common/libcompat.la \
					   $(top_builddir)/src/libsceac/libsceac.la \
					   $(top_builddir)/src/libopensc/libopensc.la
libcardnpa_la_CFLAGS = -I$(top_srcdir)/src $(OPENPACE_CFLAGS) $(OPENSSL_CFLAGS)
libcardnpa_la_LDFLAGS = $(AM_LDFLAGS) \
						-version-info @OPENSC_LT_CURRENT@:@OPENSC_LT_REVISION@:@OPENSC_LT_AGE@ \
						-export-symbols "$(srcdir)/cardnpa.exports" \
						-no-undefined

lib_LTLIBRARIES = libcardnpa.la

noinst_HEADERS = card-npa.h
