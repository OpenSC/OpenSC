EXTRA_DIST = Makefile.mak

libsceac_la_SOURCES = sc-eac.c rw_sfid.c
libsceac_la_LIBADD = $(OPENPACE_LIBS) $(OPENSSL_LIBS) $(top_builddir)/src/libisosm/libisosm.la
libsceac_la_CFLAGS = $(OPENPACE_CFLAGS) $(OPENSSL_CFLAGS) -I$(top_srcdir)/src

noinst_LTLIBRARIES = libsceac.la

noinst_HEADERS = \
		 sslutil.h \
		 rw_sfid.h \
		 sc-eac.h
