# Process this file with automake to create Makefile.in

bundledir = @BUNDLEDIR@/opensc
libdir = @libdir@/opensc

MAINTAINERCLEANFILES = Makefile.in

EXTRA_DIST = Makefile.mak engine_pkcs11.def test_engine.sh \
	$(engine_opensc_la_SOURCES) $(engine_pkcs11_la_SOURCES) 

if HAVE_ENGINE
lib_LTLIBRARIES = engine_opensc.la engine_pkcs11.la
endif

OPENSSL_CFLAGS = \
	-DOPENSSL_THREADS -D_REENTRANT -DDSO_DLFCN -DHAVE_DLFCN_H \
	-DOPENSSL_NO_KRB5 -DL_ENDIAN -DTERMIO -DENGINE_DYNAMIC_SUPPORT \
	-DSHA1_ASM -DMD5_ASM -DRMD160_ASM

engine_opensc_la_SOURCES = hw_opensc.c engine_opensc.c engine_opensc.h
engine_opensc_la_CFLAGS = $(OPENSSL_CFLAGS)
engine_opensc_la_LIBADD = @ENGINE_LINK@ @LIBOPENSC@

engine_opensc_la_LDFLAGS = @OPENSSL_LDFLAGS@ -module -avoid-version

engine_pkcs11_la_SOURCES = \
	hw_pkcs11.c engine_pkcs11.c engine_pkcs11.h \
	p11_attr.c p11_cert.c p11_err.c p11_key.c \
	p11_load.c p11_misc.c p11_rsa.c p11_slot.c \
	pkcs11-internal.h
engine_pkcs11_la_CFLAGS = $(OPENSSL_CFLAGS)
engine_pkcs11_la_LIBADD = @ENGINE_LINK@ ../pkcs11/libpkcs11.la
engine_pkcs11_la_LDFLAGS = @OPENSSL_LDFLAGS@ -module -avoid-version

install-exec-local: install-libLTLIBRARIES
if HAVE_ENGINE
if HAVE_BUNDLES
	-${top_srcdir}/macos/libtool-bundle $(DESTDIR)$(libdir)/engine_opensc.so \
		$(DESTDIR)$(bundledir)/
	-${top_srcdir}/macos/libtool-bundle $(DESTDIR)$(libdir)/engine_pkcs11.so \
		$(DESTDIR)$(bundledir)/
endif
endif

uninstall-local: uninstall-libLTLIBRARIES
if HAVE_ENGINE
if HAVE_BUNDLES
	rm -rf $(DESTDIR)$(bundledir)/engine_opensc.bundle/
	rm -rf $(DESTDIR)$(bundledir)/engine_pkcs11.bundle/
endif
endif
