include $(top_srcdir)/win32/ltrc.inc

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in $(srcdir)/versioninfo-pkcs11.rc $(srcdir)/versioninfo-pkcs11-spy.rc
EXTRA_DIST = Makefile.mak versioninfo-pkcs11.rc.in versioninfo-pkcs11-spy.rc.in

dist_noinst_SCRIPTS = opensc_pkcs11_install.js
lib_LTLIBRARIES = opensc-pkcs11.la pkcs11-spy.la onepin-opensc-pkcs11.la

AM_CFLAGS = $(OPTIONAL_OPENSSL_CFLAGS) $(PTHREAD_CFLAGS)
AM_CPPFLAGS = -I$(top_srcdir)/src

OPENSC_PKCS11_INC = sc-pkcs11.h pkcs11.h pkcs11-opensc.h
OPENSC_PKCS11_SRC = pkcs11-global.c pkcs11-session.c pkcs11-object.c misc.c slot.c \
	mechanism.c openssl.c framework-pkcs15.c \
	framework-pkcs15init.c debug.c opensc-pkcs11.exports \
	pkcs11-display.c pkcs11-display.h
OPENSC_PKCS11_LIBS = \
	$(top_builddir)/src/libopensc/libopensc.la \
	$(top_builddir)/src/common/libscdl.la \
	$(top_builddir)/src/common/libcompat.la \
	$(OPTIONAL_OPENSSL_LIBS) $(PTHREAD_LIBS)

opensc_pkcs11_la_SOURCES = $(OPENSC_PKCS11_SRC) $(OPENSC_PKCS11_INC)
opensc_pkcs11_la_LIBADD = $(OPENSC_PKCS11_LIBS)
opensc_pkcs11_la_LDFLAGS = $(AM_LDFLAGS) \
	-export-symbols "$(srcdir)/opensc-pkcs11.exports" \
	-module -shared -avoid-version -no-undefined

onepin_opensc_pkcs11_la_SOURCES = $(OPENSC_PKCS11_SRC) $(OPENSC_PKCS11_INC)
onepin_opensc_pkcs11_la_CFLAGS = -DMODULE_APP_NAME=\"onepin-opensc-pkcs11\"
onepin_opensc_pkcs11_la_LIBADD = $(OPENSC_PKCS11_LIBS)
onepin_opensc_pkcs11_la_LDFLAGS = $(AM_LDFLAGS) \
        -export-symbols "$(srcdir)/opensc-pkcs11.exports" \
        -module -shared -avoid-version -no-undefined

pkcs11_spy_la_SOURCES = pkcs11-spy.c pkcs11-display.c pkcs11-display.h pkcs11-spy.exports
pkcs11_spy_la_LIBADD = \
	$(top_builddir)/src/common/libpkcs11.la \
	$(top_builddir)/src/common/libscdl.la \
	$(OPTIONAL_OPENSSL_LIBS)
pkcs11_spy_la_LDFLAGS = $(AM_LDFLAGS) \
	-export-symbols "$(srcdir)/pkcs11-spy.exports" \
	-module -shared -avoid-version -no-undefined

if WIN32
opensc_pkcs11_la_SOURCES += versioninfo-pkcs11.rc
pkcs11_spy_la_SOURCES += versioninfo-pkcs11-spy.rc
endif

jar-dir:
	if test ! -d jar-dir ; then mkdir jar-dir ; fi

pkcs11-jar: jar-dir
	cp .libs/*.so jar-dir
	cp opensc_pkcs11_install.js jar-dir
	signtool -Z"opensc-pkcs11.jar" -i"opensc_pkcs11_install.js" \
		 -k"testcert" jar-dir

if WIN32
install-exec-hook:
	$(MKDIR_P) "$(DESTDIR)$(libdir)"
	for l in opensc-pkcs11.dll pkcs11-spy.dll; do \
		mv "$(DESTDIR)$(libdir)/$$l" "$(DESTDIR)$(bindir)/$$l"; \
	done
else
# see http://wiki.cacert.org/wiki/Pkcs11TaskForce
if CYGWIN
PKCS11_SUFFIX=.dll
else
PKCS11_SUFFIX=.so
endif
install-exec-hook:
	$(MKDIR_P) "$(DESTDIR)$(pkcs11dir)"
	for l in opensc-pkcs11$(PKCS11_SUFFIX) onepin-opensc-pkcs11$(PKCS11_SUFFIX) pkcs11-spy$(PKCS11_SUFFIX); do \
		rm -f "$(DESTDIR)$(pkcs11dir)/$$l"; \
		$(LN_S) ../$$l "$(DESTDIR)$(pkcs11dir)/$$l"; \
	done

endif
