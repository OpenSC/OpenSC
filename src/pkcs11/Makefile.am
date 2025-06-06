include $(top_srcdir)/win32/ltrc.inc

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
EXTRA_DIST = Makefile.mak versioninfo-pkcs11.rc versioninfo-pkcs11-spy.rc opensc-pkcs11.pc.in opensc.module.in opensc-pkcs11.dll.manifest

if ENABLE_SHARED
lib_LTLIBRARIES = opensc-pkcs11.la pkcs11-spy.la
else
noinst_LTLIBRARIES = libopensc-pkcs11.la
endif

AM_CPPFLAGS = -I$(top_srcdir)/src

OPENSC_PKCS11_INC = sc-pkcs11.h pkcs11.h pkcs11-opensc.h
OPENSC_PKCS11_SRC = pkcs11-global.c pkcs11-session.c pkcs11-object.c misc.c slot.c \
	mechanism.c openssl.c framework-pkcs15.c \
	framework-pkcs15init.c debug.c pkcs11.exports \
	pkcs11-display.c pkcs11-display.h
OPENSC_PKCS11_CFLAGS = \
	$(OPENPACE_CFLAGS) $(OPTIONAL_OPENSSL_CFLAGS) $(OPENSC_PKCS11_PTHREAD_CFLAGS)
OPENSC_PKCS11_LIBS = \
	$(top_builddir)/src/libopensc/libopensc.la \
	$(top_builddir)/src/common/libscdl.la \
	$(top_builddir)/src/common/libcompat.la \
	$(OPENPACE_LIBS) $(OPTIONAL_OPENSSL_LIBS) $(PTHREAD_LIBS)
if WIN32
OPENSC_PKCS11_LIBS += -lshlwapi
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = opensc-pkcs11.pc
DISTCLEANFILES = $(pkgconfig_DATA)
if ENABLE_P11KIT
p11kitdir = $(P11_SYSTEM_CONFIG_MODULES)
p11kit_DATA = opensc.module
DISTCLEANFILES += $(p11kit_DATA)
endif

opensc_pkcs11_la_SOURCES = $(OPENSC_PKCS11_SRC) $(OPENSC_PKCS11_INC)
opensc_pkcs11_la_CFLAGS = $(OPENSC_PKCS11_CFLAGS)
opensc_pkcs11_la_LIBADD = $(OPENSC_PKCS11_LIBS)
opensc_pkcs11_la_LDFLAGS = $(AM_LDFLAGS) \
	-export-symbols "$(srcdir)/pkcs11.exports" \
	-module -shared -avoid-version -no-undefined

libopensc_pkcs11_la_SOURCES = $(OPENSC_PKCS11_SRC) $(OPENSC_PKCS11_INC)
libopensc_pkcs11_la_CFLAGS = $(OPENSC_PKCS11_CFLAGS)
libopensc_pkcs11_la_LIBADD = $(OPENSC_PKCS11_LIBS)
libopensc_pkcs11_la_LDFLAGS = $(AM_LDFLAGS)

pkcs11_spy_la_SOURCES = pkcs11-spy.c pkcs11-display.c pkcs11-display.h pkcs11.exports
pkcs11_spy_la_CFLAGS = $(OPTIONAL_OPENSSL_CFLAGS) $(OPENSC_PKCS11_PTHREAD_CFLAGS)
pkcs11_spy_la_LIBADD = \
	$(top_builddir)/src/common/libpkcs11.la \
	$(top_builddir)/src/common/libscdl.la \
	$(top_builddir)/src/common/libcompat.la \
	$(OPTIONAL_OPENSSL_LIBS) $(PTHREAD_LIBS)
pkcs11_spy_la_LDFLAGS = $(AM_LDFLAGS) \
	-export-symbols "$(srcdir)/pkcs11.exports" \
	-module -shared -avoid-version -no-undefined

if WIN32
opensc_pkcs11_la_SOURCES += versioninfo-pkcs11.rc
pkcs11_spy_la_SOURCES += versioninfo-pkcs11-spy.rc
pkcs11_spy_la_LIBADD += -lshlwapi
endif

if WIN32
install-exec-hook:
	$(MKDIR_P) "$(DESTDIR)$(libdir)"
	for l in opensc-pkcs11.dll pkcs11-spy.dll; do \
		mv "$(DESTDIR)$(libdir)/$$l" "$(DESTDIR)$(bindir)/$$l"; \
	done

uninstall-hook:
	for l in opensc-pkcs11.dll pkcs11-spy.dll; do \
		rm -f "$(DESTDIR)$(bindir)/$$l"; \
	done
else
# see http://wiki.cacert.org/wiki/Pkcs11TaskForce
install-exec-hook:
	cd $(DESTDIR)$(libdir) && \
	  rm -f "onepin-opensc-pkcs11$(DYN_LIB_EXT)" && \
	  $(LN_S) "opensc-pkcs11$(DYN_LIB_EXT)" "onepin-opensc-pkcs11$(DYN_LIB_EXT)"
	$(MKDIR_P) "$(DESTDIR)$(pkcs11dir)"
	for l in opensc-pkcs11$(DYN_LIB_EXT) onepin-opensc-pkcs11$(DYN_LIB_EXT) pkcs11-spy$(DYN_LIB_EXT); do \
		rm -f "$(DESTDIR)$(pkcs11dir)/$$l"; \
		$(LN_S) ../$$l "$(DESTDIR)$(pkcs11dir)/$$l"; \
	done

uninstall-hook:
	for l in opensc-pkcs11$(DYN_LIB_EXT) onepin-opensc-pkcs11$(DYN_LIB_EXT) pkcs11-spy$(DYN_LIB_EXT); do \
		rm -f "$(DESTDIR)$(pkcs11dir)/$$l"; \
	done
	rm -df "$(DESTDIR)$(pkcs11dir)" || true
	rm -f "$(DESTDIR)$(libdir)/onepin-opensc-pkcs11$(DYN_LIB_EXT)"
endif

TIDY_FLAGS = $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) $(OPENSC_PKCS11_CFLAGS)
TIDY_FILES = \
			 pkcs11-global.c pkcs11-session.c pkcs11-object.c slot.c \
			 mechanism.c openssl.c framework-pkcs15.c \
			 framework-pkcs15init.c debug.c

check-local:
	if [ -x "$(CLANGTIDY)" ]; then clang-tidy -config='' --checks='$(TIDY_CHECKS)' --warnings-as-errors='$(TIDY_CHECKS)' -header-filter=.* $(addprefix $(srcdir)/,$(TIDY_FILES)) -- $(TIDY_FLAGS); fi
