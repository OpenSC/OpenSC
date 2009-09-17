include $(top_srcdir)/win32/ltrc.inc

MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in $(srcdir)/versioninfo.rc
CLEANFILES = versioninfo.rc
EXTRA_DIST = Makefile.mak

lib_LTLIBRARIES = libpkcs15init.la
openscinclude_HEADERS = pkcs15-init.h
noinst_HEADERS = profile.h keycache.h
dist_pkgdata_DATA = \
	cyberflex.profile \
	flex.profile \
	gpk.profile \
	miocos.profile \
	cardos.profile \
	incrypto34.profile \
	jcop.profile \
	oberthur.profile \
	starcos.profile \
	setcos.profile \
	pkcs15.profile \
	muscle.profile \
	rutoken.profile \
	asepcos.profile \
	entersafe.profile \
	rutoken_ecp.profile \
	westcos.profile \
	myeid.profile

AM_CPPFLAGS = -DSC_PKCS15_PROFILE_DIRECTORY=\"$(pkgdatadir)\"
AM_CFLAGS = $(OPTIONAL_OPENSSL_CFLAGS) $(LTLIB_CFLAGS)
INCLUDES = -I$(top_srcdir)/src/common -I$(top_builddir)/src/include

libpkcs15init_la_SOURCES = \
	pkcs15-lib.c profile.c keycache.c \
    pkcs15-westcos.c \
	pkcs15-gpk.c pkcs15-miocos.c pkcs15-cflex.c \
	pkcs15-cardos.c pkcs15-jcop.c pkcs15-starcos.c \
	pkcs15-oberthur.c pkcs15-setcos.c pkcs15-incrypto34.c \
	pkcs15-muscle.c pkcs15-asepcos.c pkcs15-rutoken.c \
	pkcs15-entersafe.c pkcs15-rtecp.c pkcs15-myeid.c \
	pkcs15init.exports
if WIN32
libpkcs15init_la_SOURCES += versioninfo.rc
else
dist_noinst_DATA = versioninfo.rc
endif
libpkcs15init_la_LIBADD = $(OPTIONAL_OPENSSL_LIBS) $(LTLIB_LIBS) \
	$(top_builddir)/src/libopensc/libopensc.la \
	$(top_builddir)/src/scconf/libscconf.la \
	$(top_builddir)/src/common/libcompat.la
libpkcs15init_la_LDFLAGS = $(AM_LDFLAGS) \
	-version-info @OPENSC_LT_CURRENT@:@OPENSC_LT_REVISION@:@OPENSC_LT_AGE@ \
	-export-symbols "$(srcdir)/pkcs15init.exports" \
	-no-undefined

versioninfo.rc:
	sed 's/@@FILE_DESCRIPTION@@/OpenSC Core Library/g' \
		"$(top_builddir)/win32/versioninfo.rc.in" > versioninfo.rc

if WIN32
# def file required for MS users to build library
mylibdir=$(libdir)
mylib_DATA=.libs/@WIN_LIBPREFIX@pkcs15init-@OPENSC_LT_OLDEST@.dll.def
.libs/@WIN_LIBPREFIX@pkcs15init-@OPENSC_LT_OLDEST@.dll.def:	libpkcs15init.la
endif
