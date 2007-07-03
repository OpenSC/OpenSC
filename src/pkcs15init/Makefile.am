# Process this file with automake to create Makefile.in

includedir = @includedir@/opensc

MAINTAINERCLEANFILES = Makefile.in

AM_CFLAGS = -DSC_PKCS15_PROFILE_DIRECTORY=\"$(pkgdatadir)\" $(OPENSSL_CFLAGS) -I$(top_srcdir)/src/common
AM_LDFLAGS = @LIBOPENSC@ $(OPENSSL_LIBS)

PROFILES = \
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
	asepcos.profile
	

EXTRA_DIST = $(PROFILES) Makefile.mak

lib_LTLIBRARIES = libpkcs15init.la

libpkcs15init_la_SOURCES = \
	pkcs15-lib.c profile.c keycache.c \
	pkcs15-gpk.c pkcs15-miocos.c pkcs15-cflex.c \
	pkcs15-cardos.c pkcs15-jcop.c pkcs15-starcos.c \
	pkcs15-oberthur.c pkcs15-setcos.c pkcs15-incrypto34.c \
	pkcs15-muscle.c pkcs15-asepcos.c

libpkcs15init_la_LDFLAGS = -version-info @OPENSC_LT_CURRENT@:@OPENSC_LT_REVISION@:@OPENSC_LT_AGE@

include_HEADERS = pkcs15-init.h
noinst_HEADERS = profile.h keycache.h
pkgdata_DATA = $(PROFILES)
