# Process this file with automake to create Makefile.in

includedir = @includedir@/opensc

MAINTAINERCLEANFILES = Makefile.in

AM_CFLAGS = -DSC_PKCS15_PROFILE_DIRECTORY=\"$(pkgdatadir)\"
AM_LDFLAGS = @LIBOPENSC@

PROFILES = \
	cyberflex.profile \
	flex.profile \
	gpk.profile \
	miocos.profile \
	etoken.profile \
	jcop.profile \
	oberthur.profile \
	starcos.profile \
	pkcs15.profile 

EXTRA_DIST = $(PROFILES) Makefile.mak

lib_LTLIBRARIES = libpkcs15init.la

libpkcs15init_la_SOURCES = \
	pkcs15-lib.c profile.c keycache.c \
	pkcs15-gpk.c pkcs15-miocos.c pkcs15-cflex.c \
	pkcs15-etoken.c pkcs15-jcop.c pkcs15-starcos.c \
	pkcs15-oberthur.c

libpkcs15init_la_LDFLAGS = -version-info @OPENSC_LT_CURRENT@:@OPENSC_LT_REVISION@:@OPENSC_LT_AGE@

include_HEADERS = pkcs15-init.h
noinst_HEADERS = profile.h keycache.h
pkgdata_DATA = $(PROFILES)
