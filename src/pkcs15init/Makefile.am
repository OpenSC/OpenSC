# Process this file with automake to create Makefile.in

includedir = @includedir@/opensc

MAINTAINERCLEANFILES = Makefile.in

CFLAGS = @CFLAGS@ -DSC_PKCS15_PROFILE_DIRECTORY=\"$(pkgdatadir)\"
LDFLAGS = @LDFLAGS@ @LIBOPENSC@

PROFILES = \
	flex.profile \
	flex_so.profile \
	flex_onepin.profile \
	gpk.profile \
	miocos.profile \
	etoken.profile \
	pkcs15-small.profile \
	pkcs15.profile

EXTRA_DIST = $(PROFILES) Makefile.mak

lib_LTLIBRARIES = libpkcs15init.la

libpkcs15init_la_SOURCES = \
	pkcs15-lib.c profile.c \
	pkcs15-gpk.c pkcs15-miocos.c pkcs15-cflex.c \
	pkcs15-etoken.c
libpkcs15init_la_LDFLAGS = -version-info @OPENSC_LT_CURRENT@:@OPENSC_LT_REVISION@:@OPENSC_LT_AGE@

include_HEADERS = pkcs15-init.h
noinst_HEADERS = profile.h
pkgdata_DATA = $(PROFILES)
