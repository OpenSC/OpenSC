# Process this file with automake to create Makefile.in

includedir = ${prefix}/include/opensc

MAINTAINERCLEANFILES = Makefile.in

INCLUDES = @CFLAGS_OPENSC@ -DSC_PKCS15_PROFILE_DIRECTORY=\"$(pkgdatadir)\"
LDFLAGS = @LDFLAGS@ @LIBOPENSC@

EXTRA_DIST = flex.profile gpk.profile miocos.profile pkcs15.profile

lib_LTLIBRARIES	= libpkcs15init.la

libpkcs15init_la_SOURCES = \
		  pkcs15-lib.c profile.c \
		  pkcs15-gpk.c pkcs15-miocos.c pkcs15-cflex.c \
		  pkcs15-etoken.c

include_HEADERS = pkcs15-init.h
noinst_HEADERS = profile.h
pkgdata_DATA = flex.profile gpk.profile miocos.profile pkcs15.profile
