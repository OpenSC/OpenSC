# Process this file with automake to create Makefile.in

MAINTAINERCLEANFILES = Makefile.in

INCLUDES = @CFLAGS_OPENSC@ -DSC_PKCS15_PROFILE_DIRECTORY=\"$(pkgdatadir)\"
LDFLAGS = @LDFLAGS@ @LIBOPENSC@ @LIBCRYPTO@

EXTRA_DIST = flex.profile gpk.profile miocos.profile pkcs15.profile

if HAVE_SSL
lib_LTLIBRARIES	= libpkcs15init.la
endif

libpkcs15init_la_SOURCES = \
		  pkcs15-lib.c profile.c \
		  pkcs15-gpk.c
# pkcs15-miocos.c pkcs15-cflex.c

include_HEADERS = pkcs15-init.h
noinst_HEADERS = profile.h
pkgdata_DATA = flex.profile gpk.profile miocos.profile pkcs15.profile
