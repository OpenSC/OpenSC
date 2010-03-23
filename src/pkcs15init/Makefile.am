include $(top_srcdir)/win32/ltrc.inc

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
EXTRA_DIST = Makefile.mak

noinst_LTLIBRARIES = libpkcs15init.la
noinst_HEADERS = profile.h pkcs15-init.h pkcs15-oberthur.h
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
INCLUDES = -I$(top_srcdir)/src

libpkcs15init_la_SOURCES = \
	pkcs15-lib.c profile.c \
	pkcs15-westcos.c \
	pkcs15-gpk.c pkcs15-miocos.c pkcs15-cflex.c \
	pkcs15-cardos.c pkcs15-jcop.c pkcs15-starcos.c \
	pkcs15-setcos.c pkcs15-incrypto34.c pkcs15-muscle.c \
	pkcs15-asepcos.c pkcs15-rutoken.c pkcs15-entersafe.c \
	pkcs15-rtecp.c pkcs15-myeid.c \
	pkcs15-oberthur.c pkcs15-oberthur-awp.c
