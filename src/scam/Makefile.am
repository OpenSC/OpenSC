# Process this file with automake to create Makefile.in

MAINTAINERCLEANFILES = Makefile.in

lib_LTLIBRARIES = libscam.la

libscam_la_SOURCES = \
	scam.c cert_support.c \
	p15_eid.c p15_ldap.c
libscam_la_LDFLAGS = -version-info @OPENSC_LT_CURRENT@:@OPENSC_LT_REVISION@:@OPENSC_LT_AGE@
libscam_la_LIBADD = @LIBOPENSC@ @LIBCRYPTO@ @LIBSCLDAP@ \
	../scrandom/libscrandom.la

noinst_HEADERS = scam.h cert_support.h
