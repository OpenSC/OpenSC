# Process this file with automake to create Makefile.in

MAINTAINERCLEANFILES = Makefile.in

INCLUDES = @CFLAGS_OPENSC@

lib_LTLIBRARIES = libscam.la

if HAVE_LDAP
LDAP_LIB = @LIBSCLDAP@
endif
if HAVE_SSL
SSL_LIB = @LIBCRYPTO@
endif

SRC = scam.c scam.h p15_eid.c p15_ldap.c

libscam_la_SOURCES = $(SRC)
libscam_la_LDFLAGS = -avoid-version
libscam_la_LIBADD = @LIBOPENSC@ $(LDAP_LIB) $(SSL_LIB) \
	../scrandom/libscrandom.la
