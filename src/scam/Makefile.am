# Process this file with automake to create Makefile.in

MAINTAINERCLEANFILES = Makefile.in

INCLUDES = @CFLAGS_PCSC@ @CFLAGS_OPENSC@

lib_LTLIBRARIES = libscam.la

if HAVE_LDAP
LDAP_LIB = @LIBSCLDAP@
endif
if HAVE_SSL
SSL_LIB = @LIBCRYPTO@
endif

LDFLAGS = @LIBOPENSC@ $(LDAP_LIB) $(SSL_LIB)

SRC = scam.c scam.h p15_eid.c p15_ldap.c

libscam_la_SOURCES = $(SRC) ../scrandom/scrandom.c 
libscam_la_LDFLAGS = -module -avoid-version
libscam_la_CFLAGS = $(EXTRAINC)
