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

LDFLAGS = @LIBOPENSC@ @LIBSCRANDOM@ $(LDAP_LIB) $(SSL_LIB) $(SCIDI_LIB)
EXTRAINC = $(SCIDI_INC)

SRC = scam.c scam.h p15_eid.c p15_ldap.c $(SCIDI_SRC)

libscam_la_SOURCES = $(SRC)
libscam_la_LDFLAGS = -module -avoid-version
libscam_la_CFLAGS = $(EXTRAINC)
