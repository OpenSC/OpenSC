# Process this file with automake to create Makefile.in

include_HEADERS = scldap.h

if HAVE_LDAP
LDAP_LTLIB = libscldap.la
LDAP_PROGRAM = test-ldap
else
LDAP_LTLIB = 
LDAP_PROGRAM = 
endif

lib_LTLIBRARIES = $(LDAP_LTLIB)
libscldap_la_SOURCES = scldap.c scldap.h
libscldap_la_LIBADD = @LIBLDAP@ @LIBSCCONF@

noinst_PROGRAMS = $(LDAP_PROGRAM)

test_ldap_SOURCES = test-ldap.c
test_ldap_LDFLAGS = @LDFLAGS@ @LIBSCLDAP@
