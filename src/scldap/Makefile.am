# Process this file with automake to create Makefile.in

includedir = @includedir@/opensc

MAINTAINERCLEANFILES = Makefile.in

include_HEADERS = scldap.h

if HAVE_LDAP
lib_LTLIBRARIES = libscldap.la
noinst_PROGRAMS = test-ldap
endif

libscldap_la_SOURCES = scldap.c scldap.h
libscldap_la_LDFLAGS = -version-info @OPENSC_LT_CURRENT@:@OPENSC_LT_REVISION@:@OPENSC_LT_AGE@
libscldap_la_LIBADD = @LIBSCCONF@ @LIBLDAP@

test_ldap_SOURCES = test-ldap.c
test_ldap_LDFLAGS = @LDFLAGS@ libscldap.la
