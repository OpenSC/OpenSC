# Process this file with automake to create Makefile.in

MAINTAINERCLEANFILES = Makefile.in

INCLUDES = @CFLAGS_OPENSC@
LDFLAGS = @LDFLAGS@ @LIBCRYPTO@ @LIBOPENSC@

if HAVE_SSL
bin_PROGRAMS = opensc-ssh
endif

opensc_ssh_SOURCES = opensc-ssh.c
opensc_ssh_LDADD = @GETOPTSRC@
