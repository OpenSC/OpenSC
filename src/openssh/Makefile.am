# Process this file with automake to create Makefile.in

INCLUDES = -I$(top_srcdir)/src/libopensc
LDFLAGS = @LDFLAGS@ @LIBCRYPTO@ \
	$(top_srcdir)/src/libopensc/libopensc.la

bin_PROGRAMS = opensc-ssh

opensc_ssh_SOURCES = opensc-ssh.c
