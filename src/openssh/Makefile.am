# Process this file with automake to create Makefile.in

INCLUDES = -I../libopensc
LDFLAGS = @LDFLAGS@ @LIBCRYPTO@ \
	../libopensc/libopensc.la

EXTRA_DIST = openssh-3.0.2p1-patch.diff

if HAVE_SSL
bin_PROGRAMS = opensc-ssh
else
bin_PROGRAMS = 
endif

opensc_ssh_SOURCES = opensc-ssh.c
