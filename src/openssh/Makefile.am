# Process this file with automake to create Makefile.in

INCLUDES = @CFLAGS_OPENSC@
LDFLAGS = @LDFLAGS@ @LIBCRYPTO@ @LIBOPENSC@

EXTRA_DIST = openssh-3.0.2p1-patch.diff

if HAVE_SSL
bin_PROGRAMS = opensc-ssh
else
bin_PROGRAMS = 
endif

opensc_ssh_SOURCES = opensc-ssh.c
opensc_ssh_LDADD = @GETOPTSRC@
