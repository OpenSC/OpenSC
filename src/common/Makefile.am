MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
EXTRA_DIST = Makefile.mak

noinst_LTLIBRARIES = libcompat.la
noinst_PROGRAMS = compat_getopt_main
dist_noinst_DATA = \
	README.compat_getopt ChangeLog.compat_getopt \
	LICENSE.compat_getopt compat_getopt.txt \
	compat_getopt_main.c \
	README.compat_strlcpy compat_strlcpy.3

libcompat_la_SOURCES = \
	compat_dummy.c \
	compat_strlcat.h compat_strlcat.c \
	compat_strlcpy.h compat_strlcpy.c \
	compat_getpass.h compat_getpass.c \
	compat_getopt.h compat_getopt.c \
	simclist.c simclist.h

compat_getopt_main_LDADD = libcompat.la

