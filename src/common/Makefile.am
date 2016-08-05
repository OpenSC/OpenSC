MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
EXTRA_DIST = Makefile.mak

noinst_LTLIBRARIES = libcompat.la libpkcs11.la libscdl.la
noinst_PROGRAMS = compat_getopt_main
dist_noinst_DATA = \
	README.compat_getopt ChangeLog.compat_getopt \
	LICENSE.compat_getopt compat_getopt.txt \
	compat_getopt_main.c \
	README.compat_strlcpy compat_strlcpy.3

AM_CPPFLAGS = -I$(top_srcdir)/src

libcompat_la_SOURCES = \
	compat_dummy.c \
	compat_strlcat.h compat_strlcat.c \
	compat_strlcpy.h compat_strlcpy.c \
	compat_strnlen.h compat_strnlen.c \
	compat_getpass.h compat_getpass.c \
	compat_getopt.h compat_getopt.c \
	compat_report_rangecheckfailure.c \
	compat___iob_func.c \
	simclist.c simclist.h

compat_getopt_main_LDADD = libcompat.la

libpkcs11_la_SOURCES = libpkcs11.c libpkcs11.h

libscdl_la_SOURCES = libscdl.c libscdl.h
