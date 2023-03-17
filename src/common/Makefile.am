MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
EXTRA_DIST = Makefile.mak

noinst_LTLIBRARIES = libcompat.la libpkcs11.la libscdl.la
noinst_PROGRAMS = compat_getopt_main
dist_noinst_DATA = \
	README.compat_getopt ChangeLog.compat_getopt \
	LICENSE.compat_getopt compat_getopt.txt \
	compat_getopt_main.c \
	README.compat_strlcpy compat_strlcpy.3
noinst_HEADERS = compat_strlcat.h compat_strlcpy.h compat_strnlen.h compat_getpass.h compat_getopt.h simclist.h libpkcs11.h libscdl.h compat_overflow.h

AM_CPPFLAGS = -I$(top_srcdir)/src

libcompat_la_SOURCES = \
	compat_dummy.c \
	compat_strlcat.c \
	compat_strlcpy.c \
	compat_strnlen.c \
	compat_getpass.c \
	compat_getopt.c \
	compat_report_rangecheckfailure.c \
	compat___iob_func.c \
	compat_overflow.c \
	simclist.c

compat_getopt_main_LDADD = libcompat.la

libpkcs11_la_SOURCES = libpkcs11.c

libscdl_la_SOURCES = libscdl.c
libscdl_la_LIBADD = $(LDL_LIBS)

TIDY_FLAGS = $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS)
TIDY_FILES = \
	compat_dummy.c \
	compat_strlcat.h compat_strlcat.c \
	compat_strlcpy.h compat_strlcpy.c \
	compat_strnlen.h compat_strnlen.c \
	compat_getpass.h compat_getpass.c \
	compat_getopt.h compat_getopt.c \
	compat_report_rangecheckfailure.c \
	compat___iob_func.c \
	compat_overflow.h compat_overflow.c \
	simclist.c simclist.h \
	libpkcs11.c libscdl.c

check-local:
	if [ -x "$(CLANGTIDY)" ]; then clang-tidy -config='' --checks='$(TIDY_CHECKS)' -header-filter=.* $(addprefix $(srcdir)/,$(TIDY_FILES)) -- $(TIDY_FLAGS); fi
