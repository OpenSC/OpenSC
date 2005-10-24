# Process this file with automake to create Makefile.in

SUBDIRS = . aclocal etc man src win32
DIST_SUBDIRS = . aclocal doc etc man src win32

EXTRA_DIST = README \
	bootstrap Makefile.mak depcomp \
	solaris/Makefile solaris/README solaris/checkinstall.in \
	solaris/opensc.conf-dist solaris/pkginfo.in solaris/proto

MAINTAINERCLEANFILES = \
	Makefile.in config.h.in configure \
	install-sh ltmain.sh missing mkinstalldirs \
	compile depcomp config.log config.status \
	config.guess config.sub acinclude.m4 aclocal.m4

DEPCLEANFILES = config.log configure

AUTOMAKE_OPTIONS = foreign 1.5
ACLOCAL_AMFLAGS = -I aclocal
