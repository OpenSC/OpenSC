# Process this file with automake to create Makefile.in

SUBDIRS = . aclocal docs etc macos src win32

EXTRA_DIST = ANNOUNCE CodingStyle PAM_README QUICKSTART README \
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
