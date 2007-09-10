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

distcheck-hook:
	@eval $$(sed -e '/^PACKAGE_VERSION=/!d' -e 's,^,configure_,' configure); \
	eval $$(sed -e '/^ \(FILE\|PRODUCT\)VERSION /!d' -e 's,^ ,version_rc_,' -e 's, ,=,' -e 's/,/./g' win32/version.rc); \
	eval $$(sed -e '/^#define VERSION /!d' -e 's,^#define ,winconfig_h_,' -e 's, ,=,' src/include/winconfig.h); \
	err=$$( \
		test "$${configure_PACKAGE_VERSION}.0" = "$${version_rc_FILEVERSION}" || echo "configure PACKAGE_VERSION $${configure_PACKAGE_VERSION} != win32/version.rc FILEVERSION $${version_rc_FILEVERSION}"; \
		test "$${configure_PACKAGE_VERSION}.0" = "$${version_rc_PRODUCTVERSION}" || echo "configure PACKAGE_VERSION $${configure_PACKAGE_VERSION} != win32/version.rc PRODUCTVERSION $${version_rc_PRODUCTVERSION}"; \
		test "$${configure_PACKAGE_VERSION}" = "$${winconfig_h_VERSION}" || echo "configure PACKAGE_VERSION $${configure_PACKAGE_VERSION} != src/include/winconfig.h VERSION $${winconfig_h_VERSION}"; \
	); \
	echo "$${err}"; \
	test -z "$${err}"
