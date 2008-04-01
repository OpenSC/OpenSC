AUTOMAKE_OPTIONS = foreign 1.10
ACLOCAL_AMFLAGS = -I aclocal

MAINTAINERCLEANFILES = \
	config.log config.status \
	$(srcdir)/Makefile.in \
	$(srcdir)/config.h.in $(srcdir)/config.h.in~ $(srcdir)/configure \
	$(srcdir)/install-sh $(srcdir)/ltmain.sh $(srcdir)/missing \
	$(srcdir)/depcomp $(srcdir)/aclocal.m4 \
	$(srcdir)/config.guess $(srcdir)/config.sub \
	$(srcdir)/packaged
EXTRA_DIST = Makefile.mak svnignore

SUBDIRS = aclocal etc src win32 doc

dist_noinst_SCRIPTS = bootstrap
dist_noinst_DATA = README \
	solaris/Makefile solaris/README solaris/checkinstall.in \
	solaris/opensc.conf-dist solaris/pkginfo.in solaris/proto
dist_doc_DATA = NEWS

# Allow detection of packaged tarball
dist-hook:
	echo > "$(distdir)/packaged"

distcheck-hook:
	@eval $$(sed -e '/^PACKAGE_VERSION=/!d' -e 's/-svn//' -e 's,^,configure_,' "$(srcdir)/configure"); \
	eval $$(sed -e '/^ \(FILE\|PRODUCT\)VERSION /!d' -e 's,^ ,version_rc_,' -e 's, ,=,' -e 's/,/./g' "$(srcdir)/win32/version.rc"); \
	eval $$(sed -e '/^#define VERSION /!d' -e 's,^#define ,winconfig_h_,' -e 's, ,=,' "$(srcdir)/src/include/winconfig.h"); \
	err=$$( \
		test "$${configure_PACKAGE_VERSION}.0" = "$${version_rc_FILEVERSION}" || echo "configure PACKAGE_VERSION $${configure_PACKAGE_VERSION} != win32/version.rc FILEVERSION $${version_rc_FILEVERSION}"; \
		test "$${configure_PACKAGE_VERSION}.0" = "$${version_rc_PRODUCTVERSION}" || echo "configure PACKAGE_VERSION $${configure_PACKAGE_VERSION} != win32/version.rc PRODUCTVERSION $${version_rc_PRODUCTVERSION}"; \
		test "$${configure_PACKAGE_VERSION}" = "$${winconfig_h_VERSION}" || echo "configure PACKAGE_VERSION $${configure_PACKAGE_VERSION} != src/include/winconfig.h VERSION $${winconfig_h_VERSION}"; \
	); \
	echo "$${err}"; \
	test -z "$${err}"
