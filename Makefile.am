ACLOCAL_AMFLAGS = -I m4

MAINTAINERCLEANFILES = \
	config.log config.status \
	$(srcdir)/Makefile.in \
	$(srcdir)/config.h.in $(srcdir)/config.h.in~ $(srcdir)/configure \
	$(srcdir)/install-sh $(srcdir)/ltmain.sh $(srcdir)/missing \
	$(srcdir)/depcomp $(srcdir)/aclocal.m4 \
	$(srcdir)/config.guess $(srcdir)/config.sub \
	$(srcdir)/m4/ltsugar.m4 $(srcdir)/m4/libtool.m4 \
	$(srcdir)/m4/ltversion.m4 $(srcdir)/m4/lt~obsolete.m4 \
	$(srcdir)/m4/ltoptions.m4 \
	$(srcdir)/packaged
EXTRA_DIST = Makefile.mak svnignore

SUBDIRS = etc src win32 doc MacOSX

dist_noinst_SCRIPTS = bootstrap
dist_noinst_DATA = README \
	solaris/Makefile solaris/README solaris/checkinstall.in \
	solaris/opensc.conf-dist solaris/pkginfo.in solaris/proto
dist_doc_DATA = NEWS

Generate-ChangeLog:
	rm -f ChangeLog.tmp "$(srcdir)/ChangeLog"
	test -n "$(SVN)" -a -n "$(XSLTPROC)"
	if test -d "$(top_srcdir)/.svn"; then \
		$(SVN) --verbose --xml log "$(top_srcdir)" | \
			$(XSLTPROC) --nonet --stringparam linelen 75 \
			--stringparam groupbyday no \
			--stringparam include-rev no \
			"$(top_srcdir)/doc/svn2cl.xsl" - > ChangeLog.tmp; \
	else \
		echo "Warning: Unable to generate ChangeLog from none svn checkout" >&2; \
		echo > ChangeLog.tmp; \
	fi
	mv ChangeLog.tmp "$(srcdir)/ChangeLog"
	( cd "$(srcdir)" && autoreconf -ivf )
