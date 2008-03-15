MAINTAINERCLEANFILES = Makefile.in
DISTCLEANFILES = opensc.conf 

SUFFIXES = .in

dist_noinst_DATA = opensc.conf.in
nodist_noinst_DATA = opensc.conf

.in:
	sed -e "s|@pkgdatadir[@]|$(pkgdatadir)|g" < $^ > $@

sysconf_DATA=#required in order to create dir
install-exec-hook:	install-sysconfDATA opensc.conf
	if [ -f $(DESTDIR)$(sysconfdir)/opensc.conf ]; then \
		$(INSTALL_DATA) $(srcdir)/opensc.conf $(DESTDIR)$(sysconfdir)/opensc.conf.new; \
	else \
		$(INSTALL_DATA) $(srcdir)/opensc.conf $(DESTDIR)$(sysconfdir)/opensc.conf; \
	fi
