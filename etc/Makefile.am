MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
DISTCLEANFILES = opensc.conf 

SUFFIXES = .in

dist_noinst_DATA = opensc.conf.in
nodist_noinst_DATA = opensc.conf

.in:
	sed \
		-e 's|@pkgdatadir[@]|$(pkgdatadir)|g' \
		-e 's|@DEFAULT_PCSC_PROVIDER[@]|$(DEFAULT_PCSC_PROVIDER)|g' \
		< $^ > $@

sysconf_DATA=#required in order to create dir
install-exec-hook:	install-sysconfDATA opensc.conf
	if [ -f "$(DESTDIR)$(sysconfdir)/opensc.conf" ]; then \
		$(INSTALL_DATA) opensc.conf "$(DESTDIR)$(sysconfdir)/opensc.conf.new"; \
	else \
		$(INSTALL_DATA) opensc.conf "$(DESTDIR)$(sysconfdir)/opensc.conf"; \
	fi
