MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
DISTCLEANFILES = opensc.conf 

SUFFIXES = .in

dist_noinst_DATA = opensc.conf.in
nodist_noinst_DATA = opensc.conf	# For Windows MSVC build

# Make sure we build this every time
# as there is no dependency for this.
# Can be removed if MSVC is not requried.
force:
opensc.conf: opensc.conf.in force

.in:
	sed \
		-e 's|@pkgdatadir[@]|$(pkgdatadir)|g' \
		-e 's|@DEFAULT_PCSC_PROVIDER[@]|$(DEFAULT_PCSC_PROVIDER)|g' \
		< $< > $@

sysconf_DATA=#required in order to create dir
install-exec-hook:	install-sysconfDATA opensc.conf
	if [ -f "$(DESTDIR)$(sysconfdir)/opensc.conf" ]; then \
		$(INSTALL_DATA) opensc.conf "$(DESTDIR)$(sysconfdir)/opensc.conf.new"; \
	else \
		$(INSTALL_DATA) opensc.conf "$(DESTDIR)$(sysconfdir)/opensc.conf"; \
	fi
