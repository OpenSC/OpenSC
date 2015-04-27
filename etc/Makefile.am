MAINTAINERCLEANFILES = $(srcdir)/Makefile.in $(srcdir)/opensc.conf.win
DISTCLEANFILES = opensc.conf opensc.conf.win

EXTRA_DIST = Makefile.mak

SUFFIXES = .in

dist_noinst_DATA = opensc.conf.in opensc.conf.win.in
nodist_noinst_DATA = opensc.conf opensc.conf.win # For Windows MSVC build

# Make sure we build this every time
# as there is no dependency for this.
# Can be removed if MSVC is not requried.
force:
opensc.conf: opensc.conf.in force

.in:
	@sed \
		-e 's|@pkgdatadir[@]|$(pkgdatadir)|g' \
		-e 's|@libdir[@]|$(libdir)|g' \
		-e 's|@DEFAULT_PCSC_PROVIDER[@]|$(DEFAULT_PCSC_PROVIDER)|g' \
		-e 's|@DEFAULT_SM_MODULE[@]|$(DEFAULT_SM_MODULE)|g' \
		-e 's|@DEBUG_FILE[@]|$(DEBUG_FILE)|g' \
		< $< > $@

install-exec-hook: opensc.conf
	$(MKDIR_P) "$(DESTDIR)$(sysconfdir)"
	if [ -f "$(DESTDIR)$(sysconfdir)/opensc.conf" ]; then \
		$(INSTALL_DATA) opensc.conf "$(DESTDIR)$(sysconfdir)/opensc.conf.new"; \
	else \
		$(INSTALL_DATA) opensc.conf "$(DESTDIR)$(sysconfdir)/opensc.conf"; \
	fi

uninstall-hook: opensc.conf
	rm -f "$(DESTDIR)$(sysconfdir)/opensc.conf.new" "$(DESTDIR)$(sysconfdir)/opensc.conf"
