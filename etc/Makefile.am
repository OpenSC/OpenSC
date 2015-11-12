MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
DISTCLEANFILES = opensc.conf

EXTRA_DIST = Makefile.mak

SUFFIXES = .in

dist_noinst_DATA = opensc.conf.in
nodist_noinst_DATA = opensc.conf

# Make sure we build this every time
# as there is no dependency for this.
# Can be removed if MSVC is not requried.
force:
opensc.conf: opensc.conf.in force

.in:
	@sed \
		-e 's|@pkgdatadir[@]|$(pkgdatadir)|g' \
		-e 's|@DEBUG_FILE[@]|$(DEBUG_FILE)|g' \
		-e 's|@DEFAULT_PCSC_PROVIDER[@]|$(DEFAULT_PCSC_PROVIDER)|g' \
		-e 's|@DEFAULT_SM_MODULE[@]|$(DEFAULT_SM_MODULE)|g' \
		-e 's|@DEFAULT_SM_MODULE_PATH[@]|$(DEFAULT_SM_MODULE_PATH)|g' \
		-e 's|@DYN_LIB_EXT[@]|$(DYN_LIB_EXT)|g' \
		-e 's|@LIBDIR[@]|$(LIBDIR)|g' \
		-e 's|@LIB_PRE[@]|$(LIB_PRE)|g' \
		-e 's|@PROFILE_DIR[@]|$(PROFILE_DIR)|g' \
		-e 's|@PROFILE_DIR_DEFAULT[@]|$(PROFILE_DIR_DEFAULT)|g' \
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
