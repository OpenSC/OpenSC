# Process this file with automake to create Makefile.in

XSLTPROC = @XSLTPROC@
HTMLFILES = opensc.html opensc.css
XMLFILES = opensc.xml opensc.xsl

MAINTAINERCLEANFILES = Makefile.in pkcs15-profile.5

MANSRC = \
	pkcs15-crypt.1 \
	pkcs15-init.1 \
	cryptoflex-tool.1 \
	opensc-config.1 \
	opensc-explorer.1 \
	opensc-tool.1 \
	pkcs15-tool.1 \
	pkcs11-tool.1 \
	cardos-info.1 \
	opensc.7 \
	pkcs15.7 \
	sc_connect_card.3 \
	sc_detect_card_presence.3 \
	sc_disconnect_card.3 \
	sc_establish_context.3 \
	sc_file.3 \
	sc_file_free.3 \
	sc_file_new.3 \
	sc_list_files.3 \
	sc_lock.3 \
	sc_read_binary.3 \
	sc_read_record.3 \
	sc_release_context.3 \
	sc_select_file.3 \
	sc_pkcs15_compute_signature.3

man_MANS = $(MANSRC) pkcs15-profile.5
noinst_DATA = $(HTMLFILES)
EXTRA_DIST = $(MANSRC) pkcs15-profile.5.in pkcs-15v1_1.asn \
	$(XMLFILES) $(HTMLFILES) doxygen.conf

STYLESHEET = opensc.xsl

%.html: %.xml
if HAVE_DOCBOOK
	$(XSLTPROC) -o $@ $(STYLESHEET) $<
	tidy -im -utf8 -xml $@ || true
else
	@echo "Docbook support disabled, not building $@" >&2
endif
