# Process this file with automake to create Makefile.in

XSLTPROC := @XSLTPROC@
HTMLFILES := usbtoken.html

MAINTAINERCLEANFILES = Makefile.in pkcs15-profile.5

MANSRC  	= pkcs15-crypt.1 \
	   	  pkcs15-init.1 \
		  cryptoflex-tool.1 \
		  opensc-config.1 \
		  opensc-explorer.1 \
		  opensc-tool.1 \
		  pkcs15-tool.1 \
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
		  sc_select_file.3
man_MANS	= $(MANSRC) pkcs15-profile.5
noinst_DATA	= $(HTMLFILES)
EXTRA_DIST	= $(MANSRC) pkcs15-profile.5.in pkcs-15v1_1.asn \
	     	  usbtoken.xml $(HTMLFILES) doxygen.conf pkcs11.txt

STYLESHEET=/usr/share/sgml/docbook/stylesheet/xsl/nwalsh/xhtml/docbook.xsl

%.html: %.xml
if HAVE_DOCBOOK
	$(XSLTPROC) -o $@ $(STYLESHEET) $<
else
	@echo "Docbook support disabled, not building $@" >&2
endif
