# Process this file with automake to create Makefile.in

XSLTPROC = @XSLTPROC@
HTMLFILES = opensc.html opensc.css opensc-es.html
XMLFILES = opensc.xml opensc.xsl opensc-es.xml

MAINTAINERCLEANFILES = Makefile.in 

noinst_DATA = $(HTMLFILES)
EXTRA_DIST = pkcs-15v1_1.asn $(XMLFILES) $(HTMLFILES) doxygen.conf

STYLESHEET = opensc.xsl

%.html: %.xml
if HAVE_DOCBOOK
	$(XSLTPROC) -o $@ $(STYLESHEET) $<
	tidy -im -utf8 -xml $@ || true
else
	@echo "Docbook support disabled, not building $@" >&2
endif
