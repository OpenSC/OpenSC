MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

EXTRA_DIST = completion-template

dist_noinst_DATA = $(wildcard $(srcdir)/*.xml)
if ENABLE_DOC
html_DATA = tools.html
endif

if ENABLE_MAN
man1_MANS = $(patsubst $(srcdir)/%.xml, %, $(wildcard $(srcdir)/*.1.xml))
endif

completion_DATA = $(patsubst $(srcdir)/%.1.xml, %, $(wildcard $(srcdir)/*.1.xml))

tools.html: $(srcdir)/tools.xml $(wildcard $(srcdir)/*.1.xml)
	$(XSLTPROC) --nonet --path "$(srcdir)/..:$(xslstylesheetsdir)/html" --xinclude -o $@ html.xsl $<

%.1: $(srcdir)/%.1.xml
	sed -e 's|@pkgdatadir[@]|$(pkgdatadir)|g' < $< \
	| $(XSLTPROC) --nonet --path "$(srcdir)/..:$(xslstylesheetsdir)/manpages" --xinclude -o $@ man.xsl $<

%: $(srcdir)/%.1.xml
	@echo $< $@
	@cat $(srcdir)/completion-template \
		| sed "s,ALLOPTS,\
			$(shell sed -n 's,.*<option>\([^<]*\)</option>.*,\1,pg' $< \
				| sort -u | grep -- '^\-' | tr '\n' ' ')," \
		| sed "s,OPTSWITHARGS,\
			$(shell sed -n 's,.*<option>\([^<]*\)</option>.*<replaceable>.*,\1,pg' $< \
				| sort -u | grep -- '^\-' | tr '\n' '|' | sed 's,|$$,,' | grep ^ || echo "!*")," \
		| sed "s,FILEOPTS,\
			$(shell sed -n 's,.*<option>\([^<]*\)</option>.*<replaceable>.*filename.*,\1,pg' $< \
				| sort -u | grep -- '^\-' | tr '\n' '|' | sed 's,|$$,,' | grep ^ || echo "!*"),"  \
		| sed "s,MODULEOPTS,\
			$(shell sed -n 's,.*<option>\([^<]*\)</option>.*<replaceable>.*mod.*,\1,pg' $< \
				| sort -u | grep -- '^\-' | tr '\n' '|' | sed 's,|$$,,' | grep ^ || echo "!*")," \
		| sed "s,FUNCTION_NAME,$(shell echo $@ | sed s,-,_,g)," \
		| sed "s,PROGRAM_NAME,$@," \
		> $@

clean-local:
	-rm -rf $(html_DATA) $(man1_MANS) $(completion_DATA)
