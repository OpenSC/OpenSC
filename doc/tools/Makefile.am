MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

dist_noinst_DATA = $(wildcard $(srcdir)/*.xml)
if ENABLE_DOC
html_DATA = tools.html
endif

if ENABLE_MAN
man1_MANS = $(patsubst $(srcdir)/%.xml, %, $(wildcard $(srcdir)/*.1.xml))
man5_MANS = $(patsubst $(srcdir)/%.xml, %, $(wildcard $(srcdir)/*.5.xml))
endif

completion_DATA = $(patsubst $(srcdir)/%.1.xml, %, $(wildcard $(srcdir)/*.1.xml))
completiondir = $(sysconfdir)/bash_completion.d

tools.html: $(srcdir)/tools.xml $(wildcard $(srcdir)/*.1.xml) $(wildcard $(srcdir)/*.5.xml)
	$(XSLTPROC) --nonet --path "$(srcdir)/..:$(xslstylesheetsdir)/html" --xinclude -o $@ html.xsl $<

%.1: $(srcdir)/%.1.xml
	sed -e 's|@pkgdatadir[@]|$(pkgdatadir)|g' < $< \
	| $(XSLTPROC) --nonet --path "$(srcdir)/..:$(xslstylesheetsdir)/manpages" --xinclude -o $@ man.xsl $<

%.5: $(srcdir)/%.5.xml
	sed -e 's|@pkgdatadir[@]|$(pkgdatadir)|g' < $< \
	| $(XSLTPROC) --nonet --path "$(srcdir)/..:$(xslstylesheetsdir)/manpages" --xinclude -o $@ man.xsl $<

%: $(srcdir)/%.1.xml
	@echo $< $@
	@cat completion-template \
		| sed "s,ALLOPTS,\
			$(shell sed -n 's,\s\s\s*<option>\([^<]*\)</option>.*,\1,pg' $< \
				| sort -u | grep -- '^\-' | tr '\n' ' ')," \
		| sed "s,OPTSWITHARGS,\
			$(shell sed -n 's,\s\s\s*<option>\([^<]*\)</option>.*<replaceable>.*,\1,pg' $< \
				| sort -u | grep -- '^\-' | tr '\n' '|' | sed 's,|$$,,')," \
		| sed "s,FILEOPTS,\
			$(shell sed -n 's,\s\s\s*<option>\([^<]*\)</option>.*<replaceable>.*filename.*,\1,pg' $< \
				| sort -u | grep -- '^\-' | tr '\n' '|')," \
		| sed "s,FUNCTION_NAME,$(shell echo $@ | sed s,-,_,g)," \
		| sed "s,PROGRAM_NAME,$@," \
		> $@

clean-local:
	-rm -rf $(html_DATA) $(man1_MANS) $(man5_MANS) $(completion_DATA)
