XSLTPROC = xsltproc --xinclude

default:
	@echo -e "The following make targets are available:\n"
	@echo -e "\thtml\t\tA single HTML page\n"
	@echo -e "\tman\t\tMan pages for all functions\n"

all: html man

clean:
	rm -rf html man

html:
	$(XSLTPROC) -o html/api.html src/api/html.xsl src/api/api.xml

man:
	$(XSLTPROC) -o man/ src/api/man.xsl src/api/api.xml

.SILENT:
