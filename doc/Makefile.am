# Process this file with automake to create Makefile.in

MAINTAINERCLEANFILES = Makefile.in

EXTRA_DIST = README export-wiki.sh export-wiki.xsl $(HTML)

HTML= AladdinEtokenPro.html AutoVersions.html BelgianEid.html CardOs.html \
	CardReaders_CTAPI.html CardReaders_SPR532.html CardsAndTokens.html \
	CompatibilityIssues.html CompatiblityIssues.html \
	CryptoIdendityItsec.html Cryptoflex.html Cyberflex.html \
	DesignDiscussion.html DesignDiscussion_UserInterface.html \
	EstonianEid.html FinnishEid.html GemplusGpk.html GermanEid.html \
	ItalianEid.html ItalianPostecert.html LinuxDistributions.html \
	MacOsX.html MartinBlog.html MartinBlogMuscle.html \
	MartinBlogPlatform.html OpenPgp.html OpenSsh.html \
	OpensslEngines.html PinpadReaders.html PuTTYcard.html \
	RainbowIkeyThree.html RecentTestresults.html ReleaseHowto.html \
	ReplacingCertificates.html RoadMap.html SchlumbergerEgate.html \
	SmartCardApplications.html SpanishEid.html SubversionRepository.html \
	SupportedHardware.html SwedishEid.html TaiwanEid.html TelseCos.html \
	TroubleShooting.html WindowsCsp.html index.html pkcs11_keypair_gen.html

# OLD
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
