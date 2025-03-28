TOPDIR = ..

all: versioninfo-customactions.res config.h

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

config.h: winconfig.h
	copy /y winconfig.h config.h

customactions.dll: versioninfo-customactions.res customactions.obj
	echo LIBRARY $* > $*.def
	echo EXPORTS >> $*.def
	type customactions.exports >> $*.def
	link /dll $(LINKFLAGS) /def:$*.def /out:customactions.dll versioninfo-customactions.res customactions.obj msi.lib $(WIX_LIBS) Advapi32.lib User32.lib Version.lib Shell32.lib

OpenSC.msi: OpenSC.wxs customactions.dll
	wix build -arch $(PLATFORM) -ext WixToolset.UI.wixext -ext WixToolset.Util.wixext -d SOURCE_DIR=$(TOPDIR) $(WIXFLAGS) OpenSC.wxs

clean::
	del /Q config.h *.msi *.wixobj *.wixpdb
