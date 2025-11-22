TOPDIR = ..

all: versioninfo-customactions.res config.h

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

config.h: winconfig.h
	copy /y winconfig.h config.h

customactions.dll: versioninfo-customactions.res $*.obj $*.def
	link /dll $(LINKFLAGS) /out:$@ /def:$*.def versioninfo-customactions.res customactions.obj msi.lib $(WIX_LIBS) Advapi32.lib User32.lib Version.lib Shell32.lib

$(MSI_NAME): OpenSC.wxs customactions.dll
	wix build -arch $(PLATFORM) -o $(MSI_NAME) -ext WixToolset.UI.wixext -ext WixToolset.Util.wixext -d SOURCE_DIR=$(TOPDIR) $(WIXFLAGS) OpenSC.wxs

OpenSC.msi: $(MSI_NAME)

clean::
	del /Q config.h *.msi *.wixobj *.wixpdb
