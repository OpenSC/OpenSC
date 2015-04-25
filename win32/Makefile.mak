TOPDIR = ..

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

all: config.h

config.h: winconfig.h
	copy /y winconfig.h config.h

customactions.dll: customactions.obj
	echo LIBRARY $* > $*.def
	echo EXPORTS >> $*.def
	type customactions.exports >> $*.def
        link /dll $(LINKFLAGS) /def:$*.def /out:customactions.dll customactions.obj msi.lib $(WIX_LIBS) Advapi32.lib User32.lib Version.lib Shell32.lib

OpenSC.msi: OpenSC.wixobj
        $(WIX_PATH)\bin\light.exe -sh -ext WixUIExtension -ext WiXUtilExtension $?

OpenSC.wixobj: OpenSC.wxs customactions.dll
        $(WIX_PATH)\bin\candle.exe -ext WiXUtilExtension -dSOURCE_DIR=$(TOPDIR) $(CANDLEFLAGS) OpenSC.wxs

clean::
	del /Q config.h *.msi *.wixobj *.wixpdb
