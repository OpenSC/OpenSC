TOPDIR = ..

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

all: config.h

config.h: winconfig.h
	copy /y winconfig.h config.h

OpenSC.msi: OpenSC.wixobj
        $(WIX_PATH)\bin\light.exe -sh -ext WixUIExtension -ext WiXUtilExtension $?

OpenSC.wixobj: OpenSC.wxs
        $(WIX_PATH)\bin\candle.exe -ext WiXUtilExtension -dSOURCE_DIR=$(TOPDIR) $(CANDLEFLAGS) $?

clean::
	del /Q config.h *.msi *.wixobj *.wixpdb
