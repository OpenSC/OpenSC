TOPDIR = ..

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

all: config.h

config.h: winconfig.h
	@copy /y winconfig.h config.h

OpenSC.msi: OpenSC.wixobj
        $(WIX_INSTALLED_PATH)\bin\light.exe -sh -ext WixUIExtension $?

OpenSC.wixobj: OpenSC.wxs
        $(WIX_INSTALLED_PATH)\bin\candle.exe -dSOURCE_DIR=$(TOPDIR) $?

clean::
	del /Q config.h *.msi *.wixobj *.wixpdb
