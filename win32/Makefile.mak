TOPDIR = ..

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

all: config.h

config.h: winconfig.h
	copy /y winconfig.h config.h

opensc-setup-custom-action.dll: opensc-setup-custom-action.obj
        link /dll $(LINKFLAGS) /out:opensc-setup-custom-action.dll opensc-setup-custom-action.obj msi.lib $(WIX_LIB)\dutil.lib $(WIX_LIB)\wcautil.lib

OpenSC.msi: OpenSC.wixobj
        $(WIX_PATH)\bin\light.exe -sh -ext WixUIExtension -ext WiXUtilExtension $?

OpenSC.wixobj: OpenSC.wxs opensc-setup-custom-action.dll
        $(WIX_PATH)\bin\candle.exe -ext WiXUtilExtension -dSOURCE_DIR=$(TOPDIR) $(CANDLEFLAGS) $?

clean::
	del /Q config.h *.msi *.wixobj *.wixpdb
