TOPDIR = ..\..\..

TARGET = OpenSC.msi

all: $(TARGET) 

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

OpenSC.msi: OpenSC.wixobj
	$(WIX_INSTALLED_PATH)\light.exe -sh -ext WixUIExtension $?
	
OpenSC.wixobj: OpenSC.wxs
	$(WIX_INSTALLED_PATH)\candle.exe -dSOURCE_DIR=$(TOPDIR) -dPATH_TO_LIBLTD3_DLL=$(LIBLTDL_DLL) $?

clean::
	del /Q *.msi *.wixobj *.wixpdb

