TOPDIR = ..\..


TARGET                  = opensc-pkcs11.dll

OBJECTS			= pkcs11-global.obj pkcs11-session.obj pkcs11-object.obj misc.obj slot.obj \
			  secretkey.obj framework-pkcs15.obj framework-pkcs15init.obj

all: $(TARGET)

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

$(TARGET): $(OBJECTS)
	link $(LINKFLAGS) /dll /out:$(TARGET) $(OBJECTS) ..\libopensc\opensc.lib ..\scconf\scconf.lib ..\pkcs15init\pkcs15init.lib winscard.lib

