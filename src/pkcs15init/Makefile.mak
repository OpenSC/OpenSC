TOPDIR = ..\..

TARGET = pkcs15init.lib
OBJECTS = pkcs15-lib.obj profile.obj \
          pkcs15-gpk.obj pkcs15-miocos.obj pkcs15-cflex.obj \
          pkcs15-cardos.obj pkcs15-jcop.obj pkcs15-starcos.obj \
          pkcs15-oberthur.obj pkcs15-oberthur-awp.obj \
          pkcs15-setcos.obj pkcs15-incrypto34.obj \
          pkcs15-muscle.obj pkcs15-asepcos.obj pkcs15-rutoken.obj \
          pkcs15-entersafe.obj pkcs15-rtecp.obj pkcs15-westcos.obj \
	  pkcs15-myeid.obj

all: $(TARGET) 

$(TARGET): $(OBJECTS)
	lib /nologo /machine:ix86 /out:$(TARGET) $(OBJECTS)

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

