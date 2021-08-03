TOPDIR = ..\..

TARGET = pkcs15init.lib
OBJECTS = pkcs15-lib.obj profile.obj \
          pkcs15-gpk.obj pkcs15-cflex.obj \
          pkcs15-cardos.obj pkcs15-starcos.obj \
          pkcs15-oberthur.obj pkcs15-oberthur-awp.obj \
          pkcs15-setcos.obj pkcs15-incrypto34.obj \
          pkcs15-muscle.obj pkcs15-asepcos.obj pkcs15-rutoken.obj \
          pkcs15-entersafe.obj pkcs15-rtecp.obj pkcs15-westcos.obj \
          pkcs15-myeid.obj pkcs15-authentic.obj pkcs15-iasecc.obj \
          pkcs15-epass2003.obj pkcs15-openpgp.obj pkcs15-sc-hsm.obj \
          pkcs15-isoApplet.obj pkcs15-gids.obj

all: $(TARGET)

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

$(TARGET): $(OBJECTS)
	lib $(LIBFLAGS) /out:$(TARGET) $(OBJECTS)
