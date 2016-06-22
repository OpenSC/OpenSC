TOPDIR = ..\..

TARGET = libsm.lib
OBJECTS = sm-common.obj

all: $(TARGET)

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

!IF "$(OPENSSL_DEF)" == "/DENABLE_OPENSSL"

$(TARGET): $(OBJECTS)
        lib $(LIBFLAGS) /out:$(TARGET) $(OBJECTS)

!ELSE
$(TARGET):

!ENDIF
