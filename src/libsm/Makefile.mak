TOPDIR = ..\..

!IF "$(OPENSSL_DEF)" == "/DENABLE_OPENSSL"
TARGET = libsm.lib
OBJECTS = sm-common.obj

all: $(TARGET)

$(TARGET): $(OBJECTS)
        lib $(LIBFLAGS) /out:$(TARGET) $(OBJECTS)

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

!ELSE
all:
!ENDIF
