TOPDIR = ..\..

TARGET = libsm.lib
OBJECTS = sm-common.obj

TARGET1 = libisosm.lib
OBJECTS1 = iso-sm.obj

all: $(TARGET) $(TARGET1)

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

!IF "$(OPENSSL_DEF)" == "/DENABLE_OPENSSL"

$(TARGET): $(OBJECTS)
        lib $(LIBFLAGS) /out:$(TARGET) $(OBJECTS)

!ELSE
$(TARGET):

!ENDIF

$(TARGET1): $(OBJECTS1)
        lib $(LIBFLAGS) /out:$(TARGET1) $(OBJECTS1)
