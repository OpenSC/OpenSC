# Process this file with automake to create Makefile.in

MAINTAINERCLEANFILES = Makefile.in
EXTRA_DIST = DEPRECATED

if HAVE_USBTOKEN
sbin_PROGRAMS = usbtoken
endif

usbtoken_SOURCES = atr.c eutron.c etoken.c ikey2k.c ikey3k.c main.c pid.c \
	socket.c t1.c usb.c usbtoken.h
#usbtoken_CFLAGS = -DUSB_DEBUG
