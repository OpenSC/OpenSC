/*
 * reader-usbtoken.c: Reader driver for USBtoken
 *
 * Copyright (C) 2002  Andreas Jellinghaus <aj@dungeon.inka.de>
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "opensc.h"
#include "internal.h"
#include "log.h"

/* we will create that many usbtoken readers */
#define READERS 5

#define CLISOCKET "/tmp/opensc-usbtoken.XXXXXX"
#define SRVSOCKET "/var/run/usbtoken/socket%d"

/* function declarations */
int usbtoken_reader_init(struct sc_context *ctx, void **priv_data);
int usbtoken_reader_finish(struct sc_context *ctx, void *priv_data);
int usbtoken_reader_release(struct sc_reader *reader);
int usbtoken_reader_detect_card_presence(struct sc_reader *reader,
			struct sc_slot_info *slot);
int usbtoken_reader_connect(struct sc_reader *reader,
			struct sc_slot_info *slot);
int usbtoken_reader_disconnect(struct sc_reader *reader,
			struct sc_slot_info *slot, int action);
int usbtoken_reader_transmit(struct sc_reader *reader,
		struct sc_slot_info *slot, const u8 *sendbuf, size_t sendsize,
		u8 *recvbuf, size_t *recvsize, int control);
int usbtoken_reader_lock(struct sc_reader *reader,
			struct sc_slot_info *slot);
int usbtoken_reader_unlock(struct sc_reader *reader,
			struct sc_slot_info *slot);

/* the operations struct, already initialized */
static struct sc_reader_operations usbtoken_reader_operations = {
	.init			= usbtoken_reader_init,
	.finish			= usbtoken_reader_finish,
	.release		= usbtoken_reader_release,
	.detect_card_presence	= usbtoken_reader_detect_card_presence,
	.connect		= usbtoken_reader_connect,
	.disconnect		= usbtoken_reader_disconnect,
	.transmit		= usbtoken_reader_transmit,
	.lock			= usbtoken_reader_lock,
	.unlock			= usbtoken_reader_unlock,
};

/* also, the driver struct */
static struct sc_reader_driver usbtoken_reader_driver = {
	.name = "USB Crypto Token Reader",
	.short_name = "usbtoken",
	.ops = &usbtoken_reader_operations
};

/* return our structure */
const struct sc_reader_driver *sc_get_usbtoken_driver() {
	return &usbtoken_reader_driver;
};

/* private data structures */
struct usbtoken_privslot {
	struct sockaddr_un sa_un;
	int slot, fd;
};

/* ok,lets start the real code */
int usbtoken_reader_init(struct sc_context *ctx, void **priv_data) {
	/* Called during sc_establish_context(), when the driver
	 * is loaded */

	int i;
	struct sc_reader *myreader;
	struct usbtoken_privslot *myprivslot;

	SC_FUNC_CALLED(ctx, 1);
	for (i=0; i< READERS; i++) {
		myreader = malloc(sizeof(struct sc_reader));
		bzero(myreader,sizeof(struct sc_reader));
		myreader->driver = &usbtoken_reader_driver;
		myreader->ops = &usbtoken_reader_operations;
		myreader->slot_count = 1;
		myreader->name =strdup("USB Crypto Token");
		myprivslot = malloc(sizeof(struct usbtoken_privslot));
		bzero(myprivslot,sizeof(struct usbtoken_privslot));
		myreader->slot[0].drv_data=myprivslot;
	
		myprivslot->sa_un.sun_family=AF_UNIX;
		snprintf(myprivslot->sa_un.sun_path,
			sizeof(myprivslot->sa_un.sun_path), SRVSOCKET, i);

		if ( _sc_add_reader(ctx, myreader) != 0) { 
			/* error */
			free(myprivslot);
			free(myreader->name);
			free(myreader);
			break;
		}
	}
	
	return SC_NO_ERROR;
}

int usbtoken_reader_finish(struct sc_context *ctx, void *priv_data) {
	/* Called when the driver is being unloaded.  finish() has to
	 * deallocate the private data and any resources. */

	SC_FUNC_CALLED(ctx, 1);
	return SC_NO_ERROR;
}

int usbtoken_reader_release(struct sc_reader *reader) {
	/* Called when releasing a reader.  release() has to
	 * deallocate the private data.  Other fields will be
	 * freed by OpenSC. */
	struct usbtoken_privslot *myprivslot;

	SC_FUNC_CALLED(reader->ctx, 1);
	myprivslot = reader->slot[0].drv_data;
	if (myprivslot) {
		close (myprivslot->fd);
		free(myprivslot);
	}
	
	return SC_NO_ERROR;
}

int usbtoken_reader_detect_card_presence(struct sc_reader *reader,
			struct sc_slot_info *slot) {
	struct usbtoken_privslot *myprivslot;
	struct stat statbuf;
	int rc;

	SC_FUNC_CALLED(reader->ctx, 1);
	myprivslot = slot->drv_data;

	rc = stat(myprivslot->sa_un.sun_path, &statbuf);

	if (rc == -1)
		slot->flags = 0;
	else 
		slot->flags = SC_SLOT_CARD_PRESENT;

	return slot->flags;
}

int usbtoken_reader_unix_cmd(struct sc_reader *reader, 
			struct sc_slot_info *slot,
			u8 cmd) {
	struct usbtoken_privslot *myprivslot;
	u8 msg;
	int rc;

	SC_FUNC_CALLED(reader->ctx, 1);
	myprivslot = slot->drv_data;
	
	rc = write(myprivslot->fd, &cmd, sizeof(cmd));
	if (rc != sizeof(cmd)) {
		error(reader->ctx, "usbtoken_reader_unix_cmd write failed\n");
		return SC_ERROR_READER;
	}

	rc = read(myprivslot->fd, &msg, sizeof(msg));
	if (rc != 1 || msg != 0) {
		error(reader->ctx, "usbtoken_reader_unix_cmd read failed\n");
		return SC_ERROR_READER;
	}

	return SC_NO_ERROR;
}

int usbtoken_reader_connect(struct sc_reader *reader,
			struct sc_slot_info *slot) {
	struct usbtoken_privslot *myprivslot;
	int rc,len;

	SC_FUNC_CALLED(reader->ctx, 1);
	myprivslot = slot->drv_data;

	rc = socket(AF_UNIX, SOCK_STREAM, 0);
	if (rc < 0) {
		error(reader->ctx, "usbtoken_reader_connect socket failed\n");
		return SC_ERROR_READER;
	}

	myprivslot->fd = rc;
	len = sizeof(myprivslot->sa_un.sun_family) +
		strlen(myprivslot->sa_un.sun_path);
	rc = connect(myprivslot->fd, (struct sockaddr *)
			&(myprivslot->sa_un), len);

	if (rc < 0) {
		close(myprivslot->fd);
		myprivslot->fd=0;
		error(reader->ctx, "usbtoken_reader_connect connect failed\n");
		return SC_ERROR_CARD_NOT_PRESENT;
	} 

	rc = read(myprivslot->fd, slot->atr, SC_MAX_ATR_SIZE);
	if (rc == -1) {
		error(reader->ctx, "usbtoken_reader_connect read failed\n");
		return SC_ERROR_READER;
	}

	if (rc == 0) {
		error(reader->ctx, "usbtoken_reader_connect recved no data\n");
		return SC_ERROR_READER;
	}

	slot->atr_len = rc;
	return SC_NO_ERROR;
}

int usbtoken_reader_disconnect(struct sc_reader *reader,
			struct sc_slot_info *slot, int action) {
	struct usbtoken_privslot *myprivslot;

	SC_FUNC_CALLED(reader->ctx, 1);
	myprivslot = slot->drv_data;
	close (myprivslot->fd);

	return SC_NO_ERROR;
}

int usbtoken_reader_transmit(struct sc_reader *reader,
		struct sc_slot_info *slot, const u8 *sendbuf, size_t sendsize,
		u8 *recvbuf, size_t *recvsize, int control) {
	struct usbtoken_privslot *myprivslot;
	u8 buffer[1024];
	int rc;

	SC_FUNC_CALLED(reader->ctx, 1);
	myprivslot = slot->drv_data;

	if (sendsize > 1023) {
		error(reader->ctx, "usbtoken_reader_transmit sendsize %d too big\n", sendsize);
		return SC_ERROR_READER;
	}

	buffer[0] = 3;
	memcpy(&buffer[1],sendbuf, sendsize);
	rc = write (myprivslot->fd, buffer, sendsize+1);
	if (rc != sendsize+1) {
		error(reader->ctx, "usbtoken_reader_transmit write failed\n");
		return SC_ERROR_READER;
	}

	rc = read(myprivslot->fd, buffer, sizeof(buffer));
	if (rc == -1) {
		error(reader->ctx, "usbtoken_reader_transmit read failed\n");
		return SC_ERROR_READER;
	}

	if (rc == 0) {
		error(reader->ctx, "usbtoken_reader_transmit recved no data\n");
		return SC_ERROR_READER;
	}

	if (buffer[0] != 3) {
		error(reader->ctx, "usbtoken_reader_transmit token failed\n");
		return SC_ERROR_READER;
	}

	if (rc-1 > *recvsize) {
		error(reader->ctx, "usbtoken_reader_transmit recved too much (%d > %d)\n", rc-1, *recvsize);
		return SC_ERROR_READER;
	}

	*recvsize = rc -1;
	memcpy(recvbuf,&buffer[1], rc-1);

	return SC_NO_ERROR;
}

int usbtoken_reader_lock(struct sc_reader *reader,
			struct sc_slot_info *slot) {
	SC_FUNC_CALLED(reader->ctx, 1);
	return usbtoken_reader_unix_cmd(reader, slot, 4);
}

int usbtoken_reader_unlock(struct sc_reader *reader,
			struct sc_slot_info *slot) {
	SC_FUNC_CALLED(reader->ctx, 1);
	return usbtoken_reader_unix_cmd(reader, slot, 5);
}
