/*
 * reader-usbtoken.c: Reader driver for USBtoken
 *
 * Copyright (C) 2002  Andreas Jellinghaus <aj@dungeon.inka.de>
 */

#include "internal.h"
#ifdef HAVE_USBTOKEN
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

/* we will create that many usbtoken readers */
#define READERS 5

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
			     struct sc_slot_info *slot, const u8 * sendbuf,
			     size_t sendsize, u8 * recvbuf,
			     size_t * recvsize, int control);
int usbtoken_reader_lock(struct sc_reader *reader,
			 struct sc_slot_info *slot);
int usbtoken_reader_unlock(struct sc_reader *reader,
			   struct sc_slot_info *slot);

static struct sc_reader_operations usbtoken_ops;

static struct sc_reader_driver usbtoken_reader_driver = {
	"USB Crypto Token Reader",
	"usbtoken",
	&usbtoken_ops
};

/* private data structures */
struct usbtoken_privslot {
	struct sockaddr_un sa_un;
	int slot, fd;
};

/* ok,lets start the real code */
int usbtoken_reader_init(struct sc_context *ctx, void **priv_data)
{
	/* Called during sc_establish_context(), when the driver
	 * is loaded */

	int i;
	struct sc_reader *myreader;
	struct usbtoken_privslot *myprivslot;

	SC_FUNC_CALLED(ctx, 4);
	for (i = 0; i < READERS; i++) {
		myreader = malloc(sizeof(struct sc_reader));
		bzero(myreader, sizeof(struct sc_reader));
		myreader->driver = &usbtoken_reader_driver;
		myreader->ops = &usbtoken_ops;
		myreader->slot_count = 1;
		myreader->name = strdup("USB Crypto Token %d");
		snprintf(myreader->name, strlen(myreader->name),
			 myreader->name, i);
		myprivslot = malloc(sizeof(struct usbtoken_privslot));
		bzero(myprivslot, sizeof(struct usbtoken_privslot));
		myreader->slot[0].drv_data = myprivslot;
		myreader->slot[0].flags = SC_SLOT_CARD_PRESENT;

		myprivslot->fd = -1;
		myprivslot->sa_un.sun_family = AF_UNIX;
		snprintf(myprivslot->sa_un.sun_path,
			 sizeof(myprivslot->sa_un.sun_path), SRVSOCKET, i);

		if (_sc_add_reader(ctx, myreader) != 0) {
			/* error */
			free(myprivslot);
			free(myreader->name);
			free(myreader);
			break;
		}
	}

	return SC_NO_ERROR;
}

int usbtoken_reader_finish(struct sc_context *ctx, void *priv_data)
{
	/* Called when the driver is being unloaded.  finish() has to
	 * deallocate the private data and any resources. */

	SC_FUNC_CALLED(ctx, 4);
	return SC_NO_ERROR;
}

int usbtoken_reader_release(struct sc_reader *reader)
{
	/* Called when releasing a reader.  release() has to
	 * deallocate the private data.  Other fields will be
	 * freed by OpenSC. */
	struct usbtoken_privslot *myprivslot;

	SC_FUNC_CALLED(reader->ctx, 4);
	myprivslot = reader->slot[0].drv_data;
	if (myprivslot) {
		if (myprivslot->fd >= 0)
			close(myprivslot->fd);
		free(myprivslot);
	}

	return SC_NO_ERROR;
}

int usbtoken_reader_detect_card_presence(struct sc_reader *reader,
					 struct sc_slot_info *slot)
{
	struct usbtoken_privslot *myprivslot;
	struct stat statbuf;
	int rc, newflags;

	SC_FUNC_CALLED(reader->ctx, 4);
	myprivslot = slot->drv_data;

	newflags =
	    slot->flags & ~(SC_SLOT_CARD_PRESENT | SC_SLOT_CARD_CHANGED);


	if (myprivslot->fd >= 0) {
		struct pollfd pfd;
		pfd.fd = myprivslot->fd;
		pfd.events = 0;
		rc = poll(&pfd, 1, 0);
		if (pfd.revents & POLLHUP) {	/* card removed, slot invalid */
			newflags |= SC_SLOT_CARD_CHANGED;
			usbtoken_reader_disconnect(reader, slot,
						   SC_DISCONNECT);
			usbtoken_reader_connect(reader, slot);
		}
	}

	rc = stat(myprivslot->sa_un.sun_path, &statbuf);

	if (rc != -1)
		newflags |= SC_SLOT_CARD_PRESENT;

	if ((slot->flags & SC_SLOT_CARD_PRESENT) != newflags)
		newflags |= SC_SLOT_CARD_CHANGED;
	slot->flags = newflags;

	return slot->flags;
}

int usbtoken_reader_unix_cmd(struct sc_reader *reader,
			     struct sc_slot_info *slot, u8 cmd)
{
	struct usbtoken_privslot *myprivslot;
	u8 msg;
	int rc;

	SC_FUNC_CALLED(reader->ctx, 4);
	myprivslot = slot->drv_data;

	assert(myprivslot->fd >= 0);
	rc = write(myprivslot->fd, &cmd, sizeof(cmd));
	if (rc != sizeof(cmd)) {
		sc_error(reader->ctx,
		      "usbtoken_reader_unix_cmd write failed\n");
		return SC_ERROR_READER;
	}

	rc = read(myprivslot->fd, &msg, sizeof(msg));
	if (rc != 1 || msg != 0) {
		sc_error(reader->ctx,
		      "usbtoken_reader_unix_cmd read failed\n");
		return SC_ERROR_READER;
	}

	return SC_NO_ERROR;
}

int usbtoken_reader_connect(struct sc_reader *reader,
			    struct sc_slot_info *slot)
{
	struct usbtoken_privslot *myprivslot;
	int rc, len;

	SC_FUNC_CALLED(reader->ctx, 4);
	myprivslot = slot->drv_data;

	rc = socket(AF_UNIX, SOCK_STREAM, 0);
	if (rc < 0) {
		sc_error(reader->ctx,
		      "usbtoken_reader_connect: socket() failed\n");
		return SC_ERROR_READER;
	}

	myprivslot->fd = rc;
	len = sizeof(myprivslot->sa_un.sun_family) +
	    strlen(myprivslot->sa_un.sun_path);
	rc = connect(myprivslot->fd, (struct sockaddr *)
		     &(myprivslot->sa_un), len);

	if (rc < 0) {
		close(myprivslot->fd);
		myprivslot->fd = -1;
		sc_error(reader->ctx,
		      "usbtoken_reader_connect: connect(%s) failed\n",
		      myprivslot->sa_un.sun_path);
		return SC_ERROR_CARD_NOT_PRESENT;
	}

	rc = read(myprivslot->fd, slot->atr, SC_MAX_ATR_SIZE);
	if (rc == -1) {
		sc_error(reader->ctx,
		      "usbtoken_reader_connect: read failed on %s\n",
		      myprivslot->sa_un.sun_path);
		return SC_ERROR_READER;
	}

	if (rc == 0) {
		sc_error(reader->ctx,
		      "usbtoken_reader_connect: read on %s recieved no data\n",
		      myprivslot->sa_un.sun_path);
		return SC_ERROR_READER;
	}

	slot->atr_len = rc;
	return SC_NO_ERROR;
}

int usbtoken_reader_disconnect(struct sc_reader *reader,
			       struct sc_slot_info *slot, int action)
{
	struct usbtoken_privslot *myprivslot;

	SC_FUNC_CALLED(reader->ctx, 4);
	myprivslot = slot->drv_data;
	if (myprivslot->fd >= 0) {
		close(myprivslot->fd);
		myprivslot->fd = -1;
	}

	return SC_NO_ERROR;
}

int usbtoken_reader_transmit(struct sc_reader *reader,
			     struct sc_slot_info *slot, const u8 * sendbuf,
			     size_t sendsize, u8 * recvbuf,
			     size_t * recvsize, int control)
{
	struct usbtoken_privslot *myprivslot;
	u8 buffer[1024];
	int rc;

	SC_FUNC_CALLED(reader->ctx, 4);
	myprivslot = slot->drv_data;

	assert(myprivslot->fd >= 0);
	if (sendsize > 1023) {
		sc_error(reader->ctx,
		      "usbtoken_reader_transmit sendsize %d too big\n",
		      sendsize);
		return SC_ERROR_READER;
	}

	buffer[0] = 3;
	memcpy(&buffer[1], sendbuf, sendsize);
	rc = write(myprivslot->fd, buffer, sendsize + 1);
	if (rc != sendsize + 1) {
		sc_error(reader->ctx,
		      "usbtoken_reader_transmit write failed\n");
		return SC_ERROR_READER;
	}

	rc = read(myprivslot->fd, buffer, sizeof(buffer));
	if (rc == -1) {
		sc_error(reader->ctx,
		      "usbtoken_reader_transmit read failed\n");
		return SC_ERROR_READER;
	}

	if (rc == 0) {
		sc_error(reader->ctx,
		      "usbtoken_reader_transmit recved no data\n");
		return SC_ERROR_READER;
	}

	if (buffer[0] != 3) {
		sc_error(reader->ctx,
		      "usbtoken_reader_transmit token failed\n");
		return SC_ERROR_READER;
	}

	if (rc - 1 > *recvsize) {
		sc_error(reader->ctx,
		      "usbtoken_reader_transmit recved too much (%d > %d)\n",
		      rc - 1, *recvsize);
		return SC_ERROR_READER;
	}

	*recvsize = rc - 1;
	memcpy(recvbuf, &buffer[1], rc - 1);

	return SC_NO_ERROR;
}

int usbtoken_reader_lock(struct sc_reader *reader,
			 struct sc_slot_info *slot)
{
	SC_FUNC_CALLED(reader->ctx, 4);
	return usbtoken_reader_unix_cmd(reader, slot, 4);
}

int usbtoken_reader_unlock(struct sc_reader *reader,
			   struct sc_slot_info *slot)
{
	SC_FUNC_CALLED(reader->ctx, 4);
	return usbtoken_reader_unix_cmd(reader, slot, 5);
}

const struct sc_reader_driver *sc_get_usbtoken_driver(void)
{
	usbtoken_ops.init = usbtoken_reader_init;
	usbtoken_ops.finish = usbtoken_reader_finish;
	usbtoken_ops.release = usbtoken_reader_release;
	usbtoken_ops.detect_card_presence = usbtoken_reader_detect_card_presence;
	usbtoken_ops.connect = usbtoken_reader_connect;
	usbtoken_ops.disconnect = usbtoken_reader_disconnect;
	usbtoken_ops.transmit = usbtoken_reader_transmit;
	usbtoken_ops.lock = usbtoken_reader_lock;
	usbtoken_ops.unlock = usbtoken_reader_unlock;

	return &usbtoken_reader_driver;
}

#endif	/* HAVE_USBTOKEN */
