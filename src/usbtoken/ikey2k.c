#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "usbtoken.h"

int ikey2k_init();
int ikey2k_transmit(uint8_t * buf_send, int len_send,
		    uint8_t * buf_recv, int *len_recv);

const struct token_drv ikey2k_drv = {
	.init = ikey2k_init,
	.transmit = ikey2k_transmit,
	.max_ifsc = 0xb4,	/* as used under windows */
	.timeout = 10000,
	.name = "Rainbow iKey 2000/2032",
};

char *ikey2k_products[] = { "4b9/1202/100", 0 };

int ikey2k_test(char *product)
{
	char **p;
	if (!product)
		return USBTOKEN_ERROR;

	for (p = ikey2k_products; *p; p++) {
		if (strcmp(product, *p) == 0) {
			usbtoken.drv = ikey2k_drv;
			return USBTOKEN_OK;
		}
	}
	return USBTOKEN_ERROR;
}

int ikey2k_init()
{
	uint8_t buffer[1024];

	uint8_t expect5[] = { 0x0d, 0x63, 0x00, 0x05, 0x2d, 0x2d, 0xc0,
		0x80, 0x80, 0x60, 0x80, 0x01, 0x19
	};
#ifdef MANUAL_IFSC
	uint8_t expect17[] =
	    { 0x00, 0xe1, 0x01, 0xb4, 0x54, 0x40, 0x98, 0xc1 };
#endif				/* MANUAL_IFSC */


	int rc;

	rc = usb_control_xmit(0xc1, 0x00, 0x0000, 0x0000, 0x0040, buffer);
	if (memcmp(buffer, expect5, sizeof(expect5)) != 0) {
		syslog(LOG_ERR, "ikey2k fatal: ikey2k urb 5 bad match");
		return USBTOKEN_ERROR;
	}

	rc = usb_control_xmit(0x41, 0x16, 0x0000, 0x0000, 0x0000, buffer);
	if (rc != 0) {
		syslog(LOG_ERR, "ikey2k fatal: urb 6 returned %d", rc);
		return USBTOKEN_ERROR;
	}

	rc = usb_control_xmit(0xc1, 0x01, 0x0000, 0x0000, 0x0002, buffer);
	if (rc != 1 || buffer[0] != 0) {
		syslog(LOG_ERR,
		       "ikey2k fatal: urb 7 returned %d, first byte %hhx",
		       rc, buffer[0]);
		return USBTOKEN_ERROR;
	}

	rc = usb_control_xmit(0x41, 0x16, 0x1901, 0x0000, 0x0000, buffer);
	if (rc != 0) {
		syslog(LOG_ERR, "ikey2k fatal: urb 8 returned %d", rc);
		return USBTOKEN_ERROR;
	}

	rc = usb_control_xmit(0xc1, 0x01, 0x0000, 0x0000, 0x0019, buffer);
	if (rc != 25) {
		syslog(LOG_ERR, "ikey2k fatal: urb 9 returned %d", rc);
		return USBTOKEN_ERROR;
	}

	rc = usb_control_xmit(0x41, 0x16, 0x0000, 0x0000, 0x0000, buffer);
	if (rc != 0) {
		syslog(LOG_ERR, "ikey2k fatal: urb 10 returned %d", rc);
		return USBTOKEN_ERROR;
	}

	rc = usb_control_xmit(0xc1, 0x01, 0x0000, 0x0000, 0x0002, buffer);
	if (rc != 1 || buffer[0] != 0) {
		syslog(LOG_ERR,
		       "ikey2k fatal: urb 11 returned %d, first byte %hhx",
		       rc, buffer[0]);
		return USBTOKEN_ERROR;
	}

	rc = usb_control_xmit(0x41, 0x16, 0x0000, 0x0000, 0x0000, buffer);
	if (rc != 0) {
		syslog(LOG_ERR, "ikey2k fatal: urb 12 returned %d", rc);
		return USBTOKEN_ERROR;
	}

	rc = usb_control_xmit(0xc1, 0x01, 0x0000, 0x0000, 0x0020, buffer);
	if (rc != 1 || buffer[0] != 0) {
		syslog(LOG_ERR,
		       "ikey2k fatal: urb 13 returned %d, first byte %hhx",
		       rc, buffer[0]);
		return USBTOKEN_ERROR;
	}

	rc = usb_control_xmit(0x41, 0x16, 0x1901, 0x0000, 0x0000, buffer);
	if (rc != 0) {
		syslog(LOG_ERR, "ikey2k fatal: urb 14 returned %d", rc);
		return USBTOKEN_ERROR;
	}

	rc = usb_control_xmit(0xc1, 0x01, 0x0000, 0x0000, 0x0019, buffer);
	if (rc != 25) {
		syslog(LOG_ERR, "ikey2k fatal: urb 15 returned %d", rc);
		return USBTOKEN_ERROR;
	}

	usbtoken.atr = malloc(rc);
	if (!usbtoken.atr) {
		syslog(LOG_ERR,
		       "fatal error: ikey2k could not malloc for atr");
		return USBTOKEN_ERROR;
	}
	memcpy(usbtoken.atr, buffer, rc);
	usbtoken.atrlen = rc;

#ifdef MANUAL_IFSC
	buffer[0] = 0x74;
	rc = usb_control_xmit(0x41, 0x17, 0xc100, 0xb401, 0x0001, buffer);
	if (rc != 1) {
		syslog(LOG_ERR, "ikey2k fatal: urb 16 returned %d", rc);
		return USBTOKEN_ERROR;
	}

	rc = usb_control_xmit(0xc1, 0x01, 0x0000, 0x0000, 0x0008, buffer);
	if (memcmp(buffer, expect17, sizeof(expect17)) != 0) {
		syslog(LOG_ERR, "ikey2k fatal: urb 17 bad match");
		return USBTOKEN_ERROR;
	}
#endif				/* MANUAL_IFSC */

	return USBTOKEN_OK;
}

int ikey2k_transmit(uint8_t * buf_send, int len_send,
		    uint8_t * buf_recv, int *len_recv)
{
	int rc;
	int value, index;

	value = buf_send[1] << 8 | buf_send[0];
	index = buf_send[3] << 8 | buf_send[2];

	/* send via usb */
	rc = usb_control_xmit(0x41, 0x17, value, index, len_send - 4,
			      &buf_send[4]);
	if (rc != len_send - 4) {
		syslog(LOG_ERR,
		       "ikey2k fatal: transfer sending failed rc %d len %d",
		       rc, len_send);
		return USBTOKEN_ERROR;
	}

	/* receive answer via usb */
	rc = usb_control_xmit(0xc1, 0x01, 0x0000, 0x0000, usbtoken.ifsc,
			      buf_recv);
	if (rc == -1) {
		syslog(LOG_ERR,
		       "ikey2k fatal: transfer receive failed rc %d", rc);
		return USBTOKEN_ERROR;
	}

	*len_recv = rc;

	return USBTOKEN_OK;
}
