#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include "usbtoken.h"

int eutron_init();
int eutron_transmit(uint8_t * buf_send, int len_send,
		    uint8_t * buf_recv, int *len_recv);

const struct token_drv eutron_drv = {
	.init = eutron_init,
	.transmit = eutron_transmit,
	.max_ifsc = 0x100,
	.timeout = 2710,
	.name = "Eutron CryptoIdentity",
};

char *eutron_products[] = { "73d/5/120", 0 };

int eutron_test(char *product)
{
	char **p;
	if (!product)
		return USBTOKEN_ERROR;

	for (p = eutron_products; *p; p++) {
		if (strcmp(product, *p) == 0) {
			usbtoken.drv = eutron_drv;
			return USBTOKEN_OK;
		}
	}
	return USBTOKEN_ERROR;
}

int eutron_init()
{
	int rc, lr, c;
	uint8_t buffer[1024];
	uint8_t cookie[] = { 0xff, 0x11, 0x98, 0x76 };

	rc = usb_control_xmit(0x41, 0xa3, 0x0000, 0x0000, 0x0000, buffer);
	rc = usb_control_xmit(0x41, 0xa1, 0x0000, 0x0000, 0x0000, buffer);
	rc = usb_control_xmit(0x41, 0xa2, 0x0000, 0x0000, 0x0000, buffer);
	rc = usb_control_xmit(0x41, 0xa0, 0x0000, 0x0000, 0x0000, buffer);
	rc = usb_control_xmit(0x41, 0x09, 0x0000, 0x0000, 0x0000, buffer);

	lr = 0;
	while (1) {
		rc = usb_control_xmit(0xc1, 0x02, 0x0000, 0x0000, 0x0100,
				      &buffer[lr]);
		if (rc == -1) {
			syslog(LOG_ERR,
			       "eutron fatal: receive answer rc %d", rc);
			return USBTOKEN_ERROR;
		}
		lr += rc;
		rc = is_atr_complete(buffer, lr);
		if (rc == USBTOKEN_OK)
			break;
		if (rc != USBTOKEN_INCOMPLETE)
			return rc;
	}
	/* copy atr */
	usbtoken.atr = malloc(lr);
	memcpy(usbtoken.atr, buffer, lr);
	usbtoken.atrlen = lr;

	rc = usb_control_xmit(0x41, 0x01, 0x0000, 0x0000,
			      sizeof(cookie), cookie);

	c = 0;
	lr = 0;
	while (1) {
		rc = usb_control_xmit(0xc1, 0x02, 0x0000, 0x0000, 0x0100,
				      &buffer[lr]);
		if (rc == -1) {
			syslog(LOG_ERR,
			       "eutron fatal: receive answer rc %d", rc);
			return USBTOKEN_ERROR;
		}
		lr += rc;
		if (lr >= 4)
			break;
		c++;
		if (c > 20) {
			syslog(LOG_ERR, "eutron fatal: looping forever");
			return USBTOKEN_ERROR;
		}
	}

	rc = usb_control_xmit(0x41, 0x65, 0x98, 0x0000, 0x0000, buffer);
	rc = usb_control_xmit(0x41, 0xa0, 0x0000, 0x0000, 0x0000, buffer);

	return USBTOKEN_OK;
}


int eutron_transmit(uint8_t * buf_send, int len_send,
		    uint8_t * buf_recv, int *len_recv)
{
	int rc, lr, c;

	rc = usb_control_xmit(0x42, 0x01, 0x0000, 0x0000, len_send,
			      buf_send);
	if (rc != len_send) {
		syslog(LOG_ERR, "eutron fatal: received %d != %d", rc,
		       len_send);
		return USBTOKEN_ERROR;
	}

	lr = 0;
	c = 0;
	while (1) {
		rc = usb_control_xmit(0xc1, 0x02, 0x0000, 0x0000, 0x0100,
				      &buf_recv[lr]);
		syslog(LOG_DEBUG, "rc %d, lr %d, len %d",
		       rc, lr, buf_recv[2]);
		if (rc == -1) {
			syslog(LOG_ERR,
			       "eutron fatal: receive answer rc %d", rc);
			return USBTOKEN_ERROR;
		}
		lr += rc;
		if (lr >= 4 && lr >= buf_recv[2] + 4)
			break;


		c++;
		if (c > 10000) {
			syslog(LOG_ERR,
			       "eutron fatal: timeout after 100s");
			return USBTOKEN_ERROR;
		} else {
			struct timespec x;
			x.tv_sec = 0;
			x.tv_nsec = 50000000;
			nanosleep(&x, NULL);
		}

	}

	*len_recv = lr;

	return USBTOKEN_OK;
}
