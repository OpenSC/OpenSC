#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "usbtoken.h"

int etoken_init();
int etoken_transmit(uint8_t * buf_send, int len_send,
		    uint8_t * buf_recv, int *len_recv);

const struct token_drv etoken_drv = {
	.init = etoken_init,
	.transmit = etoken_transmit,
	.max_ifsc = 32,		/* higher ifsc causes etoken to crash */
	.timeout = 10000,
	.name = "Aladdin eToken PRO",
};

char *etoken_products[] = { "529/50c/100", "529/514/100", 0 };

int etoken_test(char *product)
{
	char **p;
	if (!product)
		return USBTOKEN_ERROR;

	for (p = etoken_products; *p; p++) {
		if (strcmp(product, *p) == 0) {
			usbtoken.drv = etoken_drv;
			return USBTOKEN_OK;
		}
	}
	return USBTOKEN_ERROR;
}

int etoken_init()
{
	int rc, len;
	uint8_t buffer[1024];
	uint8_t cookie[] = { 0x00, 0x00, 0x01, 0x00, 0x88, 0x13 };

	/* request atr */
	rc = usb_control_xmit(0x40, 0x01, 0x0000, 0x0000, 0x0000, buffer);

	/* receive atr */
	rc = usb_control_xmit(0xc0, 0x81, 0x0000, 0x0000, 0x0023, buffer);
	if ((rc == -1) || (rc == 0)) {
		/* failed, we should get an atr */
		syslog(LOG_ERR, "etoken fatal: no ATR received");
		return USBTOKEN_ERROR;
	}

	len = buffer[0];
	if (rc < len) {
		/* failed, we need to get a whole atr */
		syslog(LOG_ERR, "etoken fatal: wrong ATR");
		return USBTOKEN_ERROR;
	}

	/* copy atr */
	usbtoken.atr = malloc(len);
	memcpy(usbtoken.atr, buffer + 1, len);
	usbtoken.atrlen = len;

	/* ask for something strange */
	rc = usb_control_xmit(0x40, 0x03, 0x0000, 0x0000, 0x0000, buffer);

	/* receive strange data */
	rc = usb_control_xmit(0xc0, 0x83, 0x0000, 0x0000, 0x000d, buffer);

	/* send something strange */
	memcpy(buffer, cookie, sizeof(cookie));
	rc = usb_control_xmit(0x40, 0x02, 0x0000, 0x0000, sizeof(cookie),
			      buffer);
	if (rc != sizeof(cookie)) {
		/* the whole cookie should have been send */
		syslog(LOG_ERR, "etoken fatal: cookie not completly send: rc=%d", rc);
		return USBTOKEN_ERROR;
	}

	/* get strange answer */
	rc = usb_control_xmit(0xc0, 0x82, 0x0000, 0x0000, 0x0001, buffer);
	if (rc != 1) {
		/* we should have got one byte */
		syslog(LOG_ERR, "etoken fatal: did not receive one byte response to cookie: rc=%d", rc);
		return USBTOKEN_ERROR;
	}

	if (buffer[0] != 0) {
		/* the answer should have bin 0x00 */
		syslog(LOG_ERR, "etoken fatal: received one byte response to cookie but it is: %d!=0", buffer[0]);
		return USBTOKEN_ERROR;
	}

	return USBTOKEN_OK;
}


int etoken_transmit(uint8_t * buf_send, int len_send,
		    uint8_t * buf_recv, int *len_recv)
{
	int rc;
	uint8_t wtx_resp[] = { 0xe0, 0xc3, 0x01, 0x01, 0xc3 };
	uint8_t wtx_send[] = { 0x00, 0x00, 0x01, 0x00, 0x10, 0x27 };
	uint8_t wtx_recv[] = { 0x00 };

	/* waiting time extension works without this,
	 * but the windows driver send a magic sequence first
	 * and asks for a magic answer, so we copied this */
	if (len_send == sizeof(wtx_resp)
	    && memcmp(buf_send, wtx_resp, sizeof(wtx_resp) == 0)) {

		rc = usb_control_xmit(0x40, 0x02, 0x0000, 0x0000,
				      sizeof(wtx_send), wtx_send);

		if (rc != sizeof(wtx_send)) {
			syslog(LOG_ERR,
			       "etoken fatal: wtx special send'd wrong len %d",
			       rc);
			return USBTOKEN_ERROR;
		}
		rc = usb_control_xmit(0xc0, 0x82, 0x0000, 0x0000, 01,
				      buf_recv);
		if (rc != sizeof(wtx_recv)) {
			syslog(LOG_ERR,
			       "etoken fatal: wtx special recv'd wrong len %d",
			       rc);
			return USBTOKEN_ERROR;
		}
		if (memcmp(buf_recv, wtx_recv, sizeof(wtx_recv) != 0)) {
			syslog(LOG_ERR,
			       "etoken fatal: wtx special recv does not match");
			return USBTOKEN_ERROR;

		}
	}

	/* send via usb */
	rc = usb_control_xmit(0x40, 0x06, 0x0000, 0x0000, len_send,
			      buf_send);
	if (rc != len_send) {
		syslog(LOG_ERR, "etoken fatal: received %d != %d",
		       rc, len_send);
		return USBTOKEN_ERROR;
	}

	/* receive answer via usb */
	rc = usb_control_xmit(0xc0, 0x86, 0x0000, 0x0000,
			      usbtoken.ifsc + 5, buf_recv);
	if (rc == -1) {
		syslog(LOG_ERR, "etoken fatal: receive answer rc %d", rc);
		return USBTOKEN_ERROR;
	}

	*len_recv = rc;
	return USBTOKEN_OK;
}
