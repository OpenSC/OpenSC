#include <stdint.h>
#include <syslog.h>

#include "usbtoken.h"

int is_atr_complete(uint8_t* buffer, int lr)
{
	int hc, i, td, rc;

	/* TS, T0 and checksum are always required */
	if (lr < 3)
		return USBTOKEN_INCOMPLETE;

	if (buffer[0] != 0x3b) {
		syslog(LOG_ERR,
		       "is_atr_complete fatal: atr not direct convention, TS %d",
		       buffer[0]);
		return USBTOKEN_ERROR;
	}

	hc = buffer[1] & 0xf;

	/* ok, first round, starting with byte 2, for T=0 */
	i = 2;
	td = buffer[1] >> 4;

	while (td) {
		if (td & 0x01)
			i++;	/* TAn */
		if (td & 0x02)
			i++;	/* TBn */
		if (td & 0x04)
			i++;	/* TCn */
		if (td & 0x08) {	/* TDn */
			if (lr < i)
				return USBTOKEN_INCOMPLETE;
			td = buffer[i] >> 4;
			i++;
		} else {
			td = 0;
		}
	}

	if (lr < i + hc + 1)
		return USBTOKEN_INCOMPLETE;

	lr = i + hc + 1;

	rc = 0;
	for (i = 1; i < lr; i++) {
		rc ^= buffer[i];
	}
	if (rc != 0) {
		syslog(LOG_ERR, "is_atr_complete fatal: checksum invalid");
		return USBTOKEN_ERROR;
	}

	return USBTOKEN_OK;
}

int parse_atr()
{
	int hc, i, td, proto, rc;

	if (usbtoken.atr == 0) {
		syslog(LOG_ERR, "parse_atr fatal: no ATR received");
		return USBTOKEN_ERROR;
	}

	if (usbtoken.atrlen < 1) {
		syslog(LOG_ERR, "parse_atr fatal: TS missing");
		return USBTOKEN_ERROR;
	}

	if (usbtoken.atr[0] != 0x3b) {
		syslog(LOG_ERR,
		       "parse_atr fatal: atr not direct convention, TS %d",
		       usbtoken.atr[0]);
		return USBTOKEN_ERROR;
	}

	if (usbtoken.atrlen < 2) {
		syslog(LOG_ERR, "parse_atr fatal: T0 missing");
		return USBTOKEN_ERROR;
	}

	hc = usbtoken.atr[1] & 0xf;

	/* ok, first round, starting with byte 2, for T=0 */
	i = 2;
	proto = 0;
	td = usbtoken.atr[1] >> 4;

	if (td & 0x1) {		/* TA1 */
		/* timing stuff, i don't care */
		i++;
	}

	if (td & 0x02) {	/* TB1 */
		/* vpp voltage, obsolete */
		i++;
	}

	if (td & 0x04) {	/* TC1 */
		/* extra guard time, i don't care */
		i++;
	}

	if (td & 0x08) {	/* TD1 */
		if (usbtoken.atrlen < i) {
			syslog(LOG_ERR, "parse_atr fatal: TD1 missing");
			return USBTOKEN_ERROR;
		}
		td = usbtoken.atr[i] >> 4;
		proto = usbtoken.atr[i] & 0xf;
		i++;
	} else {
		td = 0;
	}

	if (td & 0x01) {	/* TA2 */
		/* global interface character, for PTS */
		i++;
	}

	if (td & 0x02) {	/* TB2 */
		/* vpp voltage */
		i++;
	}

	if (td & 0x04) {	/* TC2 */
		/* work waiting time */
		i++;
	}

	if (td & 0x08) {	/* TD2 */
		if (usbtoken.atrlen < i) {
			syslog(LOG_ERR, "parse_atr fatal: TD2 missing");
			return USBTOKEN_ERROR;
		}
		td = usbtoken.atr[i] >> 4;
		proto = usbtoken.atr[i] & 0xf;
		i++;
	} else {
		td = 0;
	}

	while (td) {
		if (td & 0x01) {	/* TAn */
			/* ifsc */
			if (usbtoken.atrlen < i) {
				syslog(LOG_ERR,
				       "parse_atr fatal: TAn missing");
				return USBTOKEN_ERROR;
			}
			if (proto == 1) {
				usbtoken.ifsc = usbtoken.atr[i];
			}
			i++;
		}

		if (td & 0x02) {	/* TBn */
			/* character waiting time */
			i++;
		}

		if (td & 0x04) {	/* TCn */
			/* lrc/crc */
			if (usbtoken.atrlen < i) {
				syslog(LOG_ERR,
				       "parse_atr fatal: TAn missing");
				return USBTOKEN_ERROR;
			}
			if (proto == 1) {
				usbtoken.rc = usbtoken.atr[i] & 0x1;
			}
			i++;
		}

		if (td & 0x08) {	/* TDn */
			if (usbtoken.atrlen < i) {
				syslog(LOG_ERR,
				       "parse_atr fatal: TDn missing");
				return USBTOKEN_ERROR;
			}
			td = usbtoken.atr[i] >> 4;
			proto = usbtoken.atr[i] & 0xf;
			i++;
		} else {
			td = 0;
		}
	}

	if (usbtoken.atrlen != i + hc + 1) {
		syslog(LOG_ERR,
		       "parse_atr fatal: length should be %d, is %d",
		       i + hc, usbtoken.atrlen);
		return USBTOKEN_ERROR;
	}

	rc = 0;
	for (i = 1; i < usbtoken.atrlen; i++) {
		rc ^= usbtoken.atr[i];
	}
	if (rc != 0) {
		syslog(LOG_ERR, "parse_atr fatal: checksum invalid");
		return USBTOKEN_ERROR;
	}

	return USBTOKEN_OK;
}

int increase_ifsc()
{
	uint8_t buf_send[256];
	uint8_t buf_recv[256];
	uint8_t max_ifsc;
	int len_recv, rc;
	int i;

	max_ifsc = usbtoken.ifsc;
	if (max_ifsc > usbtoken.drv.max_ifsc) {
		max_ifsc = usbtoken.drv.max_ifsc;
	}

	usbtoken.ifsc = 0x20;

	if (max_ifsc == 0x20) {
		return USBTOKEN_OK;
	};

	buf_send[0] = 0x00;
	buf_send[1] = 0xc1;
	buf_send[2] = 0x01;
	buf_send[3] = max_ifsc;

	rc = 0;
	for (i = 0; i < 4; i++) {
		rc ^= buf_send[i];
	}
	buf_send[4] = rc;

	len_recv = sizeof(buf_recv);
	rc = usbtoken.drv.transmit(buf_send, 5, buf_recv, &len_recv);
	if (rc != USBTOKEN_OK)
		return rc;

	if (len_recv < 5) {
		syslog(LOG_ERR,
		       "increase_ifsc fatal: expected (at least) 5 byte answer, got %d",
		       len_recv);
		return USBTOKEN_ERROR;
	}

	rc = 0;
	for (i = 0; i < 4 + buf_recv[2]; i++) {
		rc ^= buf_recv[i];
	}

	if (rc != 0) {
		syslog(LOG_ERR, "increase_ifsc fatal: checksum mismatch");
		return USBTOKEN_ERROR;
	}

	if (buf_recv[0] != 0x0 || buf_recv[1] != 0xe1
	    || buf_recv[2] != 0x01) {
		syslog(LOG_ERR,
		       "increase_ifsc fatal: did not get ifsc answer");
		return USBTOKEN_ERROR;
	}

	usbtoken.ifsc = buf_recv[3];
	return USBTOKEN_OK;
}
