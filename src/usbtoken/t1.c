/* imported from SCEZ chipcard library - T=1 routines
 * This is probably the first full free/open source T=1 implementation.
 * Copyright Matthias Bruestle 1999-2002
 * For licensing, see the file LICENCE
 *
 * Copyright 2003 Andreas Jellinghaus <aj@dungeon.inka.de>
 * Copyright 2003 Kevin Stefanik <kstef@mtppi.org>
 */

#include <string.h>
#include <syslog.h>

#include "usbtoken.h"

#define T1_CHECKSUM_LRC      0x00
#define T1_CHECKSUM_CRC      0x01

#define T1_MAX_BLKLEN	3+256+2+2

/* direction */
#define T1_TO_CARD		0x00
#define T1_FROM_CARD		0x01

#define PCB(x) (x[1])
static inline int is_t1_iblock(uint8_t pcb) {	return (pcb & 0x80) == 0x00; }
static inline int is_t1_rblock(uint8_t pcb) {	return (pcb & 0xC0) == 0x80; }
static inline int is_t1_sblock(uint8_t pcb) {	return (pcb & 0xC0) == 0xC0; }

static inline int is_t1_other_error(uint8_t pcb) {return (pcb & 0xef) == 0x82;}

/* we send resync requests and get a response */
static inline int is_t1_resync_req(uint8_t pcb) { return pcb == 0xc0; }
static inline int is_t1_resync_res(uint8_t pcb) { return pcb == 0xe0; }

/* the card can request these */
static inline int is_t1_ifs_req(uint8_t pcb) { return pcb == 0xc1; }
static inline int is_t1_abort_req(uint8_t pcb) { return pcb == 0xc2; }
static inline int is_t1_wtx_req(uint8_t pcb) { return pcb == 0xc3; }

#define T1_PCB_IBLOCK		0x00
#define T1_PCB_RBLOCK		0x80
#define T1_PCB_SBLOCK		0xC0
#define T1_PCB_MASK		0xC0

/* S-Block parameter */
#define	T1_S_RESYNCH		0x00
#define	T1_S_IFS		0x01
#define	T1_S_ABORT		0x02
#define	T1_S_WTX		0x03

#define	T1_S_REQUEST		0x00
#define	T1_S_RESPONSE		0x20

/* R-Block parameter */
#define	T1_R_OK			0x00
#define	T1_R_EDC_ERROR		0x01
#define	T1_R_OTHER_ERROR		0x02

/* ISO STD 3309 */
/* From: medin@catbyte.b30.ingr.com (Dave Medin)
 * Subject: CCITT checksums
 * Newsgroups: sci.electronics
 * Date: Mon, 7 Dec 1992 17:33:39 GMT
 */

/* Correct Table? */

static unsigned short crctab[256] = {
	0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
	0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
	0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
	0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
	0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
	0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
	0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
	0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
	0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
	0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
	0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
	0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
	0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
	0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
	0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
	0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
	0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
	0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
	0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
	0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
	0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
	0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
	0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
	0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
	0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
	0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
	0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
	0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
	0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
	0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
	0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
	0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78
};

/* Returns LRC of data */

uint8_t calculate_lrc(const uint8_t * data, int datalen)
{
	uint8_t lrc = 0x00;
	int i;

	for (i = 0; i < datalen; i++)
		lrc ^= data[i];

	return lrc;
}

/* Calculates CRC of data */

void calculate_crc(const uint8_t * data, int datalen, uint8_t * crc)
{
	int i;
	unsigned short tmpcrc = 0xFFFF;

	for (i = 0; i < datalen; i++)
		tmpcrc =
		    ((tmpcrc >> 8) & 0xFF) ^ crctab[(tmpcrc ^ *data++) &
						    0xFF];

	crc[0] = (tmpcrc >> 8) & 0xFF;
	crc[1] = tmpcrc & 0xFF;
}

/* Appends RC */

int append_rc(uint8_t * data, int *datalen)
{
	if (usbtoken.rc == T1_CHECKSUM_LRC) {
		data[*datalen] = calculate_lrc(data, *datalen);
		*datalen += 1;
		return USBTOKEN_OK;
	} else if (usbtoken.rc == T1_CHECKSUM_CRC) {
		calculate_crc(data, *datalen, data + *datalen);
		*datalen += 2;
		return USBTOKEN_OK;
	}

	return USBTOKEN_ERROR;
}

/* Checks RC. */

int check_rc(const uint8_t * data, int datalen)
{
	uint8_t rc[2];
	uint8_t cmp[2];

	if (usbtoken.rc == T1_CHECKSUM_LRC) {
		/* Check LEN. */
		if ((data[2] + 3 + 1) > datalen)
			return 0;

		rc[1] = data[data[2] + 3];
		cmp[1] = calculate_lrc(data, data[2] + 3);
		return (rc[1] == cmp[1]);
	} else if (usbtoken.rc == T1_CHECKSUM_CRC) {
		/* Check LEN. */
		if ((data[2] + 3 + 2) > datalen)
			return 0;

		calculate_crc(data, data[2] + 3, cmp);
		return (memcmp(data + data[2] + 3, cmp, 2) == 0);
	}

	return 0;
}

/* Builds S-Block */

int build_neg_block(int type, int dir, int param, uint8_t * block,
		    int *len)
{
	block[0] = usbtoken.nad;

	switch (type) {
	case T1_S_RESYNCH:
		block[1] = T1_PCB_SBLOCK | dir | T1_S_RESYNCH;
		block[2] = 0x00;
		*len = 3;
		break;

	case T1_S_IFS:
		block[1] = T1_PCB_SBLOCK | dir | T1_S_IFS;
		block[2] = 0x01;
		block[3] = (uint8_t) param;
		*len = 4;
		break;

	case T1_S_ABORT:
		block[1] = T1_PCB_SBLOCK | dir | T1_S_ABORT;
		block[2] = 0x00;
		*len = 3;
		break;

	case T1_S_WTX:
		block[1] = T1_PCB_SBLOCK | dir | T1_S_WTX;
		block[2] = 0x01;
		block[3] = (uint8_t) param;
		*len = 4;
		break;

	default:
		return (USBTOKEN_ERROR);
	}

	return append_rc(block, len);
}

/* Builds R-Block */

int build_retry_block(int type, uint8_t * block, int *len)
{
	block[0] = usbtoken.nad;
	block[2] = 0x00;

	switch (type) {
	case T1_R_OK:
		if (usbtoken.nr)
			block[1] = 0x90;
		else
			block[1] = 0x80;
		break;

	case T1_R_EDC_ERROR:
		if (usbtoken.nr)
			block[1] = 0x91;
		else
			block[1] = 0x81;
		break;

	case T1_R_OTHER_ERROR:
		if (usbtoken.nr)
			block[1] = 0x92;
		else
			block[1] = 0x82;
		break;

	default:
		return USBTOKEN_ERROR;
	}

	*len = 3;
	return append_rc(block, len);
}

/* Builds I-Block */

int build_data_block(int more, const uint8_t * data, int datalen,
		     uint8_t * block, int *blocklen)
{
	block[0] = usbtoken.nad;

	block[1] = 0x00;
	if (usbtoken.ns)
		block[1] |= 0x40;
	if (more)
		block[1] |= 0x20;

	if (datalen > usbtoken.ifsc)
		return USBTOKEN_ERROR;
	block[2] = (uint8_t) datalen;

	memcpy(block + 3, data, datalen);

	*blocklen = datalen + 3;
	return append_rc(block, blocklen);
}

/* Returns N(R) or N(S) from R/I-Block. */

int get_sequence(const uint8_t * block)
{
	if (is_t1_rblock(PCB(block))) {
		return (block[1] & 0x10) ? 0x01 : 0x00;
	}

	if (is_t1_iblock(PCB(block))) {
		return (block[1] & 0x40) ? 0x01 : 0x00;
	}

	return 0;
}

int t1_process(uint8_t * apdu_cmd, int apdu_cmdlen,
	       uint8_t * apdu_rsp, int *apdu_rsplen)
{
	int sendptr;	/* Points to begining of unsent data. */
	int sendlen;

	uint8_t block[T1_MAX_BLKLEN];
	uint8_t rblock[T1_MAX_BLKLEN];
	int blocklen;
	int rblocklen;

	uint8_t rsp[256 + 3];
	uint8_t rsplen;

	int more;		/* More data to send. */
	int direction;	/* It's ICCs turn to send I-Blocks. */

	int rc;
	int errcntr = 0;
	int rerrcntr = 0;

start:
	*apdu_rsplen = 0;
	direction = T1_TO_CARD;
	rsplen = 0;
	sendptr = 0;
	sendlen = apdu_cmdlen;

	if (sendlen > usbtoken.ifsc) {
		sendlen = usbtoken.ifsc;
		more = 1;
	} else {
		more = 0;
	}
	rc = build_data_block(more, apdu_cmd, sendlen, block, &blocklen);
	if (rc) {
		goto cleanup;
	}
	sendptr += sendlen;

	while (1) {
		rblocklen = sizeof(block);
		rc = usbtoken.drv.transmit(block, blocklen, rblock,
					   &rblocklen);

		/* communication error ? abort. */
		if (rc != USBTOKEN_OK) {
			goto cleanup;
		}

		if (is_t1_other_error(PCB(rblock))) {
			/* other error, request resync */
			rc = build_neg_block(T1_S_RESYNCH, T1_S_REQUEST,
					     rblock[3], block,
					     &blocklen);
			if (rc) {
				goto cleanup;
			}
			continue;
		}

		/* length or rc error ? try three times. */
		if (!check_rc(rblock, rblocklen)) {
			errcntr++;

			if (errcntr > 3) {
				rc = USBTOKEN_ERROR;
				goto cleanup;
			}

			rc = build_retry_block(T1_R_EDC_ERROR,
					       block, &blocklen);
			if (rc) {
				goto cleanup;
			}
			continue;
		}

		/* ah, no length or rc error. reset counter. */
		errcntr = 0;

		/* shall we resend the last block ? try thee times. */
		if (is_t1_rblock(PCB(rblock))) {
			rerrcntr++;

			if (rerrcntr > 3) {
				rc = USBTOKEN_ERROR;
				goto cleanup;
			}

			if (direction == T1_FROM_CARD) {
				/* Card is sending I-Blocks, so send R-Block. */
				rc = build_retry_block(T1_R_OK,
						       block, &blocklen);
				if (rc) {
					goto cleanup;
				}
				continue;
			}

			if (get_sequence(rblock) == usbtoken.ns) {
				/* N(R) is old N(S),
				 * so resend I-Block. */
				sendptr -= sendlen;
			} else {
				/* N(R) is next N(S),
				 * so make next I-Block and send it. */

				/* Check if data available. */
				if (more == 0) {
					/* last block was with pcb: bit6=0
					 * (no more following blocks)
					 * so there is no more data to send.
					 * if the card is waiting for
					 * additional data, then it is wrong.
					 * comm error! */
					rc = USBTOKEN_ERROR;
					goto cleanup;
				}

				/* Change N(S) to new value. */
				usbtoken.ns ^= 1;
				/* Make next I-Block. */

				/* Clear error counter */
				rerrcntr = 0;
			}

			sendlen = apdu_cmdlen - sendptr;
			if (sendlen > usbtoken.ifsc) {
				sendlen = usbtoken.ifsc;
			} else {
				more = 0;
			}
			rc = build_data_block(more, apdu_cmd +
					      sendptr, sendlen, block,
					      &blocklen);
			if (rc) {
				goto cleanup;
			}
			sendptr += sendlen;
			continue;
		}

		/* we shall not resend the last block ? reset error counter. */
		rerrcntr = 0;

		/* I-Block */
		if (is_t1_iblock(PCB(rblock))) {

			if (direction == T1_TO_CARD) {
				/* Change N(S) to new value. */
				usbtoken.ns ^= 1;
			}

			direction = T1_FROM_CARD;

			if (get_sequence(rblock) != usbtoken.nr) {
				/* Card is sending wrong I-Block, so send R-Block. */
				rc = build_retry_block(T1_R_OTHER_ERROR,
						       block, &blocklen);
				if (rc) {
					goto cleanup;
				}
				continue;
			}

			/* Copy data. */
			if (rblock[2] > (256 + 2 - rsplen)) {
				rc = USBTOKEN_ERROR;
				goto cleanup;
			}
			memcpy(rsp + rsplen, rblock + 3, rblock[2]);
			rsplen += rblock[2];

			if ((rblock[1] >> 5) & 1) {
				/* More data available. */

				/* Change N(R) to new value. */
				usbtoken.nr ^= 1;

				/* more fragments to come */
				rc = build_retry_block(T1_R_OK,
						       block, &blocklen);
				if (rc) {
					goto cleanup;
				}
				continue;
			}

			/* Last block. */

			/* Change N(R) to new value. */
			usbtoken.nr ^= 1;

			if (rsplen < 2) {
				rc = USBTOKEN_ERROR;
				goto cleanup;
			}

			memcpy(apdu_rsp, rsp, rsplen);
			*apdu_rsplen = rsplen;

			rc = USBTOKEN_OK;
			goto cleanup;
		}

		if (is_t1_resync_res(PCB(rblock))) {
			/* resync: start from scratch */
			goto start;
		}

		if (is_t1_wtx_req(PCB(rblock))) {
			/* request waiting time extension */
			rc = build_neg_block(T1_S_WTX,
					     T1_S_RESPONSE, rblock[3],
					     block, &blocklen);
			if (rc) {
				goto cleanup;
			}
			continue;
		}

		if (is_t1_ifs_req(PCB(rblock))) {
			/* the card want's to set a different ifsc. */
			/* acknowledge */
			rc = build_neg_block(T1_S_IFS,
					     T1_S_RESPONSE, rblock[3],
					     block, &blocklen);
			if (rc) {
				goto cleanup;
			}

			usbtoken.ifsc = rblock[3];
			continue;
		}

		if (is_t1_abort_req(PCB(rblock))) {
			/* S-Block ABORT Request */
			rc = USBTOKEN_ERROR;
			goto cleanup;
		}

		syslog(LOG_ERR, "t1 fatal: unknown pcb %d",PCB(rblock));
		rc = USBTOKEN_ERROR;
		goto cleanup;
	}

      cleanup:
	memset(block, 0, sizeof(block));
	memset(rblock, 0, sizeof(rblock));
	memset(rsp, 0, sizeof(rsp));
	return rc;
}
