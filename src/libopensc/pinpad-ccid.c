/* 
 * OpenSC pinpad support for CCID compatible readers.
 *
 * These functions build CCID PIN control blocks to be used with
 * CCID compatible pinpad readers.
 * Currently known to work only with libccid under unices via SCardControl().
 *
 * Tested with: SPR532 with firmware 5.04, ccid-0.9.2mp1, EstEID, opensc-0.9.4mp3 (CVS)
 *
 * (C) 2004 Martin Paljak <martin@paljak.pri.ee>
 */
#ifdef MP_CCID_PINPAD
#include "internal.h"
#include "pinpad-ccid.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

/* Build a pin verification CCID block + APDU */
int ccid_build_verify_pin_block(u8 * buf, size_t * size, struct sc_pin_cmd_data *data)
{
	size_t buflen, count = 0;
	sc_apdu_t *apdu = data->apdu;
	u8 tmp;
	buflen = sizeof(buf);

	/* CCID PIN verification control message */
	buf[count++] = SC_CCID_PIN_TIMEOUT;	/* bTimeOut */

	tmp = 0x00;
	if (data->pin1.encoding == SC_PIN_ENCODING_ASCII)
		tmp |= SC_CCID_PIN_ENCODING_ASCII;
	else if (data->pin1.encoding == SC_PIN_ENCODING_BCD)
		tmp |= SC_CCID_PIN_ENCODING_BCD;
	else
		return SC_ERROR_NOT_SUPPORTED;
	/* Only byte-aligend cards are cupported */	
	tmp |= SC_CCID_PIN_UNITS_BYTES;
	tmp |= (data->pin1.length_offset - 5) << 3;
	buf[count++] = tmp;	/* bmFormatString */

	/* Ignored */
	buf[count++] = 0x00;	/* bmPINBlockString */
	/* Ignored */
	buf[count++] = 0x00;	/* bmPINLengthFormat */

	if (!data->pin1.min_length || !data->pin1.max_length)
		return SC_ERROR_INVALID_PIN_LENGTH;
	buf[count++] = data->pin1.max_length;	/* wPINMaxExtraDigit: max */	
	buf[count++] = data->pin1.min_length;	/* wPINMaxExtraDigit: min */

	buf[count++] = 0x02;	/* bEntryValidationCondition, keypress only */

	/* ignore language and T=1 parameters. */
	buf[count++] = 0x00;	/* bNumberMessage */
	buf[count++] = 0x00;	/* wLangId */
	buf[count++] = 0x00;	/* " */
	buf[count++] = 0x00;	/* bMsgIndex */
	buf[count++] = 0x00;	/* bTeoPrologue */
	buf[count++] = 0x00;	/* " */
	buf[count++] = 0x00;	/* " */

	/* APDU itself */
	buf[count++] = apdu->cla;
	buf[count++] = apdu->ins;
	buf[count++] = apdu->p1;
	buf[count++] = apdu->p2;
	
	/* If the effective PIN length offset == 4 (Lc) the condition is
	 * not possible to handle with standard CCID capabilities, as
	 * CCID defines all reader insertion offsets as relative to the first
	 * byte _after_ Lc ... Too bad.
	 * Do a special reader-dependant trick that is known to work with SPR532
	 * reader and previously mentioned library versions (We omit the APDU
	 * from the command block and send only APDU headers)
	 *
	 * Otherwise we assume a proper APDU and CCID compatible operations
	 * and the APDU is copied verbatim.
    */
	if (data->pin1.length_offset > 4) {
		memcpy(&buf[count], apdu->data, apdu->datalen);
		count += apdu->datalen;	
	}
	
	*size = count;
	return SC_SUCCESS;
}

/* Do the PIN command */
int
ccid_pin_cmd(struct sc_reader *reader, sc_slot_info_t * slot,
	     struct sc_pin_cmd_data *data)
{
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE], sbuf[SC_MAX_APDU_BUFFER_SIZE];
	size_t rcount = sizeof(rbuf), scount = 0;
	int r;
	unsigned long code;
	sc_apdu_t *apdu;

	SC_FUNC_CALLED(reader->ctx, 3);

	/* The APDU must be provided by the card driver */
	if (!data->apdu) {
		sc_error(reader->ctx, "No APDU provided for CCID PinPad verification!");
		return SC_ERROR_NOT_SUPPORTED;
	}
	
	/* Only T=0 is currently supported */
	if (slot->active_protocol != SC_PROTO_T0) {
		sc_error(reader->ctx, "Only T=0 is currently supported!");
		return SC_ERROR_NOT_SUPPORTED;
	}

	apdu = data->apdu;
	switch (data->cmd) {
	case SC_PIN_CMD_VERIFY:
		r = ccid_build_verify_pin_block(sbuf, &scount, data);
		code = IOCTL_SMARTCARD_VENDOR_VERIFY_PIN;
		break;
	case SC_PIN_CMD_CHANGE:
	case SC_PIN_CMD_UNBLOCK:
		return SC_ERROR_NOT_SUPPORTED;
		break;
	default:
		sc_error(reader->ctx, "Unknown PIN command %d", data->cmd);
		return SC_ERROR_NOT_SUPPORTED;
	}

	/* If CCID block building failed, we fail too */
	SC_TEST_RET(reader->ctx, r, "CCID PIN block building failed!");

	/* The slot must be manually locked, as the control does not pass through card.c
	 * wrappers that lock the card (card_transmit is not OK in this case, as it assumes
	 * a proper APDU as a parameter, not a arbitary binary blob to be sent to the reader)
	 */
	r = reader->ops->lock(reader, slot);
	SC_TEST_RET(reader->ctx, r, "CCID PIN: Could not lock!");
	r = reader->ops->transmit(reader, slot, sbuf, scount, rbuf, &rcount, code);
	reader->ops->unlock(reader, slot);

	SC_TEST_RET(reader->ctx, r, "CCID PIN block transmit failed!");
	
	/* We expect only two bytes of result data (SW1 and SW2) */
	if (rcount != 2) {
		SC_FUNC_RETURN(reader->ctx, 2, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	}
	
	/* Extract the SWs for the result APDU */
	apdu->sw1 = (unsigned int) rbuf[rcount - 2];
	apdu->sw2 = (unsigned int) rbuf[rcount - 1];
	
	/* PIN command completed, all is good */
	return SC_SUCCESS;
}
#endif /* MP_CCID_PINPAD */
