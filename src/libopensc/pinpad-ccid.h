/*
 * pinpad-ccid.h: CCID ifdhandler control codes for pinpad support.
 *
 * Copy from pcsc-lite package created by Ludovic Rousseau
 *
 * Martin Paljak <martin@paljak.pri.ee>
 */

#ifdef MP_CCID_PINPAD
#ifndef _PINPAD_CCID_H
#define _PINPAD_CCID_H

#define SCARD_CTL_CODE(code) (0x42000000 + (code))

#define IOCTL_SMARTCARD_VENDOR_IFD_EXCHANGE     SCARD_CTL_CODE(1)
#define IOCTL_SMARTCARD_VENDOR_VERIFY_PIN       SCARD_CTL_CODE(2)
#define IOCTL_SMARTCARD_VENDOR_MODIFY_PIN       SCARD_CTL_CODE(3)
#define IOCTL_SMARTCARD_VENDOR_TRANSFER_PIN     SCARD_CTL_CODE(4)

#define SC_CCID_PIN_TIMEOUT        30

#define SC_CCID_PIN_ENCODING_BIN   0x00
#define SC_CCID_PIN_ENCODING_BCD   0x01
#define SC_CCID_PIN_ENCODING_ASCII 0x02

#define SC_CCID_PIN_UNITS_BYTES    0x80

/* CCID reader operation for pin commands */ 
int ccid_pin_cmd(struct sc_reader *, sc_slot_info_t *, struct sc_pin_cmd_data *);

#endif /* _PINPAD_CCID_H */
#endif /* MP_CCID_PINPAD */
