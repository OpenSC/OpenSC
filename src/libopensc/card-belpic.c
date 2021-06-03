/*
 * card-belpic.c: Support for Belgium EID card
 *
 * Copyright (C) 2003, Zetes Belgium
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/*     About the Belpic (Belgian Personal Identity Card) card
 *
 * The Belpic card is a Cyberflex Java card, so you normally communicate
 * with an applet running on the card. In order to support a pkcs15 file
 * structure, an  applet (the Belpic applet) has been build that emulates
 * this. So the card's behaviour is specific for this Belpic applet, that's
 * why a separate driver has been made.
 *
 * The card contains the citizen's ID data (name, address, photo, ...) and
 * her keys and certs. The ID data are in a separate directory on the card and
 * are not handled by this software. For the cryptographic data (keys and certs)
 * a pkcs#15 structure has been chosen and they can be accessed and used
 * by the OpenSC software.
 *
 * The current situation about the cryptographic data is: there is 1 PIN
 * that protects 2 private keys and corresponding certs. Then there is a
 * CA cert and the root cert. The first key (Auth Key) can be used for
 * authentication, the second one (NonRep Key) for non repudiation purposes
 * (so it can be used as an alternative to manual signatures).
 *
 * There are some special things to note, which all have some consequences:
 * (1) the SELECT FILE command doesn't return any FCI (file length, type, ...)
 * (2) the NonRep key needs a VERIFY PIN before a signature can be done with it
 * (3) pin pad readers had to be supported by a proprietary interface (as at
 *     that moment no other solution was known/available/ready)
 * The consequences are:
 *
 * For (1): we let the SELECT FILE command return that the file length is
 * a fixed large number and that each file is a transparent working EF
 * (except the root dir 3F 00). This way however, there is a problem with the
 * sc_read_binary() function that will only stop reading until it receives
 * a 0. Therefore, we use the 'next_idx' trick. Or, if that might fail
 * and so a READ BINARY past the end of file is done, length 0 is returned
 * instead of an error code.
 *
 * For (2), we decided that a GUI for asking the PIN would be the best
 * thing to do (another option would be to make 2 virtual slots but that
 * causes other problems and is less user-friendly). A GUI being popped up
 * by the pkcs11 lib before each NonRep signature has another important
 * security advantage: applications that cache the PIN can't silently do
 * a NonRep signature because there will always be the GUI.
 *
 * For (3), we link dynamically against a pin pad lib (DLL) that implements the
 * proprietary API for a specific pin pad. For each pin pad reader (identified
 * by it's PC/SC reader name), a pin pad lib corresponds. Some reader/lib
 * name pairs are hardcoded, and others can be added in the config file.
 * Note that there's also a GUI used in this case: if a signature with the
 * NonRep key is done: a dialog box is shown that asks the user to enter
 * her PIN on the pin pad reader in order to make a legally valid signature.
 *
 * Further the (current) Belpic card as quite some limitations:
 * no key pair generation or update of data except after establishing a Secure
 * Channel or CTV-authentication (which can only be done at the municipalities),
 * no encryption. The result is that only a very limited amount of functions
 * is/had to be implemented to get the pkcs11 library working.
 *
 * About the belpic_set_language: the RA-PC software (including the pkcs11 lib)
 * in the Brussels' communities should be able to change the language of the GUI
 * messages. So the language set by this function takes priority on all other
 * language-selection  functionality.
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include "internal.h"
#include "log.h"

/* To be removed */
#include <time.h>
static long t1, t2, tot_read = 0, tot_dur = 0, dur;

#define BELPIC_VERSION			"1.4"

/* Most of the #defines here are also present in the pkcs15 files, but
 * because this driver has no access to them, it's hardcoded here. If
 * other Belpic cards with other 'settings' appear, we'll have to move
 * these #defines to the struct belpic_priv_data */
#define BELPIC_MAX_FILE_SIZE		65535
#define BELPIC_PIN_BUF_SIZE		8
#define BELPIC_MIN_USER_PIN_LEN		4
#define BELPIC_MAX_USER_PIN_LEN		12
#define BELPIC_PIN_ENCODING		SC_PIN_ENCODING_GLP
#define BELPIC_PAD_CHAR			0xFF
#define BELPIC_KEY_REF_NONREP		0x83

/* Data in the return value for the GET CARD DATA command:
 * All fields are one byte, except when noted otherwise.
 *
 * See §6.9 in
 * https://github.com/Fedict/eid-mw/blob/master/doc/sdk/documentation/Public_Belpic_Applet_v1%207_Ref_Manual%20-%20A01.pdf
 * for the full documentation on the GET CARD DATA command.
 */
// Card serial number (16 bytes)
#define BELPIC_CARDDATA_OFF_SERIALNUM 0
// "Component code"
#define BELPIC_CARDDATA_OFF_COMPCODE 16
// "OS number"
#define BELPIC_CARDDATA_OFF_OSNUM 17
// "OS version"
#define BELPIC_CARDDATA_OFF_OSVER 18
// "Softmask number"
#define BELPIC_CARDDATA_OFF_SMNUM 19
// "Softmask version"
#define BELPIC_CARDDATA_OFF_SMVER 20
// Applet version
#define BELPIC_CARDDATA_OFF_APPLETVERS 21
// Global OS version (2 bytes)
#define BELPIC_CARDDATA_OFF_GL_OSVE 22
// Applet interface version
#define BELPIC_CARDDATA_OFF_APPINTVERS 24
// PKCS#1 support version
#define BELPIC_CARDDATA_OFF_PKCS1 25
// Key exchange version
#define BELPIC_CARDDATA_OFF_KEYX 26
// Applet life cycle (Should always be 0F for released cards, is 07 when not issued yet)
#define BELPIC_CARDDATA_OFF_APPLCYCLE 27
// Full length of reply
#define BELPIC_CARDDATA_RESP_LEN 28

/* Used for a trick in select file and read binary */
static size_t next_idx = (size_t)-1;

static const struct sc_atr_table belpic_atrs[] = {
	/* Applet V1.1 */
	{ "3B:98:13:40:0A:A5:03:01:01:01:AD:13:11", NULL, NULL, SC_CARD_TYPE_BELPIC_EID, 0, NULL },
	/* Applet V1.0 with new EMV-compatible ATR */
	{ "3B:98:94:40:0A:A5:03:01:01:01:AD:13:10", NULL, NULL, SC_CARD_TYPE_BELPIC_EID, 0, NULL },
	/* Applet beta 5 + V1.0 */
	{ "3B:98:94:40:FF:A5:03:01:01:01:AD:13:10", NULL, NULL, SC_CARD_TYPE_BELPIC_EID, 0, NULL },
	{ NULL, NULL, NULL, 0, 0, NULL }
};

static struct sc_card_operations belpic_ops;
static struct sc_card_driver belpic_drv = {
	"Belpic cards",
	"belpic",
	&belpic_ops,
	NULL, 0, NULL
};
static const struct sc_card_operations *iso_ops = NULL;

static int get_carddata(sc_card_t *card, u8* carddata_loc, unsigned int carddataloc_len)
{
	sc_apdu_t apdu;
	u8 carddata_cmd[] = { 0x80, 0xE4, 0x00, 0x00, 0x1C };
	int r;

	assert(carddataloc_len == BELPIC_CARDDATA_RESP_LEN);

	r = sc_bytes2apdu(card->ctx, carddata_cmd, sizeof(carddata_cmd), &apdu);
	if(r) {
		sc_log(card->ctx,  "bytes to APDU conversion failed: %d\n", r);
		return r;
	}

	apdu.resp = carddata_loc;
	apdu.resplen = carddataloc_len;

	r = sc_transmit_apdu(card, &apdu);
	if(r) {
		sc_log(card->ctx,  "GetCardData command failed: %d\n", r);
		return r;
	}

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if(r) {
		sc_log(card->ctx,  "GetCardData: card returned %d\n", r);
		return r;
	}
	if(apdu.resplen < carddataloc_len) {
		sc_log(card->ctx, 
			 "GetCardData: card returned %"SC_FORMAT_LEN_SIZE_T"u bytes rather than expected %d\n",
			 apdu.resplen, carddataloc_len);
		return SC_ERROR_WRONG_LENGTH;
	}

	return 0;
}

static int belpic_match_card(sc_card_t *card)
{
	int i;

	i = _sc_match_atr(card, belpic_atrs, &card->type);
	if (i < 0)
		return 0;
	return 1;
}

static int belpic_init(sc_card_t *card)
{
	int key_size = 1024;

	sc_log(card->ctx,  "Belpic V%s\n", BELPIC_VERSION);

	if (card->type < 0)
		card->type = SC_CARD_TYPE_BELPIC_EID;	/* Unknown card: assume it's the Belpic Card */

	card->cla = 0x00;
	if (card->type == SC_CARD_TYPE_BELPIC_EID) {
		u8 carddata[BELPIC_CARDDATA_RESP_LEN];
		memset(carddata, 0, sizeof(carddata));

		if(get_carddata(card, carddata, sizeof(carddata)) < 0) {
			return SC_ERROR_INVALID_CARD;
		}
		if (carddata[BELPIC_CARDDATA_OFF_APPLETVERS] >= 0x17) {
			key_size = 2048;
		}
		_sc_card_add_rsa_alg(card, key_size,
				SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_NONE, 0);
	}

	/* State that we have an RNG */
	card->caps |= SC_CARD_CAP_RNG;

	card->max_pin_len = BELPIC_MAX_USER_PIN_LEN;

	return 0;
}

static int belpic_select_file(sc_card_t *card,
			      const sc_path_t *in_path, sc_file_t **file_out)
{
	sc_apdu_t apdu;
	u8 pathbuf[SC_MAX_PATH_SIZE], *path = pathbuf;
	int r, pathlen;
	sc_file_t *file = NULL;

	assert(card != NULL && in_path != NULL);
	memcpy(path, in_path->value, in_path->len);
	pathlen = in_path->len;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xA4, 0x08, 0x0C);

	apdu.lc = pathlen;
	apdu.data = path;
	apdu.datalen = pathlen;

	apdu.resplen = 0;
	apdu.le = 0;

	r = sc_transmit_apdu(card, &apdu);

	LOG_TEST_RET(card->ctx, r, "Select File APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);

	next_idx = (size_t)-1;		/* reset */

	if (file_out != NULL) {
		file = sc_file_new();
		file->path = *in_path;
		if (pathlen >= 2)
			file->id = (in_path->value[pathlen - 2] << 8) | in_path->value[pathlen - 1];
		file->size = BELPIC_MAX_FILE_SIZE;
		file->shareable = 1;
		file->ef_structure = SC_FILE_EF_TRANSPARENT;
		if (pathlen == 2 && memcmp("\x3F\x00", in_path->value, 2) == 0)
			file->type = SC_FILE_TYPE_DF;
		else
			file->type = SC_FILE_TYPE_WORKING_EF;
		*file_out = file;
	}

	return 0;
}

static int belpic_read_binary(sc_card_t *card,
			      unsigned int idx, u8 * buf, size_t count, unsigned long flags)
{
	int r;

	if (next_idx == idx)
		return 0;	/* File was already read entirely */

	t1 = clock();
	r = iso_ops->read_binary(card, idx, buf, count, flags);
	t2 = clock();

	/* If the 'next_idx trick' shouldn't work, we hope this error
	 * means that an attempt was made to read beyond the file's
	 * contents, so we'll return 0 to end the loop in sc_read_binary()*/
	if (r == SC_ERROR_INCORRECT_PARAMETERS)
		return 0;

	if (r >= 0 && (size_t)r < count)
		next_idx = idx + (size_t)r;

	dur = t2 - t1;
	tot_dur += dur;
	tot_read += r;
	return r;
}

static int belpic_pin_cmd(sc_card_t *card, struct sc_pin_cmd_data *data, int *tries_left)
{
	data->pin1.encoding = data->pin2.encoding = BELPIC_PIN_ENCODING;
	data->pin1.pad_char = data->pin2.pad_char = BELPIC_PAD_CHAR;
	data->pin1.min_length = data->pin2.min_length = BELPIC_MIN_USER_PIN_LEN;
	data->pin1.max_length = data->pin2.max_length = BELPIC_MAX_USER_PIN_LEN;
	data->apdu = NULL;

	return iso_ops->pin_cmd(card, data, tries_left);
}

static int belpic_set_security_env(sc_card_t *card,
				   const sc_security_env_t *env, int se_num)
{
	sc_apdu_t apdu;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	int r;

	sc_log(card->ctx,  "belpic_set_security_env(), keyRef = 0x%0x, algo = 0x%0x\n",
		 *env->key_ref, env->algorithm_flags);

	assert(card != NULL && env != NULL);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0, 0);
	switch (env->operation) {
	case SC_SEC_OPERATION_SIGN:
		apdu.p1 = 0x41;
		apdu.p2 = 0xB6;
		sbuf[0] = 0x04;	/* length of the following data */
		sbuf[1] = 0x80;	/* tag for algorithm reference */
		if (env->algorithm_flags & SC_ALGORITHM_RSA_PAD_PKCS1)
			sbuf[2] = 0x01;
		else if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA1)
			sbuf[2] = 0x02;
		else if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_MD5)
			sbuf[2] = 0x04;
		else {
			sc_log(card->ctx,  "Set Sec Env: unsupported algo 0X%0X\n",
				 env->algorithm_flags);
			return SC_ERROR_INVALID_ARGUMENTS;
		}
		sbuf[3] = 0x84;	/* tag for private key reference */
		sbuf[4] = *env->key_ref;	/* key reference */
		apdu.lc = 5;
		apdu.datalen = 5;
		break;
	default:
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	apdu.le = 0;
	apdu.data = sbuf;
	apdu.resplen = 0;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "Set Security Env APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card's Set Security Env command returned error");

	/* If a NonRep signature will be done, ask to enter a PIN. It would be more
	 * logical to put the code below into the compute signature function because
	 * a Verify Pin call must immediately precede a Compute Signature call.
	 * It's not done because the Compute Signature is completely ISO7816 compliant
	 * so we use the iso7816_compute_signature() function, and because this function
	 * doesn't know about the key reference.
	 * It's not a problem either, because this function is (for pkcs11) only called
	 * by sc_pkcs15_compute_signature(), where the card is already locked, and
	 * the next function to be executed will be the compute_signature function.
	 */
	if (*env->key_ref == BELPIC_KEY_REF_NONREP) {
		sc_log(card->ctx,  "No GUI for NonRep key present, signature cancelled\n");
		return SC_ERROR_NOT_SUPPORTED;
	}

	return r;
}

static struct sc_card_driver *sc_get_driver(void)
{
	if (iso_ops == NULL)
		iso_ops = sc_get_iso7816_driver()->ops;

	belpic_ops.match_card = belpic_match_card;
	belpic_ops.init = belpic_init;

	belpic_ops.update_binary = iso_ops->update_binary;
	belpic_ops.select_file = belpic_select_file;
	belpic_ops.read_binary = belpic_read_binary;
	belpic_ops.pin_cmd = belpic_pin_cmd;
	belpic_ops.set_security_env = belpic_set_security_env;

	belpic_ops.compute_signature = iso_ops->compute_signature;
	belpic_ops.get_challenge = iso_ops->get_challenge;
	belpic_ops.get_response = iso_ops->get_response;
	belpic_ops.check_sw = iso_ops->check_sw;

	return &belpic_drv;
}

#if 1
struct sc_card_driver *sc_get_belpic_driver(void)
{
	return sc_get_driver();
}
#endif
