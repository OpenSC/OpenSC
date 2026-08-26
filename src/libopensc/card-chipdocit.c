/*
 * Support for the Bit4id Digital-DNA Key (Italian CNS/eID on an NXP ChipDoc
 * chip). Same chip and CAN-unwrap scheme as the Slovenian eID (card-eoi.c):
 * the CAN is stored encrypted in EF E000 and unwrapped with the same static
 * key, and access is gated by a PACE (BSI TR-03110) channel established with
 * OpenPACE.
 *
 * Copyright (C) 2026 Grid Society S.r.l.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <stdlib.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "opensc.h"

#if defined(ENABLE_SM) && defined(ENABLE_OPENPACE)

#include "card-eoi.h"
#include "common/compat_strlcpy.h"
#include "internal.h"
#include "sm/sm-eac.h"
#include <openssl/aes.h>

#define CHIPDOCIT_ENC_CAN_EF "3F00E000" /* encrypted CAN (24 B: 16 enc || 8 SN) */

/* Signature-side application AID (SELECT 00 A4 04 04). */
static const u8 CHIPDOCIT_SSCD_AID[] = {
		0xE8, 0x28, 0xBD, 0x08, 0x0F, 0x01, 0x4E, 0x58, 0x50, 0x31};

/* Card application AID (IAS-ECC). Selecting it activates the file system that
 * carries the encrypted CAN (EF E000) and the PKCS#15 EFs; on a card that has
 * not been opened by other software these are not reachable until it is
 * selected. */
static const u8 CHIPDOCIT_IAS_AID[] = {
		0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};

#define CHIPDOCIT_DS_KEY_REF 0x11 /* DS3, nonRepudiation (from PrKD 7002) */
#define CHIPDOCIT_PUK_REF    0x86 /* user PUK, BSO 0x06 | 0x80 */

/* Classic CNS applet: a second PIN object kept in sync with the IAS PIN and
 * accessed in clear. Change/unblock must be mirrored onto it. */
static const u8 CHIPDOCIT_CNS_AID[] = {
		0xA0, 0x00, 0x00, 0x05, 0x30, 0x00, 0x0B, 0x10, 0x40, 0x01, 0x01, 0x1B};
#define CHIPDOCIT_CNS_PIN_BSO 0x10
#define CHIPDOCIT_CNS_PUK_BSO 0x11

static struct sc_card_operations chipdocit_ops;

static struct sc_card_driver chipdocit_drv = {
		"Bit4id Digital-DNA (NXP ChipDoc, Italian CNS)",
		"chipdoc-it",
		&chipdocit_ops,
		NULL, 0, NULL};

static const struct sc_atr_table chipdocit_atrs[] = {
		/* Bit4id Digital-DNA Key (NXP ChipDoc Lite CNS). Discriminator vs COSMO
		 * (00 6B 05): sub-bytes 00 6B 15 0C. */
		{"3B:FF:18:00:00:81:31:FE:45:00:6B:15:0C:03:02:01:01:01:43:4E:53:10:31:80:61",
			NULL,									       NULL, SC_CARD_TYPE_CHIPDOC_IT, 0, NULL},
		{NULL,									 NULL, NULL, 0,			      0, NULL}
};

struct chipdocit_privdata {
	char can[17]; /* up to 16 ASCII chars + NUL */
	u8 enc_can[24];
	size_t enc_can_len;
	struct sc_security_env sec_env; /* stashed until compute_signature */
	int se_num;
};

/* Decrypt the encrypted CAN (shared unwrap scheme and key with card-eoi) and
 * keep its printable bytes. Unlike the Slovenian eOI (a NUL-terminated 6-digit
 * CAN in the leading bytes) the Italian ChipDoc stores a full-block CAN with no
 * NUL, so keep every printable byte and NUL-terminate after it. */
static int
chipdocit_decrypt_can(const u8 *enc_can, size_t len, char *can)
{
	u8 dec[AES_BLOCK_SIZE];
	size_t n;
	int r;

	r = chipdoc_decrypt_can_block(enc_can, len, dec);
	if (r != SC_SUCCESS)
		return r;
	for (n = 0; n < AES_BLOCK_SIZE && dec[n] >= 0x20 && dec[n] < 0x7f; n++)
		can[n] = (char)dec[n];
	can[n] = '\0';
	return SC_SUCCESS;
}

/* --- PACE channel (CAN-based) via OpenPACE --- */

static int
chipdocit_sm_open(struct sc_card *card)
{
	struct chipdocit_privdata *priv = card->drv_data;
	struct establish_pace_channel_input pace_input;
	struct establish_pace_channel_output pace_output;
	int r;

	if (!priv)
		return SC_ERROR_INTERNAL;
	if (card->sm_ctx.sm_mode != SM_MODE_NONE)
		return SC_SUCCESS; /* channel already open */
	if (!priv->can[0]) {
		r = chipdocit_decrypt_can(priv->enc_can, priv->enc_can_len, priv->can);
		sc_log_openssl(card->ctx);
		LOG_TEST_RET(card->ctx, r, "Cannot decrypt CAN");
	}
	if (strlen(priv->can) < 6)
		return SC_ERROR_DECRYPT_FAILED;

	memset(&pace_input, 0, sizeof pace_input);
	memset(&pace_output, 0, sizeof pace_output);
	pace_input.pin_id = PACE_PIN_ID_CAN;
	pace_input.pin = (u8 *)priv->can;
	pace_input.pin_length = strlen(priv->can);

	/* EF.CardAccess is read from the MF during PACE. */
	r = sc_select_file(card, sc_get_mf_path(), NULL);
	LOG_TEST_RET(card->ctx, r, "SELECT MF failed");

	r = perform_pace(card, pace_input, &pace_output, EAC_TR_VERSION_2_02);
	sc_log_openssl(card->ctx);
	LOG_TEST_RET(card->ctx, r, "PACE (CAN) failed");
	sc_log(card->ctx, "ChipDoc-IT: PACE channel established");
	return SC_SUCCESS;
}

static int
chipdocit_match_card(sc_card_t *card)
{
	LOG_FUNC_CALLED(card->ctx);
	if (_sc_match_atr(card, chipdocit_atrs, &card->type) < 0)
		LOG_FUNC_RETURN(card->ctx, 0);
	/* The ATR is shared with other Italian CNS cards; confirm this is the
	 * NXP ChipDoc by selecting its card application, so the others fall
	 * through to the generic CNS driver. */
	if (iso7816_select_aid(card, CHIPDOCIT_IAS_AID, sizeof CHIPDOCIT_IAS_AID, NULL, NULL) != SC_SUCCESS)
		LOG_FUNC_RETURN(card->ctx, 0);
	LOG_FUNC_RETURN(card->ctx, 1);
}

static int
chipdocit_read_enc_can(sc_card_t *card, struct chipdocit_privdata *priv)
{
	sc_path_t path;
	int r;

	/* Activate the card application first: on a card that has not been
	 * opened by other software, the MF and EF E000 are only reachable once
	 * the IAS-ECC application is selected. */
	r = iso7816_select_aid(card, CHIPDOCIT_IAS_AID, sizeof CHIPDOCIT_IAS_AID, NULL, NULL);
	LOG_TEST_RET(card->ctx, r, "SELECT IAS-ECC AID failed");
	r = sc_select_file(card, sc_get_mf_path(), NULL);
	LOG_TEST_RET(card->ctx, r, "SELECT MF failed");

	sc_format_path(CHIPDOCIT_ENC_CAN_EF, &path);
	r = sc_select_file(card, &path, NULL);
	LOG_TEST_RET(card->ctx, r, "SELECT enc-CAN EF failed");
	r = sc_read_binary(card, 0, priv->enc_can, sizeof(priv->enc_can), 0);
	LOG_TEST_RET(card->ctx, r, "read enc-CAN failed");
	priv->enc_can_len = (size_t)r;
	return SC_SUCCESS;
}

static int
chipdocit_init(sc_card_t *card)
{
	struct chipdocit_privdata *priv;
	unsigned long flags;
	int r;

	LOG_FUNC_CALLED(card->ctx);

	priv = calloc(1, sizeof(*priv));
	if (!priv)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
	card->drv_data = priv;
	card->max_send_size = SC_MAX_APDU_DATA_SIZE;
	card->max_recv_size = SC_MAX_APDU_RESP_SIZE;
	/* DS sign (PSO:DECIPHER) feeds a 256-B RSA block, sent as an
	 * extended-length APDU. */
	card->caps |= SC_CARD_CAP_APDU_EXT;

	/* The DS key signs by raw RSA via PSO:DECIPHER over a full PKCS#1 v1.5
	 * block: advertise RAW *only*, so OpenSC pads in software and hands us the
	 * 256-B block in compute_signature. Do NOT also advertise PAD_PKCS1/HASHES:
	 * sc_get_encoding_flags would then leave padding to the card (pad_flags=0)
	 * and send the bare DigestInfo, which the card's raw DECIPHER primitive
	 * rejects with 6700 (verified on hardware). */
	flags = SC_ALGORITHM_RSA_RAW | SC_ALGORITHM_RSA_PAD_NONE | SC_ALGORITHM_RSA_HASH_NONE | SC_ALGORITHM_NEED_USAGE;
	_sc_card_add_rsa_alg(card, 2048, flags, 0);

	memset(&card->sm_ctx, 0, sizeof card->sm_ctx);
	card->sm_ctx.ops.open = chipdocit_sm_open;

	/* Read the encrypted CAN now (in clear, no PIN needed). PACE is opened
	 * lazily — only VERIFY/sign need it; cert/structure reads run in clear. */
	r = chipdocit_read_enc_can(card, priv);
	LOG_TEST_GOTO_ERR(card->ctx, r, "cannot read encrypted CAN");

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
err:
	free(priv);
	card->drv_data = NULL;
	LOG_FUNC_RETURN(card->ctx, r);
}

static int
chipdocit_finish(sc_card_t *card)
{
	free(card->drv_data);
	card->drv_data = NULL;
	return SC_SUCCESS;
}

/* Run one PIN command on the in-clear CNS applet through the iso7816 driver,
 * 0xFF-padded to 8 bytes. p1/p2 are the current/new secrets (either may be
 * NULL when unused). */
static int
chipdocit_cns_pin_op(struct sc_card *card, int cmd, int reference,
		const struct sc_pin_cmd_pin *p1, const struct sc_pin_cmd_pin *p2)
{
	struct sc_pin_cmd_data d;

	memset(&d, 0, sizeof d);
	d.cmd = cmd;
	d.pin_type = SC_AC_CHV;
	d.flags = SC_PIN_CMD_NEED_PADDING;
	d.pin_reference = reference;
	if (p1) {
		d.pin1 = *p1;
		d.pin1.pad_char = 0xFF;
		d.pin1.pad_length = 8;
	}
	if (p2) {
		d.pin2 = *p2;
		d.pin2.pad_char = 0xFF;
		d.pin2.pad_length = 8;
	}
	return sc_get_iso7816_driver()->ops->pin_cmd(card, &d);
}

/* Select the CNS applet in the clear. Switching to it ends any PACE session,
 * so SM is turned off; the caller re-opens PACE for the IAS side afterwards. */
static int
chipdocit_select_cns(struct sc_card *card)
{
	/* Tear down the PACE channel first: the CNS applet is accessed in the
	 * clear, and selecting it ends any secure-messaging session anyway. */
	sc_sm_stop(card);
	return iso7816_select_aid(card, CHIPDOCIT_CNS_AID, sizeof CHIPDOCIT_CNS_AID,
			NULL, NULL);
}

/*
 * Mirror a CHANGE/UNBLOCK onto the CNS-applet PIN (BSO 0x10, PUK 0x11), which
 * is kept in sync with the IAS PIN and accessed in the clear. PIN and PUK are
 * 0xFF-padded to 8 bytes here (the IAS side sends them unpadded).
 */
static int
chipdocit_cns_sync(struct sc_card *card, struct sc_pin_cmd_data *data)
{
	int r;

	r = chipdocit_select_cns(card);
	LOG_TEST_RET(card->ctx, r, "SELECT CNS AID failed");

	if (data->cmd == SC_PIN_CMD_UNBLOCK) {
		/* Verify the PUK, then reset the retry counter and set the new PIN. */
		r = chipdocit_cns_pin_op(card, SC_PIN_CMD_VERIFY,
				CHIPDOCIT_CNS_PUK_BSO, &data->pin1, NULL);
		LOG_TEST_RET(card->ctx, r, "CNS VERIFY PUK failed");
		r = chipdocit_cns_pin_op(card, SC_PIN_CMD_UNBLOCK,
				CHIPDOCIT_CNS_PIN_BSO, &data->pin1, &data->pin2);
	} else { /* SC_PIN_CMD_CHANGE */
		r = chipdocit_cns_pin_op(card, SC_PIN_CMD_CHANGE,
				CHIPDOCIT_CNS_PIN_BSO, &data->pin1, &data->pin2);
	}
	return r;
}

/* True when the ATR advertises the classic CNS applet ("CNS" in the historical
 * bytes). Variants without it carry only the IAS PIN. */
static int
chipdocit_has_cns(struct sc_card *card)
{
	size_t i;

	for (i = 0; i + 3 <= card->atr.len; i++)
		if (card->atr.value[i] == 'C' && card->atr.value[i + 1] == 'N' && card->atr.value[i + 2] == 'S')
			return 1;
	return 0;
}

/*
 * PIN operations. This is a "CNS" card carrying two PIN objects that must be
 * kept in sync: the CNS-applet PIN (in the clear) and the IAS PIN (under the
 * PACE channel). VERIFY only touches the IAS side; CHANGE and UNBLOCK are
 * mirrored onto both. On the IAS side VERIFY sends the unpadded PIN with
 * P2 = BSO|0x80 (0x83 user PIN, 0x86 PUK); CHANGE sends only the new PIN (the
 * old is proven by the preceding VERIFY); UNBLOCK = VERIFY PUK + RESET RETRY
 * COUNTER + set new PIN.
 */
static int
chipdocit_pin_cmd(struct sc_card *card, struct sc_pin_cmd_data *data)
{
	struct sc_pin_cmd_pin p1_save = {0}, p2_save = {0};
	int cmd = data->cmd;
	int synced = 0, r;

	LOG_FUNC_CALLED(card->ctx);

	/* This card carries two PIN objects that are kept in sync: the CNS-applet
	 * PIN (in the clear) and the IAS PIN (under PACE). When the PIN is entered
	 * in software both are updated. With a PIN pad the secret stays on the
	 * reader and cannot be replayed to the CNS applet, so only the IAS PIN is
	 * changed and the CNS-applet PIN is left unchanged. Mirror the CNS side
	 * first, while SM is still off. */
	if ((cmd == SC_PIN_CMD_CHANGE || cmd == SC_PIN_CMD_UNBLOCK) && chipdocit_has_cns(card) && !(data->flags & SC_PIN_CMD_USE_PINPAD)) {
		p1_save = data->pin1;
		p2_save = data->pin2;
		r = chipdocit_cns_sync(card, data);
		LOG_TEST_RET(card->ctx, r, "CNS-applet PIN sync failed");
		synced = 1;
		/* The CNS SELECT dropped PACE: go back to the IAS application. */
		r = iso7816_select_aid(card, CHIPDOCIT_IAS_AID, sizeof CHIPDOCIT_IAS_AID, NULL, NULL);
		LOG_TEST_RET(card->ctx, r, "re-SELECT IAS AID failed");
	}

	if (card->sm_ctx.sm_mode == SM_MODE_NONE) {
		r = chipdocit_sm_open(card);
		if (r != SC_SUCCESS)
			LOG_FUNC_RETURN(card->ctx, r);
	}
	/* The user PIN/PUK live at the MF; a prior signature may have left the
	 * SSCD applet selected, so re-select the MF before touching them. */
	if (data->cmd == SC_PIN_CMD_VERIFY || data->cmd == SC_PIN_CMD_CHANGE || data->cmd == SC_PIN_CMD_UNBLOCK)
		sc_select_file(card, sc_get_mf_path(), NULL);

	if (data->cmd == SC_PIN_CMD_UNBLOCK) {
		int pin_reference = data->pin_reference;
		size_t pin2_len = data->pin2.len;
		/* Verify the PUK first (recurses through VERIFY). The emulator
		 * exposes no separate PUK object, so pkcs15-pin.c leaves
		 * puk_reference at 0: fall back to the default value. */
		data->cmd = SC_PIN_CMD_VERIFY;
		data->pin_reference = data->puk_reference ? data->puk_reference : CHIPDOCIT_PUK_REF;
		r = chipdocit_pin_cmd(card, data);
		if (r != SC_SUCCESS)
			LOG_FUNC_RETURN(card->ctx, r);
		/* RESET RETRY COUNTER (no data, P1=3 via empty pins). */
		data->cmd = SC_PIN_CMD_UNBLOCK;
		data->pin_reference = 0x80 | pin_reference;
		data->pin1.len = 0;
		data->pin2.len = 0;
		r = sc_get_iso7816_driver()->ops->pin_cmd(card, data);
		if (r != SC_SUCCESS)
			LOG_FUNC_RETURN(card->ctx, r);
		/* Continue as CHANGE to write the new PIN. */
		data->cmd = SC_PIN_CMD_CHANGE;
		data->pin2.len = pin2_len;
	}

	/* Genuine CHANGE: the CNS mirror re-opened PACE, so the current PIN must
	 * be proven again under this session before the card accepts the new one
	 * (VERIFY old, then CHANGE new). */
	if (cmd == SC_PIN_CMD_CHANGE) {
		struct sc_pin_cmd_data v = *data;
		v.cmd = SC_PIN_CMD_VERIFY;
		v.pin2.data = NULL;
		v.pin2.len = 0;
		r = sc_get_iso7816_driver()->ops->pin_cmd(card, &v);
		LOG_TEST_RET(card->ctx, r, "VERIFY current PIN failed");
	}

	/* CHANGE sends only the new PIN (old already proven by VERIFY). */
	if (data->cmd == SC_PIN_CMD_CHANGE)
		data->pin1.len = 0;

	r = sc_get_iso7816_driver()->ops->pin_cmd(card, data);

	/* If the IAS side failed after the CNS PIN was changed, roll the CNS PIN
	 * back so the two objects do not diverge (CHANGE only). */
	if (r != SC_SUCCESS && synced && cmd == SC_PIN_CMD_CHANGE) {
		/* Revert the CNS PIN (new -> old) so the two objects stay in sync. */
		if (chipdocit_select_cns(card) == SC_SUCCESS)
			(void)chipdocit_cns_pin_op(card, SC_PIN_CMD_CHANGE,
					CHIPDOCIT_CNS_PIN_BSO, &p2_save, &p1_save);
	}
	LOG_FUNC_RETURN(card->ctx, r);
}

/* We don't know the hash type until compute_signature, so just stash the env. */
static int
chipdocit_set_security_env(struct sc_card *card,
		const struct sc_security_env *env, int se_num)
{
	struct chipdocit_privdata *priv = card->drv_data;

	LOG_FUNC_CALLED(card->ctx);
	if (!priv || !env)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	priv->sec_env = *env;
	priv->se_num = se_num;
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

/*
 * DS signature: raw RSA via PSO:DECIPHER on the signature applet. OpenSC has
 * already PKCS#1-padded the DigestInfo to a full modulus-sized block (we
 * advertise RSA_RAW), so we hand that block to the card's private-key
 * operation and return the raw signature.
 */
static int
chipdocit_compute_signature(struct sc_card *card, const u8 *data,
		size_t data_len, u8 *out, size_t outlen)
{
	struct chipdocit_privdata *priv = card->drv_data;
	struct sc_apdu apdu;
	u8 mse[3];
	unsigned int keyref = CHIPDOCIT_DS_KEY_REF;
	int r;

	LOG_FUNC_CALLED(card->ctx);
	if (!priv)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);

	if (card->sm_ctx.sm_mode == SM_MODE_NONE) {
		r = chipdocit_sm_open(card);
		LOG_TEST_RET(card->ctx, r, "PACE open failed");
	}
	if ((priv->sec_env.flags & SC_SEC_ENV_KEY_REF_PRESENT) && priv->sec_env.key_ref_len == 1)
		keyref = priv->sec_env.key_ref[0];

	/* Move to the signature applet. */
	r = iso7816_select_aid(card, CHIPDOCIT_SSCD_AID, sizeof CHIPDOCIT_SSCD_AID, NULL, NULL);
	LOG_TEST_RET(card->ctx, r, "SELECT SSCD AID failed");

	/* MSE:SET for the RAW private-key op: 00 22 41 B8  83 01 <keyref>. */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, 0xB8);
	mse[0] = 0x83;
	mse[1] = 0x01;
	mse[2] = (u8)keyref;
	apdu.lc = apdu.datalen = sizeof mse;
	apdu.data = mse;
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "MSE:SET transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "MSE:SET failed");

	/* PSO:DECIPHER (00 2A 80 86) with the padded block; extended APDU. */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_EXT, 0x2A, 0x80, 0x86);
	apdu.lc = apdu.datalen = data_len;
	apdu.data = data;
	apdu.resp = out;
	apdu.resplen = outlen;
	apdu.le = outlen > 256 ? 256 : outlen;
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "PSO:DECIPHER transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "PSO:DECIPHER failed");

	sc_log(card->ctx, "ChipDoc-IT: DS signature produced (%lu bytes)",
			(unsigned long)apdu.resplen);
	LOG_FUNC_RETURN(card->ctx, (int)apdu.resplen);
}

struct sc_card_driver *
sc_get_chipdocit_driver(void)
{
	struct sc_card_driver *iso = sc_get_iso7816_driver();
	chipdocit_ops = *iso->ops;
	chipdocit_ops.match_card = chipdocit_match_card;
	chipdocit_ops.init = chipdocit_init;
	chipdocit_ops.finish = chipdocit_finish;
	chipdocit_ops.pin_cmd = chipdocit_pin_cmd;
	chipdocit_ops.set_security_env = chipdocit_set_security_env;
	chipdocit_ops.compute_signature = chipdocit_compute_signature;
	return &chipdocit_drv;
}

#else /* ENABLE_SM && ENABLE_OPENPACE */

#include "internal.h"
struct sc_card_driver *
sc_get_chipdocit_driver(void)
{
	return NULL;
}

#endif
