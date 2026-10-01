/*
 * card-starsign.c: Support for G&D StarSign CUT S cards (A.E.T. Europe SafeSign)
 *
 * Copyright (C) 2026 Diego Ribeiro de Souza
 *
 * This driver performs the proprietary DRM handshake and logical
 * channel selection required by the StarSign CUT S token.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include "asn1.h"
#include "internal.h"
#include "log.h"

static const struct sc_atr_table starsign_atrs[] = {
		{"3B:F9:96:00:00:81:31:FE:45:53:43:45:37:20:0E:00:20:20:28", NULL, NULL, SC_CARD_TYPE_STARSIGN, 0, NULL},
		{NULL,						       NULL, NULL, 0,		      0, NULL}
};

static const struct sc_card_operations *iso_ops = NULL;
static struct sc_card_operations starsign_ops;
static struct sc_card_driver starsign_drv = {
		"G&D StarSign CUT S",
		"starsign",
		&starsign_ops,
		NULL, 0, NULL};

static const u8 starsign_drm_string[] = "I am A.E.T. Europe B.V. SafeSign or BlueX approved software.";

/*
 * Tracks the currently selected working directory so select_file() can
 * avoid redundant re-navigation:
 *  - df5031_selected: the PKCS#15 application DF (5031) is active, so an
 *    EF can be addressed as its direct child instead of re-navigating
 *    from the MF.
 *  - mid_fid/mid_fid_valid: certificate/data-object EFs are referenced by
 *    a path such as "3F00 3FFF 4302 05A0". 0x3FFF is a placeholder the
 *    card rejects with SW 6A82 if selected. The component right after it
 *    (e.g. 4302) IS a real directory one level below 5031 and must be
 *    selected once -- re-selecting it a second time while it is already
 *    the current DF also fails with 6A82, so it is cached and only
 *    reselected when it actually changes.
 */
struct starsign_drv_data {
	int df5031_selected;
	u8 mid_fid[2];
	int mid_fid_valid;
};

static int
starsign_match_card(sc_card_t *card)
{
	int i;
	i = _sc_match_atr(card, starsign_atrs, &card->type);
	if (i < 0)
		return 0;
	return 1;
}

static int
starsign_init(sc_card_t *card)
{
	sc_context_t *ctx = card->ctx;
	sc_apdu_t apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 aid[] = {0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35};
	unsigned long alg_flags;
	int r;

	LOG_FUNC_CALLED(ctx);

	card->name = "G&D StarSign CUT S";
	card->type = SC_CARD_TYPE_STARSIGN;

	card->drv_data = calloc(1, sizeof(struct starsign_drv_data));
	if (!card->drv_data)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

	/* 1. DRM handshake: the card silently refuses PKCS#15 operations
	 * unless this exact string is echoed back to it via PUT DATA
	 * beforehand. The card does not consider the handshake mandatory at
	 * this point (it typically answers 6D 00, "instruction not
	 * supported"), so a failure here is not fatal. */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xDA, 0x01, 0x00);
	apdu.data = starsign_drm_string;
	apdu.datalen = sizeof(starsign_drm_string) - 1;
	apdu.lc = apdu.datalen;
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, r, "APDU transmit failed (first DRM handshake)");

	/* 2. Select PKCS#15 AID on the default channel. */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, 0x04, 0x00);
	apdu.data = aid;
	apdu.datalen = sizeof(aid);
	apdu.lc = sizeof(aid);
	apdu.le = 256;
	apdu.resplen = sizeof(rbuf);
	apdu.resp = rbuf;
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, r, "APDU transmit failed (AID select)");

	/* 3. Second DRM handshake, now that the applet is selected -- the
	 * card expects this exact sequence before it will accept anything
	 * beyond basic GET DATA. */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xDA, 0x01, 0x00);
	apdu.data = starsign_drm_string;
	apdu.datalen = sizeof(starsign_drm_string) - 1;
	apdu.lc = apdu.datalen;
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, r, "APDU transmit failed (second DRM handshake)");

	/* 4. The PKCS#15 applet refuses further operations on the default
	 * logical channel (0); open channel 1 and use it from here on. */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0x70, 0x00, 0x00);
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = 1;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, r, "APDU transmit failed (MANAGE CHANNEL)");

	if (apdu.sw1 == 0x6A && apdu.sw2 == 0x81) {
		/* Channel already open from a previous session, that is fine. */
		r = SC_SUCCESS;
	} else {
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		LOG_TEST_RET(ctx, r, "Card refused logical channel opening");
	}

	/* 5. Force CLA=0x01 for all subsequent operations. */
	card->cla = 0x01;

	/* 6. Re-select the PKCS#15 AID, now on channel 1. */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xA4, 0x04, 0x00);
	apdu.data = aid;
	apdu.datalen = sizeof(aid);
	apdu.lc = sizeof(aid);
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, r, "APDU transmit failed (AID select on channel 1)");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r != SC_SUCCESS) {
		/* Some card firmware revisions answer SW 6A 86 here if the
		 * applet is already selected on this channel; that is not an
		 * error condition for us. */
		sc_log(ctx, "Card refused AID selection on channel 1 (SW %02X %02X), ignoring as it might already be selected", apdu.sw1, apdu.sw2);
	}

	/*
	 * Signature padding: this card pads a raw hash it is handed with
	 * PKCS#1 v1.5 (00 01 FF..FF 00 <hash>), but it does NOT prepend the
	 * DigestInfo ASN.1/OID header a standards-compliant SHA-256 (or
	 * MD5/SHA-1) signature requires. We verified this by decrypting a
	 * live signature with the token's own public key: the padded block
	 * held the bare digest with no DigestInfo prefix, so any compliant
	 * verifier rejects it even though the card answers SW 90 00.
	 * Advertising only SC_ALGORITHM_RSA_HASH_NONE makes OpenSC's own
	 * crypto layer build the complete DigestInfo + PKCS#1 block in
	 * software and hand the card an already-padded blob for a raw RSA
	 * operation (SC_ALGORITHM_RSA_RAW).
	 */
	/* max_recv_size is kept at 256 (the real RSA-2048 output size) rather
	 * than raised alongside max_send_size: iso7816_fixup_transceive_length()
	 * only clamps apdu.le down to max_recv_size, never up, and some PKCS#11
	 * framework callers (decipher in particular, which allocates a generic
	 * 512-byte response buffer regardless of actual key size) request a Le
	 * far larger than the real output. Left uncapped, that oversized Le
	 * produces an extended APDU the reader's USB/PC-SC transport cannot
	 * actually deliver (SCardTransmit fails with SCARD_E_INVALID_PARAMETER)
	 * instead of the correct, transmittable 256-byte request. */
	card->caps |= SC_CARD_CAP_APDU_EXT;
	card->max_send_size = 2048;
	card->max_recv_size = 256;
	/*
	 * KNOWN HARDWARE LIMITATION (not fixable here): on at least one
	 * StarSign CUT S unit, the token's built-in CCID reader declares a
	 * firmware-fixed dwMaxCCIDMsgLen of 271 bytes (~261 usable after the
	 * CCID header) in its USB descriptor -- see `lsusb -v` -- and does
	 * not advertise "Extended APDU level exchange" in dwFeatures. A raw
	 * RSA-2048 operation's 256-byte payload does not fit under that
	 * ceiling in any standard APDU encoding (even the leanest extended
	 * Case 3 APDU is 263 bytes), and this card separately rejects ISO
	 * 7816-4 command chaining as a workaround (SW 6E 00). The result is
	 * intermittent SCardTransmit failures (SCARD_E_INVALID_PARAMETER) on
	 * raw sign/decipher through that specific reader, typically
	 * succeeding on retry. We have no software fix for this: the only
	 * way to avoid the 256-byte payload is the card hashing and padding
	 * on-chip with a correct DigestInfo, which this hardware does not do
	 * (see the SC_ALGORITHM_RSA_HASH_NONE comment above).
	 */
	alg_flags = SC_ALGORITHM_RSA_RAW | SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_NONE;

	_sc_card_add_rsa_alg(card, 1024, alg_flags, 0);
	_sc_card_add_rsa_alg(card, 2048, alg_flags, 0);
	_sc_card_add_rsa_alg(card, 4096, alg_flags, 0);

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

/* Select a 2-byte FID as a direct child EF of whatever DF is currently
 * active (P1=0x02). If `file` is non-NULL, it is populated from the card's
 * FCP response via the standard ISO 7816 parser (size, type, EF structure,
 * ...) instead of a hand-rolled tag walk. */
static int
starsign_select_ef_child(sc_card_t *card, const u8 *fid, sc_file_t *file)
{
	sc_context_t *ctx = card->ctx;
	struct sc_apdu apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	int r;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, 0x02, 0x00);
	apdu.data = fid;
	apdu.datalen = 2;
	apdu.lc = 2;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = 256;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, r, "APDU transmit failed (SELECT child EF)");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, r, "SELECT child EF returned an error status word");

	if (file && apdu.resplen)
		iso_ops->process_fci(card, file, apdu.resp, apdu.resplen);
	return SC_SUCCESS;
}

static int
starsign_select_file(sc_card_t *card, const sc_path_t *in_path, sc_file_t **file_out)
{
	sc_context_t *ctx = card->ctx;
	int r = SC_SUCCESS;
	size_t i;
	struct sc_apdu apdu;
	int selected_as_ef = 0;
	struct starsign_drv_data *priv = card->drv_data;
	int has_3fff_placeholder = 0;
	sc_file_t *file = NULL;

	LOG_FUNC_CALLED(ctx);

	if (in_path->type != SC_PATH_TYPE_PATH && in_path->type != SC_PATH_TYPE_FROM_CURRENT && in_path->type != SC_PATH_TYPE_FILE_ID)
		LOG_FUNC_RETURN(ctx, iso_ops->select_file(card, in_path, file_out));

	if (in_path->len % 2 != 0 || in_path->len == 0)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	if (file_out) {
		file = sc_file_new();
		if (!file)
			LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	}

	for (i = 0; i + 2 < in_path->len; i += 2) {
		if (in_path->value[i] == 0x3F && in_path->value[i + 1] == 0xFF) {
			has_3fff_placeholder = 1;
			break;
		}
	}

	if (has_3fff_placeholder) {
		/* Certificate/data-object virtual path: "3F00 3FFF <mid> <final>".
		 * 0x3FFF itself is never selected (confirmed against a genuine
		 * SafeSign APDU capture: the proprietary driver never sends a
		 * SELECT for it either). <mid> (e.g. 4302) is a real directory
		 * and must be selected -- but re-selecting it while it is
		 * already current also fails, so it is cached. */
		const u8 *mid, *final;

		if (in_path->len < 8) {
			r = SC_ERROR_INVALID_ARGUMENTS;
			goto err;
		}

		mid = &in_path->value[in_path->len - 4];
		final = &in_path->value[in_path->len - 2];

		if (!priv || !priv->mid_fid_valid || priv->mid_fid[0] != mid[0] || priv->mid_fid[1] != mid[1]) {
			sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xA4, 0x00, 0x0C);
			apdu.data = mid;
			apdu.datalen = 2;
			apdu.lc = 2;

			r = sc_transmit_apdu(card, &apdu);
			LOG_TEST_GOTO_ERR(ctx, r, "APDU transmit failed (SELECT mid DF)");
			r = sc_check_sw(card, apdu.sw1, apdu.sw2);
			LOG_TEST_GOTO_ERR(ctx, r, "SELECT mid DF returned an error status word");

			if (priv) {
				priv->mid_fid[0] = mid[0];
				priv->mid_fid[1] = mid[1];
				priv->mid_fid_valid = 1;
			}
		}

		r = starsign_select_ef_child(card, final, file);
		LOG_TEST_GOTO_ERR(ctx, r, "SELECT of the final EF failed");
		selected_as_ef = 1;
	} else if (in_path->len == 4 && in_path->value[0] == 0x3F && in_path->value[1] == 0x00 &&
			priv && priv->df5031_selected &&
			!(in_path->value[2] == 0x50 && in_path->value[3] == 0x31)) {
		/* Once the PKCS#15 application DF (5031) has been entered, every
		 * other EF beneath it (TokenInfo, ODF/AODF/PrKDF/CDF/DODF, ...)
		 * is addressed as a direct child instead of re-navigating from
		 * the MF on every call -- doing the latter would silently drop
		 * back to the MF and break the "current DF" assumption the
		 * virtual-path handling above depends on. */
		r = starsign_select_ef_child(card, &in_path->value[2], file);
		LOG_TEST_GOTO_ERR(ctx, r, "SELECT of the direct child EF failed");
		selected_as_ef = 1;
	} else {
		/* Genuine hierarchical navigation from the MF: used for the
		 * initial "3F00 5031" DF transition and for any top-level
		 * DF/EF reached before that context has been established.
		 * The card only accepts P1=0x00 (select by file ID) here --
		 * it answers SW 6A82 for P1=0x01 ("select child DF"). Walk
		 * every component except the last one this way; DF-only
		 * selects (P2=0x0C) never return an FCI on this card, which
		 * is fine for intermediate directories. */
		size_t last = in_path->len - 2;

		for (i = 0; i < last; i += 2) {
			sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xA4, 0x00, 0x0C);
			apdu.data = &in_path->value[i];
			apdu.datalen = 2;
			apdu.lc = 2;

			r = sc_transmit_apdu(card, &apdu);
			LOG_TEST_GOTO_ERR(ctx, r, "APDU transmit failed (hierarchical SELECT)");
			r = sc_check_sw(card, apdu.sw1, apdu.sw2);
			LOG_TEST_GOTO_ERR(ctx, r, "Hierarchical SELECT returned an error status word");
		}

		/* The final component: a bare "MF + one FID" path (len == 4,
		 * e.g. "3F00 5031") is always a DF transition -- select it
		 * the same way as the rest. Anything deeper always bottoms
		 * out at a real EF on this card's layout, so select it as a
		 * child EF instead (P1=0x02) to actually capture its FCI/real
		 * size via starsign_select_ef_child(), instead of silently
		 * falling back to the placeholder file->size below. */
		if (in_path->len > 4) {
			r = starsign_select_ef_child(card, &in_path->value[last], file);
			LOG_TEST_GOTO_ERR(ctx, r, "SELECT of the final EF (hierarchical path) failed");
			selected_as_ef = 1;
		} else {
			sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xA4, 0x00, 0x0C);
			apdu.data = &in_path->value[last];
			apdu.datalen = 2;
			apdu.lc = 2;

			r = sc_transmit_apdu(card, &apdu);
			LOG_TEST_GOTO_ERR(ctx, r, "APDU transmit failed (hierarchical SELECT)");
			r = sc_check_sw(card, apdu.sw1, apdu.sw2);
			LOG_TEST_GOTO_ERR(ctx, r, "Hierarchical SELECT returned an error status word");
		}

		if (priv && in_path->len == 4 && in_path->value[2] == 0x50 && in_path->value[3] == 0x31)
			priv->df5031_selected = 1;
		/* Genuine top-level navigation leaves whatever DF the path
		 * landed on; the cached "mid DF" is no longer necessarily
		 * selected, so drop it and let the next virtual-path SELECT
		 * reselect it explicitly. */
		if (priv)
			priv->mid_fid_valid = 0;
	}

	if (file) {
		/* For EF selects, iso_ops->process_fci() (called from
		 * starsign_select_ef_child()) already populated type/size/
		 * ef_structure from the card's real FCP response. This card
		 * never returns a usable FCP for plain DF selects, though, so
		 * that case is filled in by hand. */
		if (!selected_as_ef)
			file->type = SC_FILE_TYPE_DF;
		if (file->size == 0)
			file->size = 1024;
		file->id = (in_path->value[in_path->len - 2] << 8) | in_path->value[in_path->len - 1];
		file->path = *in_path;
		*file_out = file;
	}
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);

err:
	sc_file_free(file);
	LOG_FUNC_RETURN(ctx, r);
}

static int
starsign_set_security_env(sc_card_t *card, const sc_security_env_t *env, int res)
{
	sc_context_t *ctx = card->ctx;
	sc_apdu_t apdu;
	int r;
	u8 p2;
	/*
	 * StarSign CUT S hardware specifically requires the exact MSE: SET
	 * payload below (Key Reference = 01, Algorithm Reference = 02) --
	 * standard OpenSC puts the 0x80 tag before 0x84, which this token
	 * rejects. This was reverse engineered from a genuine capture of the
	 * proprietary SafeSign driver: swapping the tag order, or omitting
	 * either reference, is silently rejected by the card. These are the
	 * defaults for this card's PKCS#15 profile, which never actually
	 * supplies a different key/algorithm reference; overridden below from
	 * `env` when the caller does provide one explicitly.
	 */
	u8 sbuf[6] = {0x84, 0x01, 0x01, 0x80, 0x01, 0x02};

	LOG_FUNC_CALLED(ctx);

	if (card == NULL || env == NULL)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	if ((env->flags & SC_SEC_ENV_KEY_REF_PRESENT) && env->key_ref_len >= 1)
		sbuf[2] = env->key_ref[0];
	if (env->flags & SC_SEC_ENV_ALG_REF_PRESENT)
		sbuf[5] = env->algorithm_ref & 0xFF;

	switch (env->operation) {
	case SC_SEC_OPERATION_AUTHENTICATE:
		p2 = 0xA4;
		break;
	case SC_SEC_OPERATION_DECIPHER:
	case SC_SEC_OPERATION_DERIVE:
		p2 = 0xB8;
		break;
	case SC_SEC_OPERATION_SIGN:
		p2 = 0xB6;
		break;
	default:
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
	}

	sc_format_apdu_ex(&apdu, card->cla, 0x22, 0x41, p2, sbuf, sizeof(sbuf), NULL, 0);

	sc_log(ctx, "MSE SET constructed payload=84 01 %02X 80 01 %02X", sbuf[2], sbuf[5]);

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, r, "APDU transmit failed (MSE SET)");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_FUNC_RETURN(ctx, r);
}

static int
starsign_finish(sc_card_t *card)
{
	free(card->drv_data);
	card->drv_data = NULL;
	return SC_SUCCESS;
}

struct sc_card_driver *
sc_get_starsign_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();
	if (iso_ops == NULL)
		iso_ops = iso_drv->ops;
	starsign_ops = *iso_drv->ops;
	starsign_ops.init = starsign_init;
	starsign_ops.finish = starsign_finish;
	starsign_ops.match_card = starsign_match_card;
	starsign_ops.select_file = starsign_select_file;
	starsign_ops.set_security_env = starsign_set_security_env;
	return &starsign_drv;
}
