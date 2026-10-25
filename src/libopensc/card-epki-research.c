/*
 * Experimental, isolated access to one observed SCE7 PKCS#15 applet.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * The ATR identifies a platform, not an applet. Require explicit profile
 * enablement, the exact observed ATR, the standard PKCS#15 AID, and the
 * reviewed interface value in both read-only and signing modes.
 * Application/file selection follows locally observed card behavior.
 * Read-only by default. Private opt-in supports PIN verification and
 * RSA-2048 PKCS#1 v1.5 signing with a PKCS#15-selected key.
 * A separate decryption opt-in enables the profile's raw RSA decipher
 * route; OpenSC supplies PKCS#1 v1.5/OAEP unpadding in its shared layer.
 * A separate raw-RSA opt-in lets OpenSC encode RSA-PSS in software.
 * Authentication is cached only during a reader transaction. OpenSC
 * manages PIN caching and revalidation; the driver never retains a PIN.
 * Provenance combines public OpenSC/standards, independent card reads,
 * guarded SCinterface runtime observations, and limited REA/static analysis.
 * PIN descriptor values have independent card/public support; selected
 * applet command bindings include vendor-derived facts. See the RFC for
 * the source distinctions and limits. This experimental driver makes no
 * public-documentation-only or formal clean-room claim.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "internal.h"
#include <stdlib.h>
#include <string.h>

static const u8 epki_atr[] = {
		0x3b, 0xf9, 0x96, 0x00, 0x00, 0x80, 0x31, 0xfe, 0x45,
		0x53, 0x43, 0x45, 0x37, 0x20, 0x00, 0x00, 0x20, 0x20, 0x27};
static const u8 epki_aid[] = {
		0xa0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4b, 0x43, 0x53, 0x2d, 0x31, 0x35};

static int epki_config_bool(sc_card_t *card, const char *option);
static int epki_check_profile(sc_card_t *card);

static int
epki_match_card(sc_card_t *card)
{
	int r, unlock_r;

	/* Neither the platform ATR, the standard AID nor the interface value
	 * uniquely identifies an applet/personalization. Require the user to
	 * select this experimental profile explicitly, including read-only use.
	 * Default driver scans must not select an applet or send a probe. */
	if (card == NULL || card->atr.len != sizeof(epki_atr) ||
			memcmp(card->atr.value, epki_atr, sizeof(epki_atr)) != 0 ||
			!epki_config_bool(card, "enable_profile"))
		return 0;
	r = sc_lock(card);
	if (r < 0)
		return 0;
	/* Keep selection and its interface query in the same transaction. */
	r = iso7816_select_aid(card, epki_aid, sizeof(epki_aid), NULL, NULL);
	if (r == SC_SUCCESS)
		r = epki_check_profile(card);
	unlock_r = sc_unlock(card);
	return r == SC_SUCCESS && unlock_r == SC_SUCCESS;
}

/* Private operations require their own explicit opt-in. */
struct epki_data {
	int signing_enabled;
	int decryption_enabled;
	int raw_rsa_enabled;
	int raw_signature;
	int pin_verified;
	int security_env_valid;
	int security_operation;
	int profile_checked;
	int app_selected;
	sc_file_t *app_file;
};

static void
epki_clear_selection(struct epki_data *priv)
{
	if (priv == NULL)
		return;
	priv->app_selected = 0;
	priv->pin_verified = 0;
	priv->security_env_valid = 0;
	priv->security_operation = 0;
	priv->raw_signature = 0;
	sc_file_free(priv->app_file);
	priv->app_file = NULL;
}

/* These options belong in an isolated OPENSC_CONF, never the system config. */
static int
epki_config_bool(sc_card_t *card, const char *option)
{
	scconf_block **blocks;
	size_t i, j;
	int enabled = 0;

	if (card->ctx == NULL || card->ctx->conf == NULL)
		return 0;
	for (i = 0; card->ctx->conf_blocks[i]; i++) {
		blocks = scconf_find_blocks(card->ctx->conf, card->ctx->conf_blocks[i],
				"card_driver", "epki-research");
		if (blocks == NULL)
			continue;
		for (j = 0; blocks[j]; j++)
			enabled = scconf_get_bool(blocks[j], option, enabled);
		free(blocks);
	}
	return enabled;
}

/* Authentication and the MSE belong to the current transaction. A failed
 * command consumes its environment, but does not disable later operations. */
static int
epki_private_state(const struct epki_data *priv, int need_env, int operation)
{
	if (!priv->pin_verified)
		return SC_ERROR_SECURITY_STATUS_NOT_SATISFIED;
	if (need_env && (!priv->security_env_valid || priv->security_operation != operation))
		return SC_ERROR_NOT_ALLOWED;
	return SC_SUCCESS;
}

static int
epki_check_profile(sc_card_t *card)
{
	sc_apdu_t apdu;
	u8 version[2];
	int r;

	/* Exact query/profile remain vendor-derived. BSI 0804-2012 p17
	 * corroborates tag/length for related v3.6 with CLA 00, not our 80.
	 * Fail closed on other lengths/profiles; see RFC provenance. */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xca, 0x01, 0x82);
	apdu.cla = 0x80;
	apdu.le = sizeof(version);
	apdu.resp = version;
	apdu.resplen = sizeof(version);
	apdu.flags |= SC_APDU_FLAGS_NO_RETRY_WL | SC_APDU_FLAGS_NO_GET_RESP;
	r = sc_transmit_apdu(card, &apdu);
	if (r < 0)
		return r;
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r < 0)
		return r;
	/* Testing wanted: ePKIApplet 2.129 (0x0281) and ePKIApplet 2.126
	 * (0x027e) may share these interfaces according to limited static
	 * analysis, but lack hardware validation. They remain rejected; see
	 * the "Testing wanted" section in doc/epki-research-rfc.txt. */
	if (apdu.resplen != sizeof(version) || version[0] != 0x02 || version[1] != 0x82)
		return SC_ERROR_INVALID_CARD;
	return SC_SUCCESS;
}

static int
epki_finish(sc_card_t *card)
{
	if (card != NULL) {
		epki_clear_selection(card->drv_data);
		free(card->drv_data);
		card->drv_data = NULL;
	}
	return SC_SUCCESS;
}

static int
epki_init(sc_card_t *card)
{
	struct epki_data *priv;
	unsigned long algorithm_flags;
	int r, signing, decryption;

	/* OpenSC may initialize a forced driver even after match_card failed. */
	if (epki_match_card(card) != 1)
		return SC_ERROR_INVALID_CARD;
	card->name = "SCE7 PKCS#15 (experimental read-only)";
	card->type = SC_CARD_TYPE_EPKI_RESEARCH;
	card->cla = 0x00;
	card->drv_data = NULL;
	signing = epki_config_bool(card, "enable_local_signing");
	decryption = epki_config_bool(card, "enable_local_decryption");
	if (!signing && !decryption)
		return SC_SUCCESS;
	priv = calloc(1, sizeof(*priv));
	if (priv == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	card->drv_data = priv;
	priv->signing_enabled = signing;
	priv->decryption_enabled = decryption;
	/* OpenSC supplies DigestInfo; the applet supplies type-1 RSA padding.
	 * The additional raw signature primitive allows the shared software
	 * encoder to implement PSS, including explicit hash/MGF/salt parameters.
	 * Raw decipher also uses the shared software encoding layer. Its
	 * security environment is distinct from either signature operation.
	 */
	algorithm_flags = signing ? SC_ALGORITHM_RSA_PAD_PKCS1_TYPE_01 | SC_ALGORITHM_RSA_HASH_NONE : 0;
	priv->raw_rsa_enabled = signing && epki_config_bool(card, "enable_raw_rsa_signing");
	if (priv->raw_rsa_enabled || decryption)
		algorithm_flags |= SC_ALGORITHM_RSA_RAW;
	r = _sc_card_add_rsa_alg(card, 2048, algorithm_flags, 0);
	if (r < 0) {
		epki_finish(card);
		return r;
	}
	priv->profile_checked = 1;
	if (priv->raw_rsa_enabled || decryption) {
		/* The checked 0282 profile supports extended APDUs. Only the
		 * 256-byte RSA inputs need one; keep public read sizes
		 * bounded to the previous short-response limit.
		 */
		card->caps |= SC_CARD_CAP_APDU_EXT;
		card->max_send_size = 256;
		card->max_recv_size = 256;
	}
	card->name = decryption ? "SCE7 PKCS#15 (experimental local cryptography)" : "SCE7 PKCS#15 (experimental local signature)";
	return SC_SUCCESS;
}

/* Cache/application authentication belongs to one uninterrupted PC/SC
 * transaction. Another client may select a different app after any unlock,
 * even when the card was not reset. After reset, verify the profile again
 * before sending another PIN; a reset is not a permanent driver failure. */
static int
epki_reader_lock_obtained(sc_card_t *card, int was_reset)
{
	struct epki_data *priv = card->drv_data;
	if (priv != NULL) {
		epki_clear_selection(priv);
		if (was_reset > 0)
			priv->profile_checked = 0;
	}
	return SC_SUCCESS;
}

static int
epki_select_application(sc_card_t *card, sc_file_t **file_out)
{
	const struct sc_card_operations *iso = sc_get_iso7816_driver()->ops;
	struct epki_data *priv = card->drv_data;
	sc_path_t selected = {0};
	sc_file_t *file = NULL;
	int r;

	/* A real AID SELECT may clear the applet's PIN/security state. */
	epki_clear_selection(priv);
	selected.type = SC_PATH_TYPE_DF_NAME;
	selected.len = sizeof(epki_aid);
	memcpy(selected.value, epki_aid, sizeof(epki_aid));
	r = iso->select_file(card, &selected, &file);
	if (r < 0)
		goto done;
	if (priv != NULL) {
		if (file == NULL) {
			r = SC_ERROR_UNKNOWN_DATA_RECEIVED;
			goto done;
		}
		sc_file_dup(&priv->app_file, file);
		if (priv->app_file == NULL) {
			r = SC_ERROR_OUT_OF_MEMORY;
			goto done;
		}
		priv->app_selected = 1;
	}
	if (file_out != NULL) {
		*file_out = file;
		file = NULL;
	}
done:
	sc_file_free(file);
	return r;
}

static int
epki_select_file(sc_card_t *card, const sc_path_t *path, sc_file_t **file_out)
{
	static const u8 app_path[] = {0x3f, 0x00, 0x50, 0x15};
	const struct sc_card_operations *iso = sc_get_iso7816_driver()->ops;
	struct epki_data *priv;
	sc_path_t selected = {0};
	sc_file_t *selected_file = NULL;
	int r, locked = 0, app_path_match, app_aid_match, reuse;

	if (card == NULL || path == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;
	priv = card->drv_data;
	if (priv != NULL) {
		/* Lock before consulting the cache; the new-transaction callback
		 * invalidates it if an outer transaction has ended. */
		r = sc_lock(card);
		if (r < 0)
			return r;
		locked = 1;
		priv->security_env_valid = 0;
	}
	app_path_match = path->type == SC_PATH_TYPE_PATH && path->aid.len == 0 &&
			 (path->len == sizeof(app_path) || path->len == sizeof(app_path) + 2) &&
			 memcmp(path->value, app_path, sizeof(app_path)) == 0;
	app_aid_match = path->type == SC_PATH_TYPE_DF_NAME && path->aid.len == 0 &&
			path->len == sizeof(epki_aid) &&
			memcmp(path->value, epki_aid, sizeof(epki_aid)) == 0;

	/* The applet exposes 3F00/5015 by AID, not by FID. Keep all other
	 * paths delegated, but never retain authentication across them. */
	if (!app_path_match && !app_aid_match) {
		epki_clear_selection(priv);
		r = iso->select_file(card, path, file_out);
		goto done;
	}

	/* Once VERIFY succeeds, repeated selects of the same application are
	 * redundant and may discard card authentication. Reuse is limited to
	 * this exact AID/path while the same outer transaction is still held.
	 * Direct-child SELECT still runs and requests FCI as required. */
	reuse = priv != NULL && priv->pin_verified &&
		priv->app_selected && priv->app_file != NULL;
	if (reuse) {
		if (file_out != NULL && (app_aid_match || path->len == sizeof(app_path))) {
			sc_file_dup(&selected_file, priv->app_file);
			if (selected_file == NULL) {
				r = SC_ERROR_OUT_OF_MEMORY;
				goto done;
			}
		}
		r = SC_SUCCESS;
	} else {
		r = epki_select_application(card, &selected_file);
		if (r < 0)
			goto done;
	}

	if (app_path_match && path->len > sizeof(app_path)) {
		sc_file_free(selected_file);
		selected_file = NULL;
		selected = *path;
		selected.type = SC_PATH_TYPE_FILE_ID;
		selected.len = 2;
		memcpy(selected.value, path->value + sizeof(app_path), 2);
		r = iso->select_file(card, &selected, &selected_file);
		if (r < 0)
			goto done;
		/* Only a known EF leaves the application's DF current. A child
		 * DF, unknown file type or absent FCI cannot justify reusing it. */
		if (selected_file == NULL ||
				(selected_file->type != SC_FILE_TYPE_WORKING_EF &&
						selected_file->type != SC_FILE_TYPE_INTERNAL_EF))
			epki_clear_selection(priv);
	}
	if (file_out != NULL) {
		*file_out = selected_file;
		selected_file = NULL;
	}

done:
	if (r < 0)
		epki_clear_selection(priv);
	sc_file_free(selected_file);
	if (locked)
		sc_unlock(card);
	return r;
}

static int
epki_pin_cmd(sc_card_t *card, struct sc_pin_cmd_data *data)
{
	struct epki_data *priv = card != NULL ? card->drv_data : NULL;
	sc_apdu_t apdu;
	u8 padded_pin[8];
	int r;

	if (priv == NULL)
		return SC_ERROR_NOT_SUPPORTED;
	if (data == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;
	data->pin1.tries_left = -1;
	data->pin1.logged_in = SC_PIN_STATE_UNKNOWN;
	/* No empty VERIFY status queries, pinpad commands, change or unblock. */
	if (data->cmd != SC_PIN_CMD_VERIFY || data->pin_type != SC_AC_CHV ||
			data->pin_reference != 1 || data->apdu != NULL ||
			(data->flags & ~SC_PIN_CMD_NEED_PADDING) != 0 ||
			data->pin2.data != NULL || data->pin2.len != 0)
		return SC_ERROR_NOT_SUPPORTED;
	if (data->pin1.data == NULL || data->pin1.len < 4 || data->pin1.len > 8 ||
			data->pin1.encoding != SC_PIN_ENCODING_ASCII)
		return SC_ERROR_INVALID_ARGUMENTS;
	/* Debug output at lower layers can contain the full APDU. Refuse before
	 * copying a PIN, rather than mutate a potentially shared log context. */
	if (card->ctx == NULL || card->ctx->debug != 0)
		return SC_ERROR_NOT_ALLOWED;

	/* Acquire the transaction before the final state check: a reconnect
	 * discovered by sc_lock must invalidate the profile before PIN I/O. */
	r = sc_lock(card);
	if (r < 0)
		return r;
	if (!priv->app_selected) {
		r = epki_select_application(card, NULL);
		if (r < 0) {
			sc_unlock(card);
			return r;
		}
	}
	if (!priv->profile_checked) {
		r = epki_check_profile(card);
		if (r < 0) {
			epki_clear_selection(priv);
			sc_unlock(card);
			return r;
		}
		priv->profile_checked = 1;
	}
	/* One VERIFY per caller request. No implicit retry, PIN retention or
	 * per-connection attempt latch: OpenSC owns its PIN-cache policy. */
	priv->pin_verified = 0;
	priv->security_env_valid = 0;
	priv->security_operation = 0;
	priv->raw_signature = 0;
	memset(padded_pin, 0xff, sizeof(padded_pin));
	memcpy(padded_pin, data->pin1.data, data->pin1.len);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x20, 0x00, 0x01);
	apdu.cla = 0x00;
	apdu.data = padded_pin;
	apdu.datalen = apdu.lc = sizeof(padded_pin);
	/* In particular, do not retry VERIFY after a wrong-length response. */
	apdu.flags |= SC_APDU_FLAGS_NO_RETRY_WL | SC_APDU_FLAGS_NO_GET_RESP;
	r = sc_transmit_apdu(card, &apdu);
	sc_mem_clear(padded_pin, sizeof(padded_pin));
	if (r < 0) {
		epki_clear_selection(priv);
		goto pin_done;
	}
	if (apdu.sw1 == 0x63 && (apdu.sw2 & 0xf0) == 0xc0) {
		data->pin1.tries_left = apdu.sw2 & 0x0f;
		r = SC_ERROR_PIN_CODE_INCORRECT;
		goto pin_done;
	}
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r == SC_SUCCESS) {
		priv->pin_verified = 1;
		data->pin1.logged_in = SC_PIN_STATE_LOGGED_IN;
	}
pin_done:
	sc_unlock(card);
	return r;
}

/* OpenSC PKCS#11 uses software-only C_Logout. Other callers of sc_logout
 * need a real card operation: reselecting this applet clears its PIN state,
 * as observed during login testing. Never invent an unverified logout APDU. */
static int
epki_logout(sc_card_t *card)
{
	struct epki_data *priv = card != NULL ? card->drv_data : NULL;
	int r;

	if (priv == NULL)
		return SC_ERROR_NOT_SUPPORTED;
	r = sc_lock(card);
	if (r < 0) {
		epki_clear_selection(priv);
		return r;
	}
	r = epki_select_application(card, NULL);
	sc_unlock(card);
	return r;
}

static int
epki_set_security_env(sc_card_t *card,
		const struct sc_security_env *env, int se_num)
{
	struct epki_data *priv = card != NULL ? card->drv_data : NULL;
	u8 mse[] = {0x84, 0x01, 0x00, 0x80, 0x01, 0x00};
	const unsigned long required = SC_SEC_ENV_ALG_PRESENT | SC_SEC_ENV_KEY_REF_PRESENT;
	const unsigned long supported = SC_ALGORITHM_RSA_PAD_PKCS1_TYPE_01 | SC_ALGORITHM_RSA_HASH_NONE;
	sc_apdu_t apdu;
	size_t i;
	int r, raw, signing, decryption;

	if (priv == NULL)
		return SC_ERROR_NOT_SUPPORTED;
	priv->security_env_valid = 0;
	priv->security_operation = 0;
	priv->raw_signature = 0;
	if (env == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;
	raw = env->algorithm_flags == SC_ALGORITHM_RSA_PAD_NONE;
	signing = env->operation == SC_SEC_OPERATION_SIGN && priv->signing_enabled &&
		  (env->algorithm_flags == supported || (raw && priv->raw_rsa_enabled));
	decryption = env->operation == SC_SEC_OPERATION_DECIPHER && priv->decryption_enabled && raw;
	if (se_num != 0 || (!signing && !decryption) ||
			env->algorithm != SC_ALGORITHM_RSA || env->key_size_bits != 2048 ||
			(env->flags & required) != required ||
			(env->flags & ~(required | SC_SEC_ENV_FILE_REF_PRESENT)) != 0 ||
			env->key_ref_len != 1 || env->key_ref[0] == 0)
		return SC_ERROR_NOT_SUPPORTED;
	/* PKCS#15 supplies the final FID of observed path 3F00/5015. The
	 * applet uses the explicit key reference, not a separate key file. */
	if ((env->flags & SC_SEC_ENV_FILE_REF_PRESENT) &&
			(env->file_ref.type != SC_PATH_TYPE_FILE_ID || env->file_ref.len != 2 ||
					env->file_ref.aid.len != 0 || env->file_ref.value[0] != 0x50 ||
					env->file_ref.value[1] != 0x15))
		return SC_ERROR_NOT_SUPPORTED;
	for (i = 0; i < SC_SEC_ENV_MAX_PARAMS; i++)
		if (env->params[i].param_type || env->params[i].value || env->params[i].value_len)
			return SC_ERROR_NOT_SUPPORTED;
	mse[2] = env->key_ref[0];
	r = epki_private_state(priv, 0, env->operation);
	if (r < 0)
		return r;

	r = sc_lock(card);
	if (r < 0)
		return r;
	r = epki_private_state(priv, 0, env->operation);
	if (r < 0) {
		sc_unlock(card);
		return r;
	}
	/* The decipher CRT is independently established for this profile.
	 * Do not reuse a signing environment for private-key decryption. */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, signing ? 0xb6 : 0xb8);
	apdu.cla = 0x00;
	apdu.data = mse;
	apdu.datalen = apdu.lc = sizeof(mse);
	apdu.flags |= SC_APDU_FLAGS_NO_RETRY_WL | SC_APDU_FLAGS_NO_GET_RESP;
	/* This call sends MSE once. Failure leaves no usable environment; a
	 * later caller may begin a new operation with a fresh MSE. */
	r = sc_transmit_apdu(card, &apdu);
	if (r < 0)
		epki_clear_selection(priv);
	else
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r == SC_SUCCESS) {
		priv->security_env_valid = 1;
		priv->security_operation = env->operation;
		priv->raw_signature = signing && raw;
	} else if (r == SC_ERROR_SECURITY_STATUS_NOT_SATISFIED) {
		priv->pin_verified = 0;
	}
	sc_unlock(card);
	return r;
}

static int
epki_compute_signature(sc_card_t *card, const u8 *input,
		size_t input_len, u8 *output, size_t output_len)
{
	struct epki_data *priv = card != NULL ? card->drv_data : NULL;
	sc_apdu_t apdu;
	u8 response[256];
	int r, raw;

	if (priv == NULL || !priv->signing_enabled)
		return SC_ERROR_NOT_SUPPORTED;
	if (priv->security_env_valid && priv->security_operation != SC_SEC_OPERATION_SIGN)
		return SC_ERROR_NOT_ALLOWED;
	raw = priv->raw_signature;
	if (raw && !priv->raw_rsa_enabled)
		return SC_ERROR_NOT_SUPPORTED;
	if (input == NULL || output == NULL ||
			(raw ? input_len != sizeof(response) : input_len == 0 || input_len > sizeof(response) - 11))
		return SC_ERROR_INVALID_ARGUMENTS;
	if (output_len < sizeof(response))
		return SC_ERROR_BUFFER_TOO_SMALL;
	r = epki_private_state(priv, 1, SC_SEC_OPERATION_SIGN);
	if (r < 0)
		return r;
	r = sc_lock(card);
	if (r < 0)
		return r;
	r = epki_private_state(priv, 1, SC_SEC_OPERATION_SIGN);
	if (r < 0) {
		sc_unlock(card);
		return r;
	}
	priv->security_env_valid = 0;
	priv->security_operation = 0;
	sc_format_apdu(card, &apdu, raw ? SC_APDU_CASE_4_EXT : SC_APDU_CASE_4_SHORT,
			0x2a, raw ? 0x80 : 0x9e, raw ? 0x86 : 0x9a);
	apdu.cla = 0x00;
	apdu.data = input;
	apdu.datalen = apdu.lc = input_len;
	/* The legacy raw primitive takes the full encoded representative with
	 * no leading indicator. Its extended Le is 0000 (maximum); the actual
	 * RSA-2048 result is still bounded and checked at exactly 256 bytes.
	 */
	apdu.le = raw ? 65536 : sizeof(response);
	apdu.resp = response;
	apdu.resplen = sizeof(response);
	/* GET RESPONSE can collect an already computed signature. Retrying
	 * the original PSO command or command chaining is not permitted. */
	apdu.flags |= SC_APDU_FLAGS_NO_RETRY_WL;
	r = sc_transmit_apdu(card, &apdu);
	if (r < 0) {
		epki_clear_selection(priv);
		goto sign_done;
	}
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r < 0) {
		if (r == SC_ERROR_SECURITY_STATUS_NOT_SATISFIED)
			priv->pin_verified = 0;
		goto sign_done;
	}
	if (apdu.resplen != sizeof(response)) {
		r = SC_ERROR_UNKNOWN_DATA_RECEIVED;
		goto sign_done;
	}
	memcpy(output, response, sizeof(response));
	r = sizeof(response);
sign_done:
	sc_mem_clear(response, sizeof(response));
	sc_unlock(card);
	return r;
}

static int
epki_decipher(sc_card_t *card, const u8 *input, size_t input_len,
		u8 *output, size_t output_len)
{
	struct epki_data *priv = card != NULL ? card->drv_data : NULL;
	sc_apdu_t apdu;
	u8 response[256];
	int r;

	if (priv == NULL || !priv->decryption_enabled)
		return SC_ERROR_NOT_SUPPORTED;
	/* Lower-layer response logs could contain decrypted key material. */
	if (card->ctx == NULL || card->ctx->debug != 0)
		return SC_ERROR_NOT_ALLOWED;
	if (input == NULL || output == NULL || input_len != sizeof(response))
		return SC_ERROR_INVALID_ARGUMENTS;
	if (output_len < sizeof(response))
		return SC_ERROR_BUFFER_TOO_SMALL;
	r = epki_private_state(priv, 1, SC_SEC_OPERATION_DECIPHER);
	if (r < 0)
		return r;
	r = sc_lock(card);
	if (r < 0)
		return r;
	r = epki_private_state(priv, 1, SC_SEC_OPERATION_DECIPHER);
	if (r < 0)
		goto done;
	priv->security_env_valid = 0;
	priv->security_operation = 0;
	/* Profile 0282 takes a complete RSA representative without an
	 * indicator. Keep padding validation in OpenSC's existing layer. */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_EXT, 0x2a, 0x80, 0x86);
	apdu.cla = 0x00;
	apdu.data = input;
	apdu.datalen = apdu.lc = input_len;
	apdu.le = 65536;
	apdu.resp = response;
	apdu.resplen = sizeof(response);
	apdu.flags |= SC_APDU_FLAGS_NO_RETRY_WL;
	r = sc_transmit_apdu(card, &apdu);
	if (r < 0) {
		epki_clear_selection(priv);
		goto done;
	}
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r < 0) {
		if (r == SC_ERROR_SECURITY_STATUS_NOT_SATISFIED)
			priv->pin_verified = 0;
		goto done;
	}
	if (apdu.resplen != sizeof(response)) {
		r = SC_ERROR_UNKNOWN_DATA_RECEIVED;
		goto done;
	}
	memcpy(output, response, sizeof(response));
	r = sizeof(response);
done:
	sc_mem_clear(response, sizeof(response));
	sc_unlock(card);
	return r;
}

static struct sc_card_operations epki_ops;
static struct sc_card_driver epki_driver = {
		"SCE7 PKCS#15 public-data research driver", "epki-research",
		&epki_ops, NULL, 0, NULL};

struct sc_card_driver *
sc_get_epki_research_driver(void)
{
	const struct sc_card_operations *iso = sc_get_iso7816_driver()->ops;

	/* Allowlist operations: never inherit ISO write or security operations. */
	memset(&epki_ops, 0, sizeof(epki_ops));
	epki_ops.match_card = epki_match_card;
	epki_ops.init = epki_init;
	epki_ops.finish = epki_finish;
	epki_ops.card_reader_lock_obtained = epki_reader_lock_obtained;
	epki_ops.read_binary = iso->read_binary;
	epki_ops.read_record = iso->read_record;
	epki_ops.select_file = epki_select_file;
	epki_ops.get_response = iso->get_response;
	epki_ops.check_sw = iso->check_sw;
	epki_ops.process_fci = iso->process_fci;
	epki_ops.pin_cmd = epki_pin_cmd;
	epki_ops.logout = epki_logout;
	epki_ops.compute_signature = epki_compute_signature;
	epki_ops.decipher = epki_decipher;
	epki_ops.set_security_env = epki_set_security_env;
	return &epki_driver;
}
