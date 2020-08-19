/*
 * card-npa.c: Recognize known German identity cards
 *
 * Copyright (C) 2011-2018 Frank Morgner <frankmorgner@gmail.com>
 *
 * This file is part of OpenSC.
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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "card-npa.h"
#include "libopensc/internal.h"
#include "libopensc/opensc.h"
#include "libopensc/pace.h"
#include "libopensc/sm.h"
#include "sm/sm-eac.h"
#include <string.h>

#ifdef ENABLE_OPENSSL
#include <openssl/evp.h>
#endif

static int fread_to_eof(const char *file, unsigned char **buf, size_t *buflen);
#include "../tools/fread_to_eof.c"

struct npa_drv_data {
	const char *can;
	unsigned char *st_dv_certificate;
	size_t st_dv_certificate_len;
	unsigned char *st_certificate;
	size_t st_certificate_len;
	unsigned char *st_key;
	size_t st_key_len;
	unsigned char *ef_cardaccess;
	size_t ef_cardaccess_length;
	unsigned char *ef_cardsecurity;
	size_t ef_cardsecurity_length;
};

static struct npa_drv_data *npa_drv_data_create(void)
{
	struct npa_drv_data *drv_data = calloc(1, sizeof *drv_data);
	return drv_data;
}

static void npa_drv_data_free(struct npa_drv_data *drv_data)
{
	if (drv_data) {
		free(drv_data->ef_cardaccess);
		free(drv_data->ef_cardsecurity);
		free(drv_data->st_certificate);
		free(drv_data->st_dv_certificate);
		free(drv_data->st_key);
		free(drv_data);
	}
}

static struct sc_card_operations npa_ops;
static struct sc_card_driver npa_drv = {
	"German ID card (neuer Personalausweis, nPA)",
	"npa",
	&npa_ops,
	NULL, 0, NULL
};

static int npa_load_options(sc_context_t *ctx, struct npa_drv_data *drv_data)
{
	int r;
	size_t i, j;
	scconf_block **found_blocks, *block;
	const char *file;

	if (!ctx || !drv_data) {
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	for (i = 0; ctx->conf_blocks[i]; i++) {
		found_blocks = scconf_find_blocks(ctx->conf, ctx->conf_blocks[i],
					"card_driver", "npa");
		if (!found_blocks)
			continue;

		for (j = 0, block = found_blocks[j]; block; j++, block = found_blocks[j]) {
			if (!drv_data->can)
				drv_data->can = scconf_get_str(block, "can", NULL);

			if (!drv_data->st_dv_certificate
					|| !drv_data->st_dv_certificate_len) {
				file = scconf_get_str(block, "st_dv_certificate", NULL);
				if (!fread_to_eof(file,
							(unsigned char **) &drv_data->st_dv_certificate,
							&drv_data->st_dv_certificate_len))
					sc_log(ctx, "Warning: Could not read %s.\n", file);
			}

			if (!drv_data->st_certificate
					|| !drv_data->st_certificate_len) {
				file = scconf_get_str(block, "st_certificate", NULL);
				if (!fread_to_eof(file,
							(unsigned char **) &drv_data->st_certificate,
							&drv_data->st_certificate_len))
					sc_log(ctx, "Warning: Could not read %s.\n", file);
			}

			if (!drv_data->st_key
					|| !drv_data->st_key_len) {
				file = scconf_get_str(block, "st_key", NULL);
				if (!fread_to_eof(file,
							(unsigned char **) &drv_data->st_key,
							&drv_data->st_key_len))
					sc_log(ctx, "Warning: Could not read %s.\n", file);
			}
		}
		
		free(found_blocks);
	}
	r = SC_SUCCESS;

err:
	return r;
}

static int npa_match_card(sc_card_t * card)
{
	int r = 0;

	if (SC_SUCCESS == sc_enum_apps(card)) {
		unsigned char esign_aid_0[] = {
			0xE8, 0x28, 0xBD, 0x08, 0x0F, 0xA0, 0x00, 0x00, 0x01, 0x67, 0x45, 0x53, 0x49, 0x47, 0x4E,
		}, esign_aid_1[] = {
			0xa0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01,
		}, esign_aid_2[] = {
			0xe8, 0x07, 0x04, 0x00, 0x7f, 0x00, 0x07, 0x03, 0x02,
		}, esign_aid_3[] = {
			0xA0, 0x00, 0x00, 0x01, 0x67, 0x45, 0x53, 0x49, 0x47, 0x4E,
		};
		int i, found_0 = 0, found_1 = 0, found_2 = 0, found_3 = 0;
		for (i = 0; i < card->app_count; i++)   {
			struct sc_app_info *app_info = card->app[i];
			if (sizeof esign_aid_0 == app_info->aid.len
					&& 0 == memcmp(esign_aid_0, app_info->aid.value,
						sizeof esign_aid_0))
				found_0 = 1;
			if (sizeof esign_aid_1 == app_info->aid.len
					&& 0 == memcmp(esign_aid_1, app_info->aid.value,
						sizeof esign_aid_1))
				found_1 = 1;
			if (sizeof esign_aid_2 == app_info->aid.len
					&& 0 == memcmp(esign_aid_2, app_info->aid.value,
						sizeof esign_aid_2))
				found_2 = 1;
			if (sizeof esign_aid_3 == app_info->aid.len
					&& 0 == memcmp(esign_aid_3, app_info->aid.value,
						sizeof esign_aid_3))
				found_3 = 1;
		}
		if (found_0 && found_1 && found_2 && found_3) {
			card->type = SC_CARD_TYPE_NPA;
			r = 1;
		}
	}

	if (r == 0) {
		sc_free_apps(card);
	}

	return r;
}

static void npa_get_cached_pace_params(sc_card_t *card,
		struct establish_pace_channel_input *pace_input,
		struct establish_pace_channel_output *pace_output)
{
	struct npa_drv_data *drv_data;

	if (card->drv_data) {
		drv_data = card->drv_data;
		
		if (pace_output) {
			pace_output->ef_cardaccess = drv_data->ef_cardaccess;
			pace_output->ef_cardaccess_length = drv_data->ef_cardaccess_length;
		}

		if (pace_input && pace_input->pin_id == PACE_PIN_ID_CAN) {
			pace_input->pin = (const unsigned char *) drv_data->can;
			pace_input->pin_length = drv_data->can ? strlen(drv_data->can) : 0;
		}
	}
}

static void npa_get_cached_ta_params(sc_card_t *card,
	const unsigned char *certs[2], size_t certs_lens[2],
	const unsigned char **st_key, size_t *st_key_len)
{
	struct npa_drv_data *drv_data;
	size_t i;

	if (card->drv_data) {
		drv_data = card->drv_data;

		if (certs && certs_lens) {
			i = 0;
			if (drv_data->st_dv_certificate) {
				certs[i] = drv_data->st_dv_certificate;
				certs_lens[i] = drv_data->st_dv_certificate_len;
				i++;
			}
			if (drv_data->st_certificate) {
				certs[i] = drv_data->st_certificate;
				certs_lens[i] = drv_data->st_certificate_len;
			}
		}
		if (st_key && st_key_len) {
			*st_key = drv_data->st_key;
			*st_key_len = drv_data->st_key_len;
		}
	}
}

static void npa_get_cached_ca_params(sc_card_t *card,
	unsigned char **ef_cardsecurity, size_t *ef_cardsecurity_length)
{
	struct npa_drv_data *drv_data;

	if (card->drv_data) {
		drv_data = card->drv_data;

		if (ef_cardsecurity && ef_cardsecurity_length) {
			*ef_cardsecurity = drv_data->ef_cardsecurity;
			*ef_cardsecurity_length = drv_data->ef_cardsecurity_length;
		}
	}
}

static void npa_cache_or_free(sc_card_t *card,
		unsigned char **ef_cardaccess, size_t *ef_cardaccess_length,
		unsigned char **ef_cardsecurity, size_t *ef_cardsecurity_length)
{
	struct npa_drv_data *drv_data;

	if (card && card->drv_data) {
		drv_data = card->drv_data;

		if (ef_cardaccess && ef_cardaccess_length
				&& *ef_cardaccess && *ef_cardaccess_length) {
			drv_data->ef_cardaccess = *ef_cardaccess;
			drv_data->ef_cardaccess_length = *ef_cardaccess_length;
			*ef_cardaccess = NULL;
			*ef_cardaccess_length = 0;
		}
		if (ef_cardsecurity && ef_cardsecurity_length
				&& *ef_cardsecurity && *ef_cardsecurity_length) {
			drv_data->ef_cardsecurity = *ef_cardsecurity;
			drv_data->ef_cardsecurity_length = *ef_cardsecurity_length;
			*ef_cardsecurity = NULL;
			*ef_cardsecurity_length = 0;
		}
	} else {
		if (ef_cardaccess && ef_cardaccess_length) {
			free(*ef_cardaccess);
			*ef_cardaccess = NULL;
			*ef_cardaccess_length = 0;
		}
		if (ef_cardsecurity && ef_cardsecurity_length) {
			free(*ef_cardsecurity);
			*ef_cardsecurity = NULL;
			*ef_cardsecurity_length = 0;
		}
	}
}

static int npa_unlock_esign(sc_card_t *card)
{
	int r = SC_ERROR_INTERNAL;
	struct establish_pace_channel_input pace_input;
	struct establish_pace_channel_output pace_output;
	const unsigned char *certs[] = { NULL, NULL };
	size_t certs_lens[] = { 0, 0};
	const unsigned char *st_key = NULL;
	size_t st_key_len = 0;
	unsigned char *ef_cardsecurity = NULL;
	size_t ef_cardsecurity_len = 0;
	memset(&pace_input, 0, sizeof pace_input);
	memset(&pace_output, 0, sizeof pace_output);

	if (!card) {
		r = SC_ERROR_INVALID_CARD;
		goto err;
	}

	sc_log(card->ctx, "Will verify CAN first for unlocking eSign application.\n");
	pace_input.chat = esign_chat;
	pace_input.chat_length = sizeof esign_chat;
	pace_input.pin_id = PACE_PIN_ID_CAN;
	npa_get_cached_pace_params(card, &pace_input, &pace_output);
	npa_get_cached_ta_params(card, certs, certs_lens, &st_key, &st_key_len);
	npa_get_cached_ca_params(card, &ef_cardsecurity, &ef_cardsecurity_len);

	if (!(card->reader && (card->reader->capabilities & SC_READER_CAP_PACE_ESIGN))
			&& (!st_key || !st_key_len)) {
		sc_log(card->ctx, "QES requires a comfort reader (CAT-K) or a ST certificate.\n");
		r = SC_ERROR_NOT_SUPPORTED;
		goto err;
	}

	/* FIXME set flags with opensc.conf */
	eac_default_flags |= EAC_FLAG_DISABLE_CHECK_ALL;
	eac_default_flags |= EAC_FLAG_DISABLE_CHECK_TA;
	eac_default_flags |= EAC_FLAG_DISABLE_CHECK_CA;

	/* FIXME show an alert to the user if CAN is NULL */
	r = perform_pace(card, pace_input, &pace_output, EAC_TR_VERSION_2_02);
	if (SC_SUCCESS != r) {
		sc_log(card->ctx, "Error verifying CAN.\n");
		goto err;
	}

	if (card->reader->capabilities & SC_READER_CAP_PACE_ESIGN) {
		sc_log(card->ctx, "Proved Access rights to eSign application with comfort reader (CAT-K).\n");
	} else {
		r = perform_terminal_authentication(card, certs, certs_lens, st_key,
				st_key_len, NULL, 0);
		if (r != SC_SUCCESS) {
			sc_log(card->ctx, "Error authenticating as signature terminal.\n");
			goto err;
		}
		r = perform_chip_authentication(card, &ef_cardsecurity, &ef_cardsecurity_len);
		if ( SC_SUCCESS != r) {
			sc_log(card->ctx, "Error verifying the chip's authenticity.\n");
		}

		sc_log(card->ctx, "Proved Access rights to eSign application with configured key as ST.\n");
	}

err:
	npa_cache_or_free(card, &pace_output.ef_cardaccess,
			&pace_output.ef_cardaccess_length,
			&ef_cardsecurity, &ef_cardsecurity_len);
	free(pace_output.recent_car);
	free(pace_output.previous_car);
	free(pace_output.id_icc);
	free(pace_output.id_pcd);

	return r;
}

static int npa_finish(sc_card_t * card)
{
	sc_sm_stop(card);
	npa_drv_data_free(card->drv_data);
	card->drv_data = NULL;

	return SC_SUCCESS;
}

static int npa_init(sc_card_t * card)
{
	int flags = SC_ALGORITHM_ECDSA_RAW;
	int ext_flags = 0;
	int r;

	if (!card) {
		r = SC_ERROR_INVALID_CARD;
		goto err;
	}

	card->caps |= SC_CARD_CAP_APDU_EXT | SC_CARD_CAP_RNG;
	/* 1520 bytes is the minimum length of the communication buffer in all
	 * Chip/OS variants */
	card->max_recv_size = 1520;
	card->max_send_size = 1520;
#ifdef ENABLE_SM
	memset(&card->sm_ctx, 0, sizeof card->sm_ctx);
#endif

	r = _sc_card_add_ec_alg(card, 192, flags, ext_flags, NULL);
	if (r != SC_SUCCESS)
		goto err;
	r = _sc_card_add_ec_alg(card, 224, flags, ext_flags, NULL);
	if (r != SC_SUCCESS)
		goto err;
	r = _sc_card_add_ec_alg(card, 256, flags, ext_flags, NULL);
	if (r != SC_SUCCESS)
		goto err;
	/* nPA does not encode the proprietary fieldSize in PrivateECKeyAttributes,
	 * which leaves it at 0 for OpenSC, so we need to add 0x00 as supported
	 * field_length */
	r = _sc_card_add_ec_alg(card, 0, flags, ext_flags, NULL);
	if (r != SC_SUCCESS)
		goto err;

	card->drv_data = npa_drv_data_create();
	if (!card->drv_data) {
		npa_finish(card);
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	r = npa_load_options(card->ctx, card->drv_data);
	if (r != SC_SUCCESS)
		goto err;

	/* unlock the eSign application for reading the certificates
	 * by the PKCS#15 layer (i.e. sc_pkcs15_bind_internal) */
	if (SC_SUCCESS != npa_unlock_esign(card)) {
		sc_log(card->ctx, "Probably not all functionality will be available.\n");
	}

err:
	return r;
}

static int npa_set_security_env(struct sc_card *card,
		const struct sc_security_env *env, int se_num)
{
	int r;
	struct sc_card_driver *iso_drv;
	struct sc_security_env fixed_env;

	iso_drv = sc_get_iso7816_driver();

	if (!env || !iso_drv || !iso_drv->ops || !iso_drv->ops->set_security_env) {
		r = SC_ERROR_INTERNAL;
	} else {
		memcpy(&fixed_env, env, sizeof fixed_env);
		if (env->operation == SC_SEC_OPERATION_SIGN) {
			/* The pkcs#15 layer assumes that the field_size of the private key
			 * object is correctly initialized and wants to include it as
			 * algorithm reference. We disable it here */
			fixed_env.flags &= ~SC_SEC_ENV_ALG_REF_PRESENT;
		}
		r = iso_drv->ops->set_security_env(card, &fixed_env, se_num);
	}

	return r;
}

static int npa_pin_cmd_get_info(struct sc_card *card,
		struct sc_pin_cmd_data *data, int *tries_left)
{
	int r;
	u8 pin_reference;

	if (!data || data->pin_type != SC_AC_CHV || !tries_left) {
		r = SC_ERROR_INVALID_ARGUMENTS;
		goto err;
	}

	pin_reference = data->pin_reference;
	switch (data->pin_reference) {
		case PACE_PIN_ID_CAN:
		case PACE_PIN_ID_MRZ:
			/* usually unlimited number of retries */
			*tries_left = -1;
			data->pin1.max_tries = -1;
			data->pin1.tries_left = -1;
			r = SC_SUCCESS;
			break;

		case PACE_PIN_ID_PUK:
			/* usually 10 tries */
			*tries_left = 10;
			data->pin1.max_tries = 10;
			r = eac_pace_get_tries_left(card,
					pin_reference, tries_left);
			data->pin1.tries_left = *tries_left;
			break;

		case PACE_PIN_ID_PIN:
			/* usually 3 tries */
			*tries_left = 3;
			data->pin1.max_tries = 3;
			r = eac_pace_get_tries_left(card,
					pin_reference, tries_left);
			data->pin1.tries_left = *tries_left;
			break;

		default:
			r = SC_ERROR_OBJECT_NOT_FOUND;
			goto err;
	}

err:
	return r;
}

static int npa_pace_verify(struct sc_card *card,
		unsigned char pin_reference, struct sc_pin_cmd_pin *pin,
		const unsigned char *chat, size_t chat_length, int *tries_left)
{
	int r;
	struct establish_pace_channel_input pace_input;
	struct establish_pace_channel_output pace_output;

	memset(&pace_input, 0, sizeof pace_input);
	memset(&pace_output, 0, sizeof pace_output);
	if (chat) {
		pace_input.chat = chat;
		pace_input.chat_length = chat_length;
	}
	pace_input.pin_id = pin_reference;
	if (pin) {
		pace_input.pin = pin->data;
		pace_input.pin_length = pin->len;
	}
	npa_get_cached_pace_params(card, &pace_input, &pace_output);

	r = perform_pace(card, pace_input, &pace_output, EAC_TR_VERSION_2_02);

	if (tries_left) {
		if (pace_output.mse_set_at_sw1 == 0x63
				&& (pace_output.mse_set_at_sw2 & 0xc0) == 0xc0) {
			*tries_left = pace_output.mse_set_at_sw2 & 0x0f;
		} else {
			*tries_left = -1;
		}
	}

	/* resume the PIN if needed */
	if (pin_reference == PACE_PIN_ID_PIN
			&& r != SC_SUCCESS
			&& pace_output.mse_set_at_sw1 == 0x63
			&& (pace_output.mse_set_at_sw2 & 0xc0) == 0xc0
			&& (pace_output.mse_set_at_sw2 & 0x0f) <= EAC_UC_PIN_SUSPENDED) {
		/* TODO ask for user consent when automatically resuming the PIN */
		sc_log(card->ctx, "%s is suspended. Will try to resume it with %s.\n",
				eac_secret_name(pin_reference), eac_secret_name(PACE_PIN_ID_CAN));

		pace_input.pin_id = PACE_PIN_ID_CAN;
		pace_input.pin = NULL;
		pace_input.pin_length = 0;

		r = perform_pace(card, pace_input, &pace_output, EAC_TR_VERSION_2_02);

		if (r == SC_SUCCESS) {
			pace_input.pin_id = pin_reference;
			if (pin) {
				pace_input.pin = pin->data;
				pace_input.pin_length = pin->len;
			}

			r = perform_pace(card, pace_input, &pace_output, EAC_TR_VERSION_2_02);

			if (r == SC_SUCCESS) {
				sc_log(card->ctx, "%s resumed.\n", eac_secret_name(pin_reference));
				if (tries_left) {
					*tries_left = EAC_MAX_PIN_TRIES;
				}
			} else {
				if (tries_left) {
					if (pace_output.mse_set_at_sw1 == 0x63
							&& (pace_output.mse_set_at_sw2 & 0xc0) == 0xc0) {
						*tries_left = pace_output.mse_set_at_sw2 & 0x0f;
					} else {
						*tries_left = -1;
					}
				}
			}
		}
	}

	if (pin_reference == PACE_PIN_ID_PIN && tries_left) {
	   if (*tries_left == 0) {
		   sc_log(card->ctx, "%s is suspended and must be resumed.\n",
				   eac_secret_name(pin_reference));
	   } else if (*tries_left == 1) {
		   sc_log(card->ctx, "%s is blocked and must be unblocked.\n",
				   eac_secret_name(pin_reference));
	   }
	}

	npa_cache_or_free(card, &pace_output.ef_cardaccess,
			&pace_output.ef_cardaccess_length, NULL, NULL);
	free(pace_output.recent_car);
	free(pace_output.previous_car);
	free(pace_output.id_icc);
	free(pace_output.id_pcd);

	return r;
}

static int npa_standard_pin_cmd(struct sc_card *card,
		struct sc_pin_cmd_data *data, int *tries_left)
{
	int r;
	struct sc_card_driver *iso_drv;

	iso_drv = sc_get_iso7816_driver();

	if (!iso_drv || !iso_drv->ops || !iso_drv->ops->pin_cmd) {
		r = SC_ERROR_INTERNAL;
	} else {
		r = iso_drv->ops->pin_cmd(card, data, tries_left);
	}

	return r;
}

int
npa_reset_retry_counter(sc_card_t *card, enum s_type pin_id,
		int ask_for_secret, const char *new, size_t new_len)
{
	sc_apdu_t apdu;
	char *p = NULL;
	int r;

	if (ask_for_secret && (!new || !new_len)) {
		if (!(SC_READER_CAP_PIN_PAD & card->reader->capabilities)) {
#ifdef ENABLE_OPENSSL
			p = malloc(EAC_MAX_PIN_LEN+1);
			if (!p) {
				sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Not enough memory for new PIN.\n");
				return SC_ERROR_OUT_OF_MEMORY;
			}
			if (0 > EVP_read_pw_string_min(p,
						EAC_MIN_PIN_LEN, EAC_MAX_PIN_LEN+1,
						"Please enter your new PIN: ", 0)) {
				sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not read new PIN.\n");
				free(p);
				return SC_ERROR_INTERNAL;
			}
			new_len = strlen(p);
			if (new_len > EAC_MAX_PIN_LEN) {
				free(p);
				return SC_ERROR_INVALID_PIN_LENGTH;
			}
			new = p;
#else
			return SC_ERROR_NOT_SUPPORTED;
#endif
		}
	}

	sc_format_apdu(card, &apdu, 0, 0x2C, 0, pin_id);
	apdu.data = (u8 *) new;
	apdu.datalen = new_len;
	apdu.lc = apdu.datalen;

	if (new_len || ask_for_secret) {
		apdu.p1 = 0x02;
		apdu.cse = SC_APDU_CASE_3_SHORT;
	} else {
		apdu.p1 = 0x03;
		apdu.cse = SC_APDU_CASE_1;
	}

	if (ask_for_secret && !new_len) {
		struct sc_pin_cmd_data data;
		data.apdu = &apdu;
		data.cmd = SC_PIN_CMD_CHANGE;
		data.flags = SC_PIN_CMD_IMPLICIT_CHANGE;
		data.pin2.encoding = SC_PIN_ENCODING_ASCII;
		data.pin2.offset = 5;
		data.pin2.max_length = EAC_MAX_PIN_LEN;
		data.pin2.min_length = EAC_MIN_PIN_LEN;
		data.pin2.pad_length = 0;
		r = card->reader->ops->perform_verify(card->reader, &data);
	} else
		r = sc_transmit_apdu(card, &apdu);

	if (p) {
		sc_mem_clear(p, new_len);
		free(p);
	}

	return r;
}

static int npa_pin_cmd(struct sc_card *card,
		struct sc_pin_cmd_data *data, int *tries_left)
{
	int r;

	if (!data) {
		r = SC_ERROR_INVALID_ARGUMENTS;
		goto err;
	}

	if (data->pin_type != SC_AC_CHV) {
		r = SC_ERROR_NOT_SUPPORTED;
		goto err;
	}

	switch (data->cmd) {
		case SC_PIN_CMD_GET_INFO:
			r = npa_pin_cmd_get_info(card, data, tries_left);
			if (r != SC_SUCCESS)
				goto err;
			break;

		case SC_PIN_CMD_UNBLOCK:
#ifdef ENABLE_SM
			/* opensc-explorer unblocks the PIN by only sending
			 * SC_PIN_CMD_UNBLOCK whereas the PKCS#15 framework first verifies
			 * the PUK with SC_PIN_CMD_VERIFY and then calls with
			 * SC_PIN_CMD_UNBLOCK.
			 *
			 * Here we determine whether the PUK has been verified or not by
			 * checking if an SM channel has been established. */
			if (card->sm_ctx.sm_mode != SM_MODE_TRANSMIT) {
				/* PUK has not yet been verified */
				r = npa_pace_verify(card, PACE_PIN_ID_PUK, &(data->pin1), NULL,
						0, NULL);
				if (r != SC_SUCCESS)
					goto err;
			}
#endif
			r = npa_reset_retry_counter(card, data->pin_reference, 0,
					NULL, 0);
			if (r != SC_SUCCESS)
				goto err;
			break;

		case SC_PIN_CMD_CHANGE:
		case SC_PIN_CMD_VERIFY:
			switch (data->pin_reference) {
				case PACE_PIN_ID_CAN:
				case PACE_PIN_ID_PUK:
				case PACE_PIN_ID_MRZ:
				case PACE_PIN_ID_PIN:
					r = npa_pace_verify(card, data->pin_reference,
							&(data->pin1), NULL, 0, tries_left);
					if (r != SC_SUCCESS)
						goto err;
					break;

				default:
					/* assuming QES PIN */

					/* We assume that the eSign application has already been
					 * unlocked, see npa_init().
					 *
					 * Now, verify the QES PIN. */
					r = npa_standard_pin_cmd(card, data, tries_left);
					if (r != SC_SUCCESS)
						goto err;
					break;
			}

			if (data->cmd == SC_PIN_CMD_CHANGE) {
				r = npa_reset_retry_counter(card, data->pin_reference, 1,
						(const char *) data->pin2.data, data->pin2.len);
				if (r != SC_SUCCESS)
					goto err;
			}
			break;

		default:
			r = SC_ERROR_INTERNAL;
			goto err;
			break;

	}

err:
	LOG_FUNC_RETURN(card->ctx, r);
}

static int npa_logout(sc_card_t *card)
{
	struct sc_apdu apdu;

	sc_sm_stop(card);

	if (card->reader->capabilities & SC_READER_CAP_PACE_GENERIC) {
		/* If PACE is done between reader and card, SM is transparent to us as
		 * it ends at the reader. With CLA=0x0C we provoke a SM error to
		 * disable SM on the reader. */
		sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0xA4, 0x00, 0x00);
		apdu.cla = 0x0C;
		if (SC_SUCCESS != sc_transmit_apdu(card, &apdu))
			sc_log(card->ctx, "Warning: Could not logout.");
	}
	return sc_select_file(card, sc_get_mf_path(), NULL);
}

struct sc_card_driver *sc_get_npa_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	npa_ops = *iso_drv->ops;
	npa_ops.match_card = npa_match_card;
	npa_ops.init = npa_init;
	npa_ops.finish = npa_finish;
	npa_ops.set_security_env = npa_set_security_env;
	npa_ops.pin_cmd = npa_pin_cmd;
	npa_ops.logout = npa_logout;

	return &npa_drv;
}
