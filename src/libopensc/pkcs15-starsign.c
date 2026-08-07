/*
 * Support for G&D StarSign CUT S tokens.
 * This handles PKCS#15 bootstrap quirks, specifically injecting
 * the correct PIN reference which the token's AODF omits.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "internal.h"
#include "pkcs15.h"

static int
starsign_parse_df(struct sc_pkcs15_card *p15card, struct sc_pkcs15_df *df)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_object *pin_objs[32];
	int rv, count, i;

	LOG_FUNC_CALLED(ctx);

	if (!df)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	if (df->enumerated)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);

	rv = sc_pkcs15_parse_df(p15card, df);
	if (rv < 0)
		LOG_FUNC_RETURN(ctx, rv);

	if (df->type == SC_PKCS15_AODF) {
		/* The token's AODF entries omit the PIN reference and length
		 * restrictions the ISO7816 driver needs to build a correct
		 * VERIFY APDU. Patch them here instead of hardcoding the PIN
		 * reference in card-starsign.c's pin_cmd, so the standard
		 * iso7816 pin_cmd() implementation can be used unmodified. */
		rv = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_AUTH_PIN, pin_objs, sizeof(pin_objs) / sizeof(pin_objs[0]));
		if (rv >= 0) {
			count = rv;
			for (i = 0; i < count; i++) {
				struct sc_pkcs15_auth_info *pin_info = (struct sc_pkcs15_auth_info *)pin_objs[i]->data;
				pin_info->attrs.pin.reference = 0x02;
				pin_info->attrs.pin.max_length = 15;
				pin_info->attrs.pin.pad_char = '\0';
				pin_info->attrs.pin.flags |= SC_PKCS15_PIN_FLAG_INITIALIZED;
			}
		}
	} else if (df->type == SC_PKCS15_PRKDF) {
		rv = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_PRKEY_RSA, pin_objs, sizeof(pin_objs) / sizeof(pin_objs[0]));
		if (rv >= 0) {
			count = rv;
			for (i = 0; i < count; i++) {
				struct sc_pkcs15_prkey_info *prkey_info = (struct sc_pkcs15_prkey_info *)pin_objs[i]->data;
				/* Force key reference to 0x01 if it's 0x00 or missing */
				if (prkey_info->key_reference == 0x00) {
					sc_log(ctx, "Patching PRKEY reference to 0x01");
					prkey_info->key_reference = 0x01;
				}
				/* Force modulus length if 0 */
				if (prkey_info->modulus_length == 0) {
					sc_log(ctx, "Patching PRKEY modulus length to 2048");
					prkey_info->modulus_length = 2048;
				}
			}
		}
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

static int
sc_pkcs15emu_starsign_init(struct sc_pkcs15_card *p15card, struct sc_aid *aid)
{
	int rv;

	LOG_FUNC_CALLED(p15card->card->ctx);

	/* Set the hook BEFORE parsing so it runs when parsing the AODF. */
	p15card->ops.parse_df = starsign_parse_df;

	rv = sc_pkcs15_bind_internal(p15card, aid);
	LOG_FUNC_RETURN(p15card->card->ctx, rv);
}

int
sc_pkcs15emu_starsign_init_ex(sc_pkcs15_card_t *p15card, struct sc_aid *aid)
{
	if (p15card->card->type == SC_CARD_TYPE_STARSIGN)
		return sc_pkcs15emu_starsign_init(p15card, aid);
	return SC_ERROR_WRONG_CARD;
}
