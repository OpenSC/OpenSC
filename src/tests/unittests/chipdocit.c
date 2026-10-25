/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Profile regression tests with public EF stand-ins; no reader or PIN operations. */
#include "libopensc/internal.h"
#include "libopensc/pkcs15.h"
#include "torture.h"

struct fixture {
	sc_context_t ctx;
	sc_card_t card;
	sc_pkcs15_card_t *p15;
	unsigned int selected;
	unsigned int reads;
	unsigned int transmits;
};

/* Distinct ASN.1 payloads test EF/ID preservation, not X.509 parsing. */
static const u8 public_ef[2][5] = {
		{0x30, 0x03, 0x02, 0x01, 0x01},
		{0x30, 0x03, 0x02, 0x01, 0x02}
};

/* The internal token-info helper is not exported by the shared library. */
static void
token_string(char **out, const char *value)
{
	free(*out);
	*out = strdup(value);
	assert_non_null(*out);
}

static int
public_transmit(sc_card_t *card, sc_apdu_t *apdu)
{
	struct fixture *f = card->drv_data;
	static const u8 aid[] = {0xe8, 0x28, 0xbd, 0x08, 0x0f, 0x01, 0x4e, 0x58, 0x50, 0x30};

	f->transmits++;
	if (apdu->ins == 0xca) {
		assert_int_equal(apdu->p1, 0x01);
		assert_int_equal(apdu->p2, 0x14);
		return SC_ERROR_NOT_SUPPORTED;
	}
	assert_int_equal(apdu->ins, 0xa4);
	if (apdu->p1 == 0x04) {
		assert_int_equal(apdu->datalen, sizeof aid);
		assert_memory_equal(apdu->data, aid, sizeof aid);
	} else {
		assert_int_equal(apdu->p1, 0x00);
		assert_int_equal(apdu->datalen, 2);
		assert_int_equal(apdu->data[0], 0);
		assert_in_range(apdu->data[1], 1, 2);
		f->selected = apdu->data[1];
	}
	apdu->sw1 = 0x90;
	apdu->sw2 = 0;
	apdu->resplen = 0;
	return SC_SUCCESS;
}

static int
public_read(sc_card_t *card, unsigned int offset, u8 *out, size_t count, unsigned long flags)
{
	struct fixture *f = card->drv_data;

	(void)flags;
	assert_int_equal(offset, 0);
	assert_in_range(f->selected, 1, 2);
	assert_true(count >= sizeof public_ef[0]);
	f->reads++;
	memcpy(out, public_ef[f->selected - 1], sizeof public_ef[0]);
	return sizeof public_ef[0];
}

#define sc_transmit_apdu	       public_transmit
#define sc_read_binary		       public_read
#define sc_pkcs15emu_chipdocit_init_ex test_chipdocit_init
#define set_string		       token_string
#include "libopensc/pkcs15-chipdocit.c"
#undef set_string
#undef sc_transmit_apdu
#undef sc_read_binary
#undef sc_pkcs15emu_chipdocit_init_ex

static int
setup(void **state)
{
	struct fixture *f = calloc(1, sizeof(*f));

	assert_non_null(f);
	f->card.ctx = &f->ctx;
	f->card.ops = sc_get_iso7816_driver()->ops;
	f->card.drv_data = f;
	f->card.name = "Synthetic ChipDoc";
	f->card.type = SC_CARD_TYPE_CHIPDOC_IT;
	f->p15 = sc_pkcs15_card_new();
	assert_non_null(f->p15);
	f->p15->card = &f->card;
	*state = f;
	return 0;
}

static int
teardown(void **state)
{
	struct fixture *f = *state;

	sc_pkcs15_card_free(f->p15);
	free(f);
	return 0;
}

static sc_pkcs15_object_t *
object_by_id(struct fixture *f, unsigned int type, u8 id)
{
	sc_pkcs15_id_t wanted = {0};
	sc_pkcs15_object_t *objects[3];
	sc_pkcs15_object_t *found = NULL;
	int i;

	wanted.len = 1;
	wanted.value[0] = id;
	assert_int_equal(sc_pkcs15_get_objects(f->p15, type, objects, 3), 2);
	for (i = 0; i < 2; i++) {
		sc_pkcs15_id_t *object_id = type == SC_PKCS15_TYPE_PRKEY_RSA
							    ? &((sc_pkcs15_prkey_info_t *)objects[i]->data)->id
							    : &((sc_pkcs15_cert_info_t *)objects[i]->data)->id;
		if (sc_pkcs15_compare_id(object_id, &wanted)) {
			assert_null(found);
			found = objects[i];
		}
	}
	assert_non_null(found);
	return found;
}

static void
torture_certificate_key_mapping(void **state)
{
	struct fixture *f = *state;
	unsigned int i;

	assert_int_equal(test_chipdocit_init(f->p15, NULL), SC_SUCCESS);
	assert_int_equal(f->transmits, 5);
	assert_int_equal(f->reads, 2);
	for (i = 0; i < 2; i++) {
		sc_pkcs15_object_t *cert = object_by_id(f, SC_PKCS15_TYPE_CERT_X509, i + 1);
		sc_pkcs15_object_t *key = object_by_id(f, SC_PKCS15_TYPE_PRKEY_RSA, i + 1);
		sc_pkcs15_cert_info_t *ci = cert->data;
		sc_pkcs15_prkey_info_t *ki = key->data;

		assert_int_equal(ci->value.len, sizeof public_ef[i]);
		assert_memory_equal(ci->value.value, public_ef[i], sizeof public_ef[i]);
		assert_int_equal(ki->key_reference, 0x10 + i);
		assert_int_equal(ki->modulus_length, 2048);
		assert_true(sc_pkcs15_compare_id(&ci->id, &ki->id));
		assert_string_equal(cert->label, i ? "DS3" : "CNS");
		assert_string_equal(key->label, cert->label);
		assert_int_equal(key->auth_id.len, 1);
		assert_int_equal(key->auth_id.value[0], 1);
	}
}

static void
torture_key_usage_and_consent(void **state)
{
	struct fixture *f = *state;
	sc_pkcs15_object_t *signature, *authentication;
	sc_pkcs15_prkey_info_t *signature_info, *authentication_info;

	assert_int_equal(test_chipdocit_init(f->p15, NULL), SC_SUCCESS);
	signature = object_by_id(f, SC_PKCS15_TYPE_PRKEY_RSA, 1);
	authentication = object_by_id(f, SC_PKCS15_TYPE_PRKEY_RSA, 2);
	signature_info = signature->data;
	authentication_info = authentication->data;
	assert_int_equal(signature_info->usage,
			SC_PKCS15_PRKEY_USAGE_SIGN | SC_PKCS15_PRKEY_USAGE_NONREPUDIATION);
	assert_int_equal(authentication_info->usage, SC_PKCS15_PRKEY_USAGE_SIGN);
	assert_false(signature_info->usage & SC_PKCS15_PRKEY_USAGE_DECRYPT);
	assert_false(authentication_info->usage & SC_PKCS15_PRKEY_USAGE_DECRYPT);
	/* The unchanged PKCS#11 getter maps user_consent >= 1 to ALWAYS_AUTHENTICATE. */
	assert_int_equal(signature->user_consent, 1);
	assert_int_equal(authentication->user_consent, 0);
}

static void
torture_other_card_rejected(void **state)
{
	struct fixture *f = *state;

	f->card.type = SC_CARD_TYPE_UNKNOWN;
	assert_int_equal(test_chipdocit_init(f->p15, NULL), SC_ERROR_WRONG_CARD);
	assert_int_equal(f->transmits, 0);
	assert_int_equal(f->reads, 0);
	assert_null(f->p15->obj_list);
}

int
main(void)
{
	const struct CMUnitTest tests[] = {
			cmocka_unit_test_setup_teardown(torture_certificate_key_mapping, setup, teardown),
			cmocka_unit_test_setup_teardown(torture_key_usage_and_consent, setup, teardown),
			cmocka_unit_test_setup_teardown(torture_other_card_rejected, setup, teardown),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
