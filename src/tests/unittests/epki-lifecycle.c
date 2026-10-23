/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Synthetic reader only. Exercise real PKCS#15 PIN caching, use_key(),
 * sc_lock()/sc_unlock() and driver dispatch; never connect to hardware. */
#include "libopensc/internal.h"
#include "libopensc/pkcs15.h"
#include "torture.h"

struct fixture {
	sc_context_t ctx;
	sc_card_t card;
	sc_reader_t reader;
	struct sc_reader_operations reader_ops;
	sc_pkcs15_card_t p15;
	sc_pkcs15_tokeninfo_t tokeninfo;
	sc_pkcs15_object_t pin, key;
	sc_pkcs15_auth_info_t pin_info;
	sc_pkcs15_prkey_info_t key_info;
	unsigned locks, unlocks, verifies, signatures, versions, selections;
	int reset_next_lock, authenticated, mse, reject_pin, fail_signature;
};

static struct fixture *active;
static const u8 synthetic_pin[] = {'1', '2', '3', '4'};

static int
reader_lock(sc_reader_t *reader)
{
	assert_ptr_equal(reader, &active->reader);
	if (active->reset_next_lock) {
		active->reset_next_lock = 0;
		active->authenticated = active->mse = 0;
		return SC_ERROR_CARD_RESET;
	}
	active->locks++;
	return SC_SUCCESS;
}

static int
reader_unlock(sc_reader_t *reader)
{
	assert_ptr_equal(reader, &active->reader);
	active->unlocks++;
	return SC_SUCCESS;
}

static int
select_aid(sc_card_t *card, const u8 *aid, size_t len,
		u8 *response, size_t *response_len)
{
	active->authenticated = active->mse = 0;
	active->selections++;
	return SC_SUCCESS;
}

static int
select_file(sc_card_t *card, const sc_path_t *path, sc_file_t **out)
{
	assert_true(card->lock_count > 0);
	assert_int_equal(path->type, SC_PATH_TYPE_DF_NAME);
	active->authenticated = active->mse = 0;
	active->selections++;
	if (out) {
		*out = sc_file_new();
		assert_non_null(*out);
		(*out)->type = SC_FILE_TYPE_DF;
		(*out)->path = *path;
	}
	return SC_SUCCESS;
}

static struct sc_card_driver *
iso_driver(void)
{
	static struct sc_card_driver driver;
	static struct sc_card_operations ops;
	driver = *sc_get_iso7816_driver();
	ops = *driver.ops;
	ops.select_file = select_file;
	driver.ops = &ops;
	return &driver;
}

static int
transmit(sc_card_t *card, sc_apdu_t *apdu)
{
	assert_true(card->lock_count > 0);
	apdu->sw1 = 0x90;
	apdu->sw2 = 0;
	switch (apdu->ins) {
	case 0xca:
		active->versions++;
		assert_true(apdu->resplen >= 2);
		apdu->resp[0] = 0x02;
		apdu->resp[1] = 0x82;
		apdu->resplen = 2;
		break;
	case 0x20:
		active->verifies++;
		assert_int_equal(apdu->datalen, 8);
		assert_memory_equal(apdu->data, synthetic_pin, sizeof(synthetic_pin));
		assert_true(apdu->flags & SC_APDU_FLAGS_NO_RETRY_WL);
		assert_true(apdu->flags & SC_APDU_FLAGS_NO_GET_RESP);
		active->authenticated = !active->reject_pin;
		if (active->reject_pin) {
			apdu->sw1 = 0x63;
			apdu->sw2 = 0xc2;
		}
		break;
	case 0x22:
		assert_true(active->authenticated);
		active->mse = 1;
		break;
	case 0x2a:
		assert_true(active->authenticated);
		assert_true(active->mse);
		active->mse = 0;
		active->signatures++;
		if (active->fail_signature) {
			active->fail_signature = 0;
			return SC_ERROR_TRANSMIT_FAILED;
		}
		assert_true(apdu->resplen >= 256);
		memset(apdu->resp, 0x5a, 256);
		apdu->resplen = 256;
		break;
	default:
		fail_msg("Unexpected command in synthetic lifecycle reader");
	}
	return SC_SUCCESS;
}

#define sc_transmit_apdu	    transmit
#define sc_get_iso7816_driver	    iso_driver
#define iso7816_select_aid	    select_aid
#define sc_get_epki_research_driver sc_get_lifecycle_epki_driver
#include "libopensc/card-epki-research.c"
#undef sc_get_epki_research_driver
#undef iso7816_select_aid
#undef sc_get_iso7816_driver
#undef sc_transmit_apdu

static int
setup(void **state)
{
	struct fixture *f = calloc(1, sizeof(*f));
	assert_non_null(f);
	active = f;
	*state = f;
	f->card.ctx = &f->ctx;
	f->card.reader = &f->reader;
	f->reader.ctx = &f->ctx;
	f->reader.ops = &f->reader_ops;
	f->reader_ops.lock = reader_lock;
	f->reader_ops.unlock = reader_unlock;
	f->card.ops = sc_get_lifecycle_epki_driver()->ops;
	f->card.atr.len = sizeof(epki_atr);
	memcpy(f->card.atr.value, epki_atr, sizeof(epki_atr));
	f->ctx.conf = scconf_new(NULL);
	assert_non_null(f->ctx.conf);
	assert_int_equal(scconf_parse_string(f->ctx.conf,
					 "card_driver epki-research { enable_profile = true; "
					 "enable_local_signing = true; }"),
			1);
	f->ctx.conf_blocks[0] = f->ctx.conf->root;
	assert_int_equal(f->card.lock_count, 0);
	assert_int_equal(sc_lock(&f->card), SC_SUCCESS);
	assert_int_equal(epki_init(&f->card), SC_SUCCESS);
	assert_int_equal(sc_unlock(&f->card), SC_SUCCESS);
	f->locks = f->unlocks = 0;
	f->p15.card = &f->card;
	f->p15.tokeninfo = &f->tokeninfo;
	f->p15.obj_list = &f->pin;
	/* Normal OpenSC defaults; no lock spanning separate operations. */
	f->p15.opts.use_pin_cache = 1;
	f->p15.opts.pin_cache_counter = 10;
	f->pin.type = SC_PKCS15_TYPE_AUTH_PIN;
	f->pin.data = &f->pin_info;
	f->pin.next = &f->key;
	f->pin_info.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
	f->pin_info.auth_method = SC_AC_CHV;
	f->pin_info.auth_id.len = 1;
	f->pin_info.auth_id.value[0] = 1;
	f->pin_info.attrs.pin.type = SC_PKCS15_PIN_TYPE_ASCII_NUMERIC;
	f->pin_info.attrs.pin.reference = 1;
	f->pin_info.attrs.pin.min_length = 4;
	f->pin_info.attrs.pin.max_length = 8;
	f->pin_info.attrs.pin.stored_length = 8;
	f->pin_info.attrs.pin.pad_char = 0xff;
	sc_format_path("3F005015", &f->pin_info.path);
	f->key.type = SC_PKCS15_TYPE_PRKEY_RSA;
	f->key.data = &f->key_info;
	f->key.auth_id = f->pin_info.auth_id;
	f->key.prev = &f->pin;
	f->key_info.native = 1;
	f->key_info.usage = SC_PKCS15_PRKEY_USAGE_SIGN;
	f->key_info.modulus_length = 2048;
	f->key_info.key_reference = 1;
	sc_format_path("3F005015", &f->key_info.path);
	return 0;
}

static int
teardown(void **state)
{
	struct fixture *f = *state;
	assert_int_equal(f->card.lock_count, 0);
	assert_int_equal(f->locks, f->unlocks);
	sc_pkcs15_pincache_clear(&f->p15);
	epki_finish(&f->card);
	free(f->card.algorithms);
	scconf_free(f->ctx.conf);
	free(f);
	active = NULL;
	return 0;
}

static int
login(struct fixture *f)
{
	int r = sc_pkcs15_verify_pin(&f->p15, &f->pin,
			synthetic_pin, sizeof(synthetic_pin));
	assert_int_equal(f->card.lock_count, 0);
	return r;
}

static int
sign_message(struct fixture *f)
{
	static const u8 message[] = {1, 2, 3, 4};
	u8 signature[256];
	int r = sc_pkcs15_compute_signature(&f->p15, &f->key,
			SC_ALGORITHM_RSA_PAD_PKCS1_TYPE_01 | SC_ALGORITHM_RSA_HASH_NONE,
			message, sizeof(message), signature, sizeof(signature), NULL);
	assert_int_equal(f->card.lock_count, 0);
	return r;
}

static void
separate_transactions_and_software_logout(void **state)
{
	struct fixture *f = *state;
	assert_int_equal(login(f), SC_SUCCESS);
	assert_int_equal(f->verifies, 1);
	assert_int_equal(sign_message(f), 256);
	assert_int_equal(f->verifies, 2);
	assert_int_equal(f->locks, 2);
	/* The PKCS#11 framework's logout clears this standard PIN cache. */
	sc_pkcs15_pincache_clear(&f->p15);
	assert_int_equal(sign_message(f), SC_ERROR_SECURITY_STATUS_NOT_SATISFIED);
	assert_int_equal(f->verifies, 2);
	assert_int_equal(login(f), SC_SUCCESS);
	assert_int_equal(sign_message(f), 256);
	assert_int_equal(f->verifies, 4);
	assert_int_equal(f->signatures, 2);
}

static void
reset_rechecks_profile_and_revalidates_pin(void **state)
{
	struct fixture *f = *state;
	unsigned versions = f->versions;
	assert_int_equal(login(f), SC_SUCCESS);
	f->reset_next_lock = 1;
	assert_int_equal(sign_message(f), 256);
	assert_int_equal(f->versions, versions + 1);
	assert_int_equal(f->verifies, 2);
}

static void
wrong_cached_pin_is_used_once_and_discarded(void **state)
{
	struct fixture *f = *state;
	assert_int_equal(login(f), SC_SUCCESS);
	f->reject_pin = 1;
	assert_int_equal(sign_message(f), SC_ERROR_SECURITY_STATUS_NOT_SATISFIED);
	assert_int_equal(f->verifies, 2);
	assert_null(f->pin.content.value);
	assert_int_equal(sign_message(f), SC_ERROR_SECURITY_STATUS_NOT_SATISFIED);
	assert_int_equal(f->verifies, 2);
	f->reject_pin = 0;
	assert_int_equal(login(f), SC_SUCCESS);
	assert_int_equal(sign_message(f), 256);
	assert_int_equal(f->verifies, 4);
}

static void
signature_failure_does_not_poison_new_operation(void **state)
{
	struct fixture *f = *state;
	assert_int_equal(login(f), SC_SUCCESS);
	f->fail_signature = 1;
	assert_int_equal(sign_message(f), SC_ERROR_TRANSMIT_FAILED);
	assert_int_equal(f->signatures, 1);
	assert_int_equal(sign_message(f), 256);
	assert_int_equal(f->signatures, 2);
}

static void
direct_logout_clears_card_state_and_allows_relogin(void **state)
{
	struct fixture *f = *state;
	assert_int_equal(login(f), SC_SUCCESS);
	sc_pkcs15_pincache_clear(&f->p15);
	assert_int_equal(sc_logout(&f->card), SC_SUCCESS);
	assert_false(f->authenticated);
	assert_int_equal(sign_message(f), SC_ERROR_SECURITY_STATUS_NOT_SATISFIED);
	assert_int_equal(login(f), SC_SUCCESS);
	assert_int_equal(sign_message(f), 256);
}

static void
no_cached_pin_means_no_implicit_verification(void **state)
{
	struct fixture *f = *state;
	f->p15.opts.use_pin_cache = 0;
	assert_int_equal(login(f), SC_SUCCESS);
	assert_int_equal(sign_message(f), SC_ERROR_SECURITY_STATUS_NOT_SATISFIED);
	assert_int_equal(f->verifies, 1);
	assert_int_equal(f->signatures, 0);
}

int
main(void)
{
	const struct CMUnitTest tests[] = {
			cmocka_unit_test_setup_teardown(separate_transactions_and_software_logout, setup, teardown),
			cmocka_unit_test_setup_teardown(reset_rechecks_profile_and_revalidates_pin, setup, teardown),
			cmocka_unit_test_setup_teardown(wrong_cached_pin_is_used_once_and_discarded, setup, teardown),
			cmocka_unit_test_setup_teardown(signature_failure_does_not_poison_new_operation, setup, teardown),
			cmocka_unit_test_setup_teardown(direct_logout_clears_card_state_and_allows_relogin, setup, teardown),
			cmocka_unit_test_setup_teardown(no_cached_pin_means_no_implicit_verification, setup, teardown),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
