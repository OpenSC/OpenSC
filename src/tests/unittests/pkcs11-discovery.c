/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Exercise the real public-object discovery path with synthetic PKCS#15
 * enumeration. No module initialization, reader or card access is performed. */
#include "torture.h"

#define sc_lock		      mock_sc_lock
#define sc_unlock	      mock_sc_unlock
#define sc_pkcs15_get_objects mock_sc_pkcs15_get_objects
#include "pkcs11/framework-pkcs15.c"
#undef sc_pkcs15_get_objects
#undef sc_unlock
#undef sc_lock

struct discovery_fixture {
	sc_card_t card;
	sc_pkcs15_card_t p15;
	struct pkcs15_fw_data fw;
	int lock_result, discovery_result, unlock_result;
	unsigned int locks, discoveries, unlocks;
	int discovery_failed;
};

static struct discovery_fixture *active;

int
mock_sc_lock(sc_card_t *card)
{
	assert_ptr_equal(card, &active->card);
	assert_true(card->caps & SC_CARD_CAP_BATCH_PUBLIC_OBJECTS);
	assert_int_equal(active->locks, 0);
	assert_int_equal(active->discoveries, 0);
	assert_int_equal(active->unlocks, 0);
	active->locks++;
	if (active->lock_result >= 0)
		card->lock_count++;
	return active->lock_result;
}

int
mock_sc_unlock(sc_card_t *card)
{
	assert_ptr_equal(card, &active->card);
	assert_int_equal(active->locks, 1);
	assert_true(active->discoveries > 0);
	assert_int_equal(active->unlocks, 0);
	assert_int_equal(card->lock_count, 1);
	active->unlocks++;
	card->lock_count--;
	return active->unlock_result;
}

int
mock_sc_pkcs15_get_objects(sc_pkcs15_card_t *p15, unsigned int type,
		sc_pkcs15_object_t **objects, size_t count)
{
	assert_ptr_equal(p15, &active->p15);
	assert_non_null(objects);
	assert_true(count > 0);
	assert_int_equal(active->unlocks, 0);
	assert_int_equal(p15->card->lock_count,
			!!(p15->card->caps & SC_CARD_CAP_BATCH_PUBLIC_OBJECTS));
	assert_false(active->discovery_failed);
	active->discoveries++;
	/* Fail after some enumeration has succeeded, not just at entry. */
	if (type == SC_PKCS15_TYPE_CERT_X509 && active->discovery_result < 0) {
		assert_true(active->discoveries > 1);
		active->discovery_failed = 1;
		return active->discovery_result;
	}
	return 0;
}

static void
check_discovery(int batch, int lock_result, int discovery_result,
		int unlock_result, int expected)
{
	struct discovery_fixture f = {0};

	f.card.caps = batch ? SC_CARD_CAP_BATCH_PUBLIC_OBJECTS : 0;
	f.p15.card = &f.card;
	f.fw.p15_card = &f.p15;
	f.lock_result = lock_result;
	f.discovery_result = discovery_result;
	f.unlock_result = unlock_result;
	active = &f;
	assert_int_equal(_pkcs15_create_typed_objects_batched(&f.fw), expected);
	assert_int_equal(f.locks, batch);
	if (batch && lock_result < 0) {
		assert_int_equal(f.discoveries, 0);
		assert_int_equal(f.unlocks, 0);
	} else {
		assert_true(f.discoveries > 0);
		assert_int_equal(f.discovery_failed, discovery_result < 0);
		assert_int_equal(f.unlocks, batch);
	}
	assert_int_equal(f.card.lock_count, 0);
	active = NULL;
}

static void
unbatched(void **state)
{
	/* Neither lock result may affect cards that did not opt in. */
	check_discovery(0, SC_ERROR_READER, SC_SUCCESS, SC_ERROR_CARD_RESET,
			SC_SUCCESS);
	check_discovery(0, SC_ERROR_READER, SC_ERROR_INVALID_DATA,
			SC_ERROR_CARD_RESET, SC_ERROR_INVALID_DATA);
}

static void
batched_success(void **state)
{
	check_discovery(1, SC_SUCCESS, SC_SUCCESS, SC_SUCCESS, SC_SUCCESS);
}

static void
lock_failure(void **state)
{
	check_discovery(1, SC_ERROR_READER, SC_SUCCESS, SC_SUCCESS,
			SC_ERROR_READER);
}

static void
discovery_failure(void **state)
{
	check_discovery(1, SC_SUCCESS, SC_ERROR_INVALID_DATA, SC_SUCCESS,
			SC_ERROR_INVALID_DATA);
}

static void
unlock_failure(void **state)
{
	check_discovery(1, SC_SUCCESS, SC_SUCCESS, SC_ERROR_CARD_RESET,
			SC_ERROR_CARD_RESET);
}

static void
preserve_discovery_failure(void **state)
{
	check_discovery(1, SC_SUCCESS, SC_ERROR_INVALID_DATA, SC_ERROR_CARD_RESET,
			SC_ERROR_INVALID_DATA);
}

int
main(void)
{
	const struct CMUnitTest tests[] = {
			cmocka_unit_test(unbatched),
			cmocka_unit_test(batched_success),
			cmocka_unit_test(lock_failure),
			cmocka_unit_test(discovery_failure),
			cmocka_unit_test(unlock_failure),
			cmocka_unit_test(preserve_discovery_failure),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
