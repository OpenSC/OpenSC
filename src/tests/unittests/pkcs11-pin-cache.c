/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Exercise exported session/PIN calls and the atomic login cache with
 * synthetic framework callbacks. No reader or card driver is initialized. */
#include "pkcs11/sc-pkcs11.h"
#include "torture.h"

static CK_CHAR old_pin[] = {'o', 'l', 'd', '-', 'p', 'i', 'n'};
static CK_CHAR new_pin[] = {'n', 'e', 'w', 0, 'p', 'i', 'n', '!'};
static CK_CHAR next_pin[] = {'n', 'e', 'x', 't', '-', 'p', 'i', 'n'};

struct endpoint {
	struct sc_pkcs11_slot slot;
	struct sc_pkcs11_card card;
	struct sc_pkcs11_session *session;
	struct sc_pkcs11_framework_ops framework;
	CK_USER_TYPE role;
	CK_CHAR current_pin[sizeof(new_pin)];
	CK_ULONG current_len;
	CK_CHAR_PTR expected_old, expected_new;
	CK_ULONG old_len, new_len;
	CK_CHAR_PTR replayed_pin;
	CK_RV change_result, login_result;
	unsigned logins, rejected_logins, changes, logouts;
	int change_before_error, protected_pin, forbid_login;
};

struct fixture {
	sc_context_t ctx;
	struct endpoint target, other;
};

static CK_RV
login(struct sc_pkcs11_slot *slot, CK_USER_TYPE role,
		CK_CHAR_PTR pin, CK_ULONG len)
{
	struct endpoint *ep = slot->fw_data;
	assert_false(ep->forbid_login);
	assert_int_equal(role, ep->role);
	ep->replayed_pin = pin;
	ep->logins++;
	if (ep->login_result != CKR_OK) {
		ep->rejected_logins++;
		return ep->login_result;
	}
	if (ep->protected_pin) {
		if (!pin && !len)
			return CKR_OK;
	} else if (len == ep->current_len &&
			(!len || (pin && memcmp(pin, ep->current_pin, len) == 0))) {
		return CKR_OK;
	}
	ep->rejected_logins++;
	return CKR_PIN_INCORRECT;
}

static CK_RV
logout(struct sc_pkcs11_slot *slot)
{
	struct endpoint *ep = slot->fw_data;
	ep->logouts++;
	return CKR_OK;
}

static CK_RV
change_pin(struct sc_pkcs11_slot *slot, CK_CHAR_PTR old, CK_ULONG oldlen,
		CK_CHAR_PTR new_value, CK_ULONG newlen)
{
	struct endpoint *ep = slot->fw_data;
	assert_int_equal(oldlen, ep->old_len);
	if (oldlen)
		assert_memory_equal(old, ep->expected_old, oldlen);
	else
		assert_null(old);
	assert_int_equal(newlen, ep->new_len);
	if (newlen)
		assert_memory_equal(new_value, ep->expected_new, newlen);
	else
		assert_null(new_value);
	ep->changes++;
	if (ep->change_result == CKR_OK || ep->change_before_error) {
		ep->protected_pin = new_value == NULL;
		assert_true(newlen <= sizeof(ep->current_pin));
		if (newlen)
			memcpy(ep->current_pin, new_value, newlen);
		ep->current_len = newlen;
	}
	return ep->change_result;
}

static int
session_seeker(const void *element, const void *key)
{
	const struct sc_pkcs11_session *session = element;
	return session != NULL && key != NULL &&
	       session->handle == *(const CK_SESSION_HANDLE *)key;
}

static int
slot_seeker(const void *element, const void *key)
{
	const struct sc_pkcs11_slot *slot = element;
	return slot != NULL && key != NULL && slot->id == *(const CK_SLOT_ID *)key;
}

static struct sc_pkcs11_session *
open_session(struct endpoint *ep)
{
	CK_SESSION_HANDLE handle = CK_INVALID_HANDLE;
	struct sc_pkcs11_session *session = NULL;
	assert_int_equal(C_OpenSession(ep->slot.id, CKF_RW_SESSION | CKF_SERIAL_SESSION,
					 NULL, NULL, &handle),
			CKR_OK);
	assert_int_equal(get_session(handle, &session), CKR_OK);
	return session;
}

static void
init_endpoint(struct endpoint *ep, CK_SLOT_ID id)
{
	ep->slot.id = id;
	ep->slot.slot_info.flags = CKF_TOKEN_PRESENT;
	ep->slot.token_info.flags = CKF_USER_PIN_INITIALIZED;
	ep->slot.login_user = -1;
	ep->slot.p11card = &ep->card;
	ep->slot.fw_data = ep;
	ep->card.framework = &ep->framework;
	ep->framework.login = login;
	ep->framework.logout = logout;
	ep->framework.change_pin = change_pin;
	assert_int_equal(list_init(&ep->slot.logins), 0);
	assert_true(list_append(&virtual_slots, &ep->slot) >= 0);
	ep->session = open_session(ep);
}

static void
reset_endpoint(struct endpoint *ep)
{
	pop_all_login_states(&ep->slot);
	ep->slot.login_user = -1;
	ep->role = CKU_USER;
	memcpy(ep->current_pin, old_pin, sizeof(old_pin));
	ep->current_len = sizeof(old_pin);
	ep->expected_old = old_pin;
	ep->old_len = sizeof(old_pin);
	ep->expected_new = new_pin;
	ep->new_len = sizeof(new_pin);
	ep->change_result = CKR_OK;
	ep->login_result = CKR_OK;
	ep->logins = ep->rejected_logins = ep->changes = ep->logouts = 0;
	ep->change_before_error = ep->protected_pin = ep->forbid_login = 0;
	ep->replayed_pin = NULL;
}

static void
save_login(struct endpoint *ep, CK_USER_TYPE role)
{
	ep->role = role;
	ep->slot.login_user = (int)role;
	assert_int_equal(push_login_state(&ep->slot, role, old_pin, sizeof(old_pin)), CKR_OK);
}

static int
setup(void **state)
{
	struct fixture *f = calloc(1, sizeof(*f));
	assert_non_null(f);
	assert_null(context);
	context = &f->ctx;
	memset(&sc_pkcs11_conf, 0, sizeof(sc_pkcs11_conf));
	sc_pkcs11_conf.atomic = 1;
	assert_int_equal(list_init(&sessions), 0);
	assert_int_equal(list_attributes_seeker(&sessions, session_seeker), 0);
	assert_int_equal(list_init(&virtual_slots), 0);
	assert_int_equal(list_attributes_seeker(&virtual_slots, slot_seeker), 0);
	init_endpoint(&f->target, 1);
	init_endpoint(&f->other, 2);
	reset_endpoint(&f->target);
	reset_endpoint(&f->other);
	*state = f;
	return 0;
}

static int
teardown(void **state)
{
	struct fixture *f = *state;
	/* An atomic=false case must still release its synthetic fixture. */
	sc_pkcs11_conf.atomic = 1;
	assert_int_equal(C_CloseAllSessions(f->target.slot.id), CKR_OK);
	assert_int_equal(C_CloseAllSessions(f->other.slot.id), CKR_OK);
	pop_all_login_states(&f->target.slot);
	pop_all_login_states(&f->other.slot);
	list_destroy(&f->target.slot.logins);
	list_destroy(&f->other.slot.logins);
	assert_int_equal(list_size(&sessions), 0);
	list_destroy(&sessions);
	list_destroy(&virtual_slots);
	context = NULL;
	memset(&sc_pkcs11_conf, 0, sizeof(sc_pkcs11_conf));
	free(f);
	return 0;
}

static void
successful_change_replays_new_pin_for_the_logged_role(void **state)
{
	struct fixture *f = *state;
	struct endpoint *ep = &f->target;
	const CK_USER_TYPE roles[] = {CKU_USER, CKU_SO};
	size_t i;
	for (i = 0; i < sizeof(roles) / sizeof(roles[0]); i++) {
		reset_endpoint(ep);
		ep->role = roles[i];
		assert_int_equal(C_Login(ep->session->handle, roles[i], old_pin,
						 sizeof(old_pin)),
				CKR_OK);
		assert_int_equal(C_SetPIN(ep->session->handle, old_pin, sizeof(old_pin),
						 new_pin, sizeof(new_pin)),
				CKR_OK);
		assert_int_equal(ep->logins, 2); /* Explicit login, then cached replay. */
		assert_int_equal(ep->changes, 1);
		assert_int_equal(ep->logouts, 2);
		assert_int_equal(ep->slot.login_user, (int)roles[i]);
		assert_int_equal(list_size(&ep->slot.logins), 1);
		ep->expected_old = new_pin;
		ep->old_len = sizeof(new_pin);
		ep->expected_new = next_pin;
		ep->new_len = sizeof(next_pin);
		/* A second exported PIN operation must authenticate with the NEW PIN. */
		assert_int_equal(C_SetPIN(ep->session->handle, new_pin, sizeof(new_pin),
						 next_pin, sizeof(next_pin)),
				CKR_OK);
		assert_int_equal(ep->logins, 3);
		assert_int_equal(ep->changes, 2);
		assert_int_equal(ep->logouts, 3);
	}
}

static void
change_is_slot_local_and_public_session_stays_public(void **state)
{
	struct fixture *f = *state;
	struct endpoint *ep = &f->target, *other = &f->other;
	int logged;
	for (logged = 0; logged <= 1; logged++) {
		reset_endpoint(ep);
		reset_endpoint(other);
		save_login(other, CKU_SO);
		if (logged)
			save_login(ep, CKU_USER);
		assert_int_equal(C_SetPIN(ep->session->handle, old_pin, sizeof(old_pin),
						 new_pin, sizeof(new_pin)),
				CKR_OK);
		assert_int_equal(ep->slot.login_user, logged ? (int)CKU_USER : -1);
		assert_int_equal(list_size(&ep->slot.logins), logged);
		assert_int_equal(other->changes, 0);
		assert_int_equal(other->logouts, 0);
		assert_int_equal(restore_login_state(&other->slot), CKR_OK);
		assert_int_equal(other->logins, 1); /* SO still receives its original PIN. */
	}
}

static void
failed_or_uncertain_change_cannot_replay_old_pin(void **state)
{
	struct fixture *f = *state;
	struct endpoint *ep = &f->target, *other = &f->other;
	const CK_RV errors[] = {CKR_PIN_INCORRECT, CKR_DEVICE_ERROR};
	size_t i;
	for (i = 0; i < sizeof(errors) / sizeof(errors[0]); i++) {
		reset_endpoint(ep);
		reset_endpoint(other);
		save_login(ep, CKU_USER);
		save_login(other, CKU_SO);
		ep->change_result = errors[i];
		ep->change_before_error = i == 1; /* Simulate a lost successful reply. */
		assert_int_equal(C_SetPIN(ep->session->handle, old_pin, sizeof(old_pin),
						 new_pin, sizeof(new_pin)),
				errors[i]);
		assert_int_equal(ep->changes, 1);
		assert_int_equal(ep->logins, 1);
		assert_int_equal(ep->slot.login_user, -1);
		assert_int_equal(list_size(&ep->slot.logins), 0);
		ep->forbid_login = 1;
		assert_int_equal(restore_login_state(&ep->slot), CKR_OK);
		assert_int_equal(ep->logins, 1);
		assert_int_equal(restore_login_state(&other->slot), CKR_OK);
		assert_int_equal(other->logins, 1);
		assert_int_equal(other->logouts, 0);
	}
}

static void
failed_restore_clears_only_affected_slot_and_allows_fresh_login(void **state)
{
	struct fixture *f = *state;
	struct endpoint *ep = &f->target, *other = &f->other;
	const CK_RV errors[] = {CKR_PIN_INCORRECT, CKR_DEVICE_ERROR};
	const CK_USER_TYPE roles[] = {CKU_USER, CKU_SO};
	size_t i, j;
	for (i = 0; i < sizeof(roles) / sizeof(roles[0]); i++) {
		for (j = 0; j < sizeof(errors) / sizeof(errors[0]); j++) {
			reset_endpoint(ep);
			reset_endpoint(other);
			save_login(ep, roles[i]);
			save_login(other, CKU_SO);
			ep->login_result = errors[j];
			assert_int_equal(C_SetPIN(ep->session->handle, old_pin, sizeof(old_pin),
							 new_pin, sizeof(new_pin)),
					errors[j]);
			assert_int_equal(ep->logins, 1);
			assert_int_equal(ep->changes, 0);
			assert_int_equal(ep->slot.login_user, -1);
			assert_int_equal(list_size(&ep->slot.logins), 0);
			ep->forbid_login = 1;
			assert_int_equal(restore_login_state(&ep->slot), CKR_OK);
			assert_int_equal(restore_login_state(&ep->slot), CKR_OK);
			assert_int_equal(ep->logins, 1);
			assert_int_equal(restore_login_state(&other->slot), CKR_OK);
			assert_int_equal(other->logins, 1);
			ep->forbid_login = 0;
			ep->login_result = CKR_OK;
			assert_int_equal(C_Login(ep->session->handle, roles[i], old_pin,
							 sizeof(old_pin)),
					CKR_OK);
			assert_int_equal(ep->logins, 2);
			assert_int_equal(ep->slot.login_user, (int)roles[i]);
		}
	}
}

static void
invalid_arguments_and_read_only_session_leave_cache_untouched(void **state)
{
	struct fixture *f = *state;
	struct endpoint *ep = &f->target;
	save_login(ep, CKU_USER);
	assert_int_equal(C_SetPIN(ep->session->handle, NULL, 1,
					 new_pin, sizeof(new_pin)),
			CKR_ARGUMENTS_BAD);
	assert_int_equal(C_SetPIN(ep->session->handle, old_pin, sizeof(old_pin),
					 NULL, 1),
			CKR_ARGUMENTS_BAD);
	ep->session->flags = CKF_SERIAL_SESSION;
	assert_int_equal(C_SetPIN(ep->session->handle, old_pin, sizeof(old_pin),
					 new_pin, sizeof(new_pin)),
			CKR_SESSION_READ_ONLY);
	assert_int_equal(ep->changes, 0);
	assert_int_equal(ep->logins, 0);
	assert_int_equal(ep->logouts, 0);
	assert_int_equal(ep->slot.login_user, CKU_USER);
	assert_int_equal(list_size(&ep->slot.logins), 1);
	assert_int_equal(restore_login_state(&ep->slot), CKR_OK);
	assert_int_equal(ep->logins, 1); /* The original credential remains valid. */
}

static void
aliased_inputs_and_protected_path_keep_valid_credentials(void **state)
{
	struct fixture *f = *state;
	struct endpoint *ep = &f->target;
	save_login(ep, CKU_USER);
	assert_int_equal(restore_login_state(&ep->slot), CKR_OK);
	ep->expected_new = old_pin;
	ep->new_len = sizeof(old_pin);
	/* Both caller inputs borrow the existing replay allocation. */
	assert_int_equal(C_SetPIN(ep->session->handle, ep->replayed_pin, sizeof(old_pin),
					 ep->replayed_pin, sizeof(old_pin)),
			CKR_OK);
	assert_int_equal(restore_login_state(&ep->slot), CKR_OK);
	assert_int_equal(ep->changes, 1);

	reset_endpoint(ep);
	save_login(ep, CKU_USER);
	ep->slot.token_info.flags |= CKF_PROTECTED_AUTHENTICATION_PATH;
	ep->expected_old = NULL;
	ep->old_len = 0;
	ep->expected_new = NULL;
	ep->new_len = 0;
	assert_int_equal(C_SetPIN(ep->session->handle, NULL, 0, NULL, 0), CKR_OK);
	assert_int_equal(ep->slot.login_user, CKU_USER);
	assert_int_equal(restore_login_state(&ep->slot), CKR_OK);
	assert_null(ep->replayed_pin);
	assert_int_equal(ep->changes, 1);
}

static void
non_atomic_change_keeps_existing_dispatch_and_session_behavior(void **state)
{
	struct fixture *f = *state;
	struct endpoint *ep = &f->target;
	const CK_RV results[] = {CKR_OK, CKR_DEVICE_ERROR};
	size_t i;
	for (i = 0; i < sizeof(results) / sizeof(results[0]); i++) {
		sc_pkcs11_conf.atomic = 1;
		reset_endpoint(ep);
		sc_pkcs11_conf.atomic = 0;
		ep->slot.login_user = CKU_USER;
		ep->change_result = results[i];
		assert_int_equal(C_SetPIN(ep->session->handle, old_pin, sizeof(old_pin),
						 new_pin, sizeof(new_pin)),
				results[i]);
		assert_int_equal(ep->changes, 1);
		assert_int_equal(ep->logins, 0);
		assert_int_equal(ep->logouts, 0);
		assert_int_equal(ep->slot.login_user, CKU_USER);
		assert_int_equal(list_size(&ep->slot.logins), 0);
		assert_int_equal(restore_login_state(&ep->slot), CKR_OK);
		assert_int_equal(ep->logins, 0);
	}
}

static void
concurrent_sessions_share_replacement_until_last_close(void **state)
{
	struct fixture *f = *state;
	struct endpoint *ep = &f->target;
	struct sc_pkcs11_session *second = open_session(ep);
	CK_SESSION_HANDLE second_handle = second->handle;
	assert_int_equal(C_Login(ep->session->handle, CKU_USER, old_pin,
					 sizeof(old_pin)),
			CKR_OK);
	assert_int_equal(C_Login(second_handle, CKU_USER, old_pin,
					 sizeof(old_pin)),
			CKR_USER_ALREADY_LOGGED_IN);
	assert_int_equal(ep->logins, 1);
	assert_int_equal(C_SetPIN(ep->session->handle, old_pin, sizeof(old_pin),
					 new_pin, sizeof(new_pin)),
			CKR_OK);
	assert_int_equal(C_CloseSession(ep->session->handle), CKR_OK);
	ep->session = NULL;
	assert_int_equal(ep->slot.nsessions, 1);
	assert_int_equal(ep->slot.login_user, CKU_USER);
	assert_int_equal(list_size(&ep->slot.logins), 1);
	ep->expected_old = new_pin;
	ep->old_len = sizeof(new_pin);
	ep->expected_new = next_pin;
	ep->new_len = sizeof(next_pin);
	assert_int_equal(C_SetPIN(second_handle, new_pin, sizeof(new_pin),
					 next_pin, sizeof(next_pin)),
			CKR_OK);
	assert_int_equal(ep->logins, 3);
	assert_int_equal(ep->changes, 2);
	assert_int_equal(C_CloseSession(second_handle), CKR_OK);
	assert_int_equal(ep->slot.nsessions, 0);
	assert_int_equal(ep->slot.login_user, -1);
	assert_int_equal(list_size(&ep->slot.logins), 0);
}

static void
last_close_and_logout_prevent_cached_replay(void **state)
{
	struct fixture *f = *state;
	struct endpoint *ep = &f->target;
	int close_last;
	for (close_last = 0; close_last <= 1; close_last++) {
		reset_endpoint(ep);
		assert_int_equal(C_Login(ep->session->handle, CKU_USER, old_pin,
						 sizeof(old_pin)),
				CKR_OK);
		assert_int_equal(C_SetPIN(ep->session->handle, old_pin, sizeof(old_pin),
						 new_pin, sizeof(new_pin)),
				CKR_OK);
		if (close_last) {
			assert_int_equal(C_CloseSession(ep->session->handle), CKR_OK);
			assert_int_equal(ep->slot.nsessions, 0);
			ep->session = open_session(ep);
		} else {
			assert_int_equal(C_Logout(ep->session->handle), CKR_OK);
		}
		assert_int_equal(ep->slot.login_user, -1);
		assert_int_equal(list_size(&ep->slot.logins), 0);
		ep->forbid_login = 1;
		ep->expected_old = new_pin;
		ep->old_len = sizeof(new_pin);
		ep->expected_new = next_pin;
		ep->new_len = sizeof(next_pin);
		/* Public-session PIN change must not resurrect a cached login. */
		assert_int_equal(C_SetPIN(ep->session->handle, new_pin, sizeof(new_pin),
						 next_pin, sizeof(next_pin)),
				CKR_OK);
		assert_int_equal(ep->logins, 2);
		assert_int_equal(ep->changes, 2);
		assert_int_equal(ep->slot.login_user, -1);
		assert_int_equal(list_size(&ep->slot.logins), 0);
	}
}

int
main(void)
{
	const struct CMUnitTest tests[] = {
			cmocka_unit_test_setup_teardown(successful_change_replays_new_pin_for_the_logged_role, setup, teardown),
			cmocka_unit_test_setup_teardown(change_is_slot_local_and_public_session_stays_public, setup, teardown),
			cmocka_unit_test_setup_teardown(failed_or_uncertain_change_cannot_replay_old_pin, setup, teardown),
			cmocka_unit_test_setup_teardown(failed_restore_clears_only_affected_slot_and_allows_fresh_login, setup, teardown),
			cmocka_unit_test_setup_teardown(invalid_arguments_and_read_only_session_leave_cache_untouched, setup, teardown),
			cmocka_unit_test_setup_teardown(aliased_inputs_and_protected_path_keep_valid_credentials, setup, teardown),
			cmocka_unit_test_setup_teardown(non_atomic_change_keeps_existing_dispatch_and_session_behavior, setup, teardown),
			cmocka_unit_test_setup_teardown(concurrent_sessions_share_replacement_until_last_close, setup, teardown),
			cmocka_unit_test_setup_teardown(last_close_and_logout_prevent_cached_replay, setup, teardown),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
