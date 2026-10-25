/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Exercise the exported search API with synthetic objects, without initializing
 * the module or connecting to a reader. Attribute comparison is production code.
 */
#include "pkcs11/sc-pkcs11.h"
#include "torture.h"

struct test_object {
	struct sc_pkcs11_object object;
	CK_OBJECT_CLASS class;
	CK_BBOOL private;
	unsigned char value;
	unsigned int value_reads;
};

struct fixture {
	struct sc_context ctx;
	struct sc_pkcs11_slot slot;
	struct sc_pkcs11_session session;
	struct test_object objects[4];
};

static CK_RV
get_attribute(struct sc_pkcs11_session *session, void *ptr, CK_ATTRIBUTE_PTR attr)
{
	struct test_object *obj = ptr;
	const void *value;
	size_t length;

	(void)session;
	switch (attr->type) {
	case CKA_CLASS:
		value = &obj->class;
		length = sizeof(obj->class);
		break;
	case CKA_PRIVATE:
		value = &obj->private;
		length = sizeof(obj->private);
		break;
	case CKA_VALUE:
		obj->value_reads++;
		value = &obj->value;
		length = sizeof(obj->value);
		break;
	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}
	if (attr->pValue) {
		if (attr->ulValueLen < length)
			return CKR_BUFFER_TOO_SMALL;
		memcpy(attr->pValue, value, length);
	}
	attr->ulValueLen = length;
	return CKR_OK;
}

static int
session_seeker(const void *ptr, const void *key)
{
	const struct sc_pkcs11_session *session = ptr;
	return session->handle == *(const CK_SESSION_HANDLE *)key;
}

static int
setup(void **state)
{
	static struct sc_pkcs11_object_ops ops = {
			.get_attribute = get_attribute,
			.cmp_attribute = sc_pkcs11_any_cmp_attribute};
	struct fixture *f = calloc(1, sizeof(*f));
	size_t i;

	assert_non_null(f);
	*state = f;
	context = &f->ctx;
	f->slot.login_user = -1;
	f->slot.token_info.flags = CKF_LOGIN_REQUIRED;
	f->session.handle = 1;
	f->session.slot = &f->slot;
	assert_int_equal(list_init(&sessions), 0);
	assert_int_equal(list_attributes_seeker(&sessions, session_seeker), 0);
	assert_int_equal(list_append(&sessions, &f->session), 1);
	assert_int_equal(list_init(&f->slot.objects), 0);
	for (i = 0; i < 4; i++) {
		f->objects[i].object.handle = i + 1;
		f->objects[i].object.ops = &ops;
		f->objects[i].class = i == 0 ? CKO_DATA : CKO_CERTIFICATE;
		f->objects[i].private = i == 3;
		f->objects[i].value = i == 2 ? 'y' : 'x';
		assert_int_equal(list_append(&f->slot.objects, &f->objects[i]), 1);
	}
	return 0;
}

static int
teardown(void **state)
{
	struct fixture *f = *state;
	C_FindObjectsFinal(f->session.handle);
	list_destroy(&f->slot.objects);
	list_destroy(&sessions);
	context = NULL;
	free(f);
	return 0;
}

static void
find_objects(struct fixture *f, CK_ATTRIBUTE_PTR attrs, CK_ULONG count,
		const CK_OBJECT_HANDLE *expected, CK_ULONG expected_count)
{
	CK_OBJECT_HANDLE handles[4];
	CK_ULONG found;
	size_t i;

	for (i = 0; i < 4; i++)
		f->objects[i].value_reads = 0;
	assert_int_equal(C_FindObjectsInit(f->session.handle, attrs, count), CKR_OK);
	assert_int_equal(C_FindObjects(f->session.handle, handles, 4, &found), CKR_OK);
	assert_int_equal(found, expected_count);
	if (found)
		assert_memory_equal(handles, expected, found * sizeof(*handles));
	assert_int_equal(C_FindObjects(f->session.handle, handles, 4, &found), CKR_OK);
	assert_int_equal(found, 0);
	assert_int_equal(C_FindObjectsFinal(f->session.handle), CKR_OK);
}

static void
class_order_avoids_unrelated_value_reads(void **state)
{
	struct fixture *f = *state;
	CK_OBJECT_CLASS class = CKO_CERTIFICATE;
	unsigned char value = 'x';
	CK_ATTRIBUTE attrs[] = {
			{CKA_VALUE, &value, 1	     },
			{CKA_CLASS, &class, sizeof(class)}
	  };
	CK_ATTRIBUTE reversed[] = {attrs[1], attrs[0]};
	const CK_OBJECT_HANDLE expected[] = {2};

	find_objects(f, attrs, 2, expected, 1);
	assert_int_equal(f->objects[0].value_reads, 0);
	assert_int_equal(f->objects[3].value_reads, 0);
	find_objects(f, reversed, 2, expected, 1);
	assert_int_equal(f->objects[0].value_reads, 0);
	assert_int_equal(f->objects[3].value_reads, 0);
}

static void
entire_template_is_still_required(void **state)
{
	struct fixture *f = *state;
	CK_OBJECT_CLASS certificate = CKO_CERTIFICATE, data = CKO_DATA;
	unsigned char value = 'x';
	CK_ATTRIBUTE attrs[] = {
			{CKA_VALUE, &value,	    1		     },
			{CKA_CLASS, &certificate, sizeof(certificate)},
			{CKA_CLASS, &data,	   sizeof(data)       }
	};

	find_objects(f, attrs, 3, NULL, 0);
	attrs[1].ulValueLen = 1;
	find_objects(f, attrs, 2, NULL, 0);
}

static void
templates_without_class_preserve_matches(void **state)
{
	struct fixture *f = *state;
	unsigned char value = 'x';
	CK_ATTRIBUTE attr = {CKA_VALUE, &value, 1};
	const CK_OBJECT_HANDLE all_public[] = {1, 2, 3}, matching[] = {1, 2};

	find_objects(f, NULL, 0, all_public, 3);
	find_objects(f, &attr, 1, matching, 2);
}

static void
private_visibility_follows_login_state(void **state)
{
	struct fixture *f = *state;
	CK_OBJECT_CLASS class = CKO_CERTIFICATE;
	unsigned char value = 'x';
	CK_ATTRIBUTE attrs[] = {
			{CKA_VALUE, &value, 1	     },
			{CKA_CLASS, &class, sizeof(class)}
	  };
	const CK_OBJECT_HANDLE expected[] = {2, 4};

	find_objects(f, attrs, 2, expected, 1);
	f->slot.login_user = CKU_USER;
	find_objects(f, attrs, 2, expected, 2);
}

int
main(void)
{
	const struct CMUnitTest tests[] = {
			cmocka_unit_test_setup_teardown(class_order_avoids_unrelated_value_reads, setup, teardown),
			cmocka_unit_test_setup_teardown(entire_template_is_still_required, setup, teardown),
			cmocka_unit_test_setup_teardown(templates_without_class_preserve_matches, setup, teardown),
			cmocka_unit_test_setup_teardown(private_visibility_follows_login_state, setup, teardown),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
