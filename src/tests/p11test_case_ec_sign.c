#include "p11test_case_ec_sign.h"

void ec_sign_size_test(void **state) {

	token_info_t *info = (token_info_t *) *state;

	test_certs_t objects;
	objects.count = 0;
	objects.data = NULL;

	search_for_all_objects(&objects, info);

	debug_print("\nCheck functionality of Sign&Verify and/or Encrypt&Decrypt");
	for (unsigned int i = 0; i < objects.count; i++) {
		if (objects.data[i].key_type == CKK_EC)
			// for (int j = 0; j < objects.data[i].num_mechs; j++) // XXX single mechanism
			for (int l = 30; l < 35; l++)
				sign_verify_test(&(objects.data[i]), info,
					&(objects.data[i].mechs[0]), l);
	}

	clean_all_objects(&objects);
}

