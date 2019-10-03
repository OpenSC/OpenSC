/*
 * p11test_case_ec_sign.c: Test different data lengths for EC signatures
 *
 * Copyright (C) 2016, 2017 Red Hat, Inc.
 *
 * Author: Jakub Jelen <jjelen@redhat.com>
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
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "p11test_case_ec_sign.h"

void ec_sign_size_test(void **state) {
	unsigned int i;
	int min, max, j, l, errors = 0, rv;
	token_info_t *info = (token_info_t *) *state;

	P11TEST_START(info);
	if (token.num_ec_mechs == 0 ) {
		fprintf(stderr, "Token does not support any ECC mechanisms. Skipping.\n");
		P11TEST_SKIP(info);
	}

	test_certs_t objects;
	objects.count = 0;
	objects.data = NULL;

	search_for_all_objects(&objects, info);

	debug_print("\nCheck functionality of Sign&Verify on different data lengths");
	for (i = 0; i < objects.count; i++) {
		if (objects.data[i].key_type != CKK_EC)
			continue;
		// sanity: Test all mechanisms
		min = (objects.data[i].bits + 7) / 8 - 2;
		max = (objects.data[i].bits + 7) / 8 + 2;
		if (objects.data[i].sign && objects.data[i].verify) {
			for (j = 0; j < objects.data[i].num_mechs; j++) {
				for (l = min; l < max; l++) {
					rv = sign_verify_test(&(objects.data[i]), info,
						&(objects.data[i].mechs[j]), l, 0);
					if (rv == -1)
						errors++;
				}
			}
		}
	}
	clean_all_objects(&objects);

	if (errors > 0)
		P11TEST_FAIL(info, "Some signatures were not verified successfully. Please review the log");
	P11TEST_PASS(info);
}

