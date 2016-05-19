/*
 * p11test_case_ec_sign.c: Test different data lengths for EC signatures
 *
 * Copyright (C) 2016 Red Hat, Inc.
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
	int min, max, j, l;
	token_info_t *info = (token_info_t *) *state;

	test_certs_t objects;
	objects.count = 0;
	objects.data = NULL;

	search_for_all_objects(&objects, info);

	debug_print("\nCheck functionality of Sign&Verify on different data lengths");
	for (unsigned int i = 0; i < objects.count; i++) {
		if (objects.data[i].key_type != CKK_EC)
			continue;
		// sanity: Test all mechanisms
		min = (objects.data[i].bits + 7) / 8 - 2;
		max = (objects.data[i].bits + 7) / 8 + 2;
		for (j = 0; j < objects.data[i].num_mechs; j++) {
			for (l = min; l < max; l++)
				sign_verify_test(&(objects.data[i]), info,
					&(objects.data[i].mechs[0]), l);
		}
	}

	clean_all_objects(&objects);
}

