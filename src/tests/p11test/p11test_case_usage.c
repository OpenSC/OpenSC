/*
 * p11test_case_usage.c: Check if the usage flags are sane
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
#include "p11test_case_usage.h"

void usage_test(void **state) {
	unsigned int i;
	int errors = 0;
	token_info_t *info = (token_info_t *) *state;

	test_certs_t objects;
	objects.count = 0;
	objects.data = NULL;

	search_for_all_objects(&objects, info);

	debug_print("Check if the usage flags are sane.\n");
	for (i = 0; i < objects.count; i++) {
		/* The usage flags are paired */
		if (objects.data[i].sign != objects.data[i].verify) {
			errors++;
			fprintf(stderr, " [ ERROR %s ] Both Sign & Verify should be set.\n",
			    objects.data[i].id_str);
		}
		if (objects.data[i].encrypt != objects.data[i].decrypt) {
			errors++;
			fprintf(stderr, " [ ERROR %s ] Both Encrypt & Decrypt should be set.\n",
			    objects.data[i].id_str);
		}
		if (objects.data[i].wrap != objects.data[i].unwrap) {
			errors++;
			fprintf(stderr, " [ ERROR %s ] Both Wrap & Unwrap should be set.\n",
			    objects.data[i].id_str);
		}
		if (objects.data[i].derive_pub != objects.data[i].derive_priv) {
			errors++;
			fprintf(stderr, " [ ERROR %s ] Derive should be set on both private and public part.\n",
			    objects.data[i].id_str);
		}

		/* We have at least one usage flag for every key group */
		if (! objects.data[i].sign       && ! objects.data[i].verify &&
		    ! objects.data[i].encrypt    && ! objects.data[i].decrypt &&
		    ! objects.data[i].wrap       && ! objects.data[i].unwrap &&
		    ! objects.data[i].derive_pub && ! objects.data[i].derive_priv) {
			errors++;
			fprintf(stderr, " [ ERROR %s ] Key group should have at least one usage flag.\n",
			    objects.data[i].id_str);
		}
	}
	clean_all_objects(&objects);

	if (errors > 0)
		fail_msg("Not all the usage flags were successfully verified. See the log above.");
}
