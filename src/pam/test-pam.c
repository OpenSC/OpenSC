/*
 * $Id$
 *
 * Copyright (C) 2001, 2002
 *  Antti Tapaninen <aet@cc.hut.fi>
 *  Anna Erika Suortti <asuortti@cc.hut.fi>
 *
 * This program is free software; you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111, USA.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <ctype.h>
#include "pam_support.h"
#include "scam.h"

extern int misc_conv(int num_msg, PAM_CONST struct pam_message **msgm, struct pam_response **response, void *appdata_ptr);

int main(int argc, char **argv)
{
	pam_handle_t *pamh = NULL;
	struct pam_conv conv =
	{
		misc_conv,
		NULL
	};
	int flags = 0, count = 3, rv = PAM_AUTH_ERR;
	const char *user = getenv("USER");

	if (!user) {
		printf("No $USER found.\n");
	}
	do {
		rv = pam_start("test", user, &conv, &pamh);
		fprintf(stderr, "[%02i] pam_start: %d\n", count, rv);
		if (rv == PAM_SUCCESS) {
			rv = pam_sm_authenticate(pamh, flags, argc, (const char **) argv);
			fprintf(stderr, "[%02i] pam_sm_authenticate: %d\n", count, rv);
		}
		if (rv == PAM_MAXTRIES) {
			pam_end(pamh, rv);
			break;
		}
		if (rv == PAM_SUCCESS) {
			fprintf(stderr, "Authenticated\n");
		} else {
			fprintf(stderr, "Authentication failed.\n");
		}
		if (rv == PAM_SUCCESS) {
			rv = pam_sm_acct_mgmt(pamh, flags, argc, (const char **) argv);
			fprintf(stderr, "[%02i] pam_sm_acct_mgmt: %d\n", count, rv);
		}
		if (rv == PAM_SUCCESS) {
			rv = pam_sm_open_session(pamh, flags, argc, (const char **) argv);
			fprintf(stderr, "[%02i] pam_sm_open_session: %d\n", count, rv);
		}
		if (rv == PAM_SUCCESS) {
			rv = pam_sm_close_session(pamh, flags, argc, (const char **) argv);
			fprintf(stderr, "[%02i] pam_sm_close_session: %d\n", count, rv);
		}
		if (pam_end(pamh, rv) != PAM_SUCCESS) {
			pamh = NULL;
		}
		count--;
		rv = PAM_AUTH_ERR;
	} while (count > 0);
	return 0;
}
