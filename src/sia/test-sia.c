/*
 * $Id$
 *
 * Copyright (C) 2002
 *  Antti Tapaninen <aet@cc.hut.fi>
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
#include <sgtty.h>
#include <utmp.h>
#include <signal.h>
#include <errno.h>
#include <ttyent.h>
#include <syslog.h>
#include <grp.h>
#include <pwd.h>
#include <setjmp.h>
#include <stdio.h>
#include <strings.h>
#include <lastlog.h>
#include <paths.h>

#include <sia.h>
#include <siad.h>

char *sia_code_string(int code)
{
	static char err_string[64];

	switch (code) {
	case SIADSUCCESS:
		return "SIADSUCCESS";
	case SIAFAIL:
		return "SIAFAIL";
	case SIASTOP:
		return "SIASTOP";
	default:
		(void) sprintf(err_string, "Unknown error %d\n", code);
		return err_string;
	}
}

int main(int argc, char **argv)
{
	int (*sia_collect) () = sia_collect_trm;
	SIAENTITY *entity = NULL;
	char *user;
	int code;

	if (argc != 2) {
		printf("Usage: test-sia user\n");
		return 1;
	}
	user = argv[1];

	code = sia_ses_init(&entity, argc, argv, NULL, user, NULL, 1, NULL);
	if (code != SIASUCCESS) {
		printf("sia_ses_init failed with code %s\n", sia_code_string(code));
		sia_ses_release(&entity);
		return 1;
	}
	code = sia_ses_reauthent(sia_collect, entity);
	if (code != SIASUCCESS) {
		printf("sia_ses_reauthent failed with code %s\n", sia_code_string(code));
		sia_ses_release(&entity);
		return 1;
	}
	code = sia_ses_release(&entity);
	if (code != SIASUCCESS) {
		printf("sia_ses_release failed with code %s\n", sia_code_string(code));
		return 1;
	}
	printf("Password verified.\n");
	return 0;
}
