/* mkdtemp.c - libc replacement function
 * Copyright (C) 2001 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

/* This is a replacement function for mkdtemp in case the platform
   we're building on (like mine!) doesn't have it. */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <assert.h>

#include <fcntl.h>
#include <unistd.h>

#include <opensc/scrandom.h>

#ifdef MKDIR_TAKES_ONE_ARG
# undef mkdir
# define mkdir(a,b) mkdir(a)
#endif

char *mkdtemp(char *tmpl)
{
	int attempts, idx, count = 0;
	char *ch;

	idx = strlen(tmpl);

	/* Walk backwards to count all the Xes */
	while (idx > 0 && tmpl[idx - 1] == 'X') {
		count++;
		idx--;
	}

	if (count == 0) {
		errno = EINVAL;
		return NULL;
	}

	ch = &tmpl[idx];

	/* Try 4 times to make the temp directory */
	for (attempts = 0; attempts < 4; attempts++) {
		int remaining = count;
		char *marker = ch;
		unsigned char *randombits;

		idx = 0;

		/* Using really random bits is probably overkill here.  The
		   worst thing that can happen with a directory name collision
		   is that the function will return an error. */

		randombits = (unsigned char *) malloc(4 * remaining);
		assert(randombits != NULL);
		assert(scrandom_get_data(randombits, 4 * remaining) ==
		       4 * remaining);

		while (remaining > 1) {
			sprintf(marker, "%02X", randombits[idx++]);
			marker += 2;
			remaining -= 2;
		}

		/* Any leftover Xes?  get_random_bits rounds up to full bytes,
		   so this is safe. */
		if (remaining > 0)
			sprintf(marker, "%X", randombits[idx] & 0xF);

		free(randombits);

		if (mkdir(tmpl, 0700) == 0)
			break;
	}

	if (attempts == 4)
		return NULL;	/* keeps the errno from mkdir, whatever it is */

	return tmpl;
}
