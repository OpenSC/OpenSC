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
#include <stdlib.h>
#include <string.h>
#include <scrandom.h>

int main(int argc, char **argv)
{
	unsigned int i, c = 0, buflen = 255;
	unsigned char *buf = NULL;

	buf = (unsigned char *) malloc(buflen);
	if (!buf) {
		perror("malloc");
		return 1;
	}
	memset(buf, 0, buflen);

	if (scrandom_get_data(buf, buflen) < 0) {
		perror("scrandom_get_data");
		free(buf);
		return 1;
	}
	for (i = 0; i < buflen; i++) {
		printf("%02X ", buf[i]);
		if (c == 16) {
			printf("\n");
			c = 0;
		} else {
			c++;
		}
	}
	printf("\n");
	free(buf);
	return 0;
}
