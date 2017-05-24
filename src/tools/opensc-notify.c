/*
 * Copyright (C) 2017 Frank Morgner <frankmorgner@gmail.com>
 *
 * This file is part of OpenSC.
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
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ui/notify.h"
#include <stdio.h>

int
main (int argc, char **argv)
{
	const char *title = NULL, *text = NULL;
	switch (argc) {
		case 3:
			text = argv[2];
			/* fall through */
		case 2:
			text = argv[1];
			/* fall through */
		case 1:
			break;

		default:
			fprintf(stderr, "Usage: opensc-notify [title [text]]");
			return 1;
	}
	sc_notify_init();
	sc_notify(title, text);
	sc_notify_close();

	return 0;
}
