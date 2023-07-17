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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "fread_to_eof.h"
#include "libopensc/asn1.h"
#include "opensc-asn1-cmdline.h"
#include <stdlib.h>

int
main (int argc, char **argv)
{
	struct gengetopt_args_info cmdline;
	unsigned char *buf = NULL;
	size_t buflen = 0, i;

	if (cmdline_parser(argc, argv, &cmdline) != 0)
		return 1;

	for (i = 0; i < cmdline.inputs_num; i++) {
		if (!fread_to_eof(cmdline.inputs[i], &buf, &buflen))
			continue;

		printf("Parsing '%s' (%"SC_FORMAT_LEN_SIZE_T"u byte%s)\n",
				cmdline.inputs[i], buflen, buflen == 1 ? "" : "s");
		sc_asn1_print_tags(buf, buflen);
	}

	free(buf);
	cmdline_parser_free (&cmdline);

	return 0;
}
