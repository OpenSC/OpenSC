
/* Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi>
 * All rights reserved.
 */

#include "sc.h"
#include "sc-pkcs15.h"
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>

int sc_sec_ask_pin_code(struct sc_pkcs15_pin_info *pin,
			char *out, int outlen, const char *prompt)
{
	char buf[80];
	int i;

	while (1) {
		printf("%s [%s]: ", prompt, pin->com_attr.label);
		fflush(stdin);
		memset(buf, 0, sizeof(buf));
		if (fgets(buf, 80, stdin) == NULL)
			return -1;
		i = 0;
		while (isdigit(buf[i])) {
			out[i] = buf[i];
			i++;
			if (i >= outlen)
				continue;
		}
		out[i] = 0;
		if (i < pin->min_length)
			continue;
		if (i > pin->stored_length)
			continue;
		memset(buf, 0, sizeof(buf));
		break;
	}
	return 0;
}
