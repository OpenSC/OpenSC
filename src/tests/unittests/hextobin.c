/*
 * hextobin.c: Test suite for sc_hex_to_bin()
 *
 * Copyright (C) 2022 Peter Popovec <popovec.peter@gmail.com>
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

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "libopensc/opensc.h"

#define LEN 30

#define C_END -1
#define C_ERROR -3

struct tst {
	int result_len;
	const char *input;
	const char *output;
};
int main()
{
	struct tst *t;
	struct tst test[] = {
		{1, "0", "\x00"},
		{1, " 0", "\x00"},
		{1, "00", "\x00"},
		{1, ":00", "\x00"},
		{1, ":0", "\x00"},
		{1, "d", "\x0d"},
		{1, ":a", "\x0a"},
		{1, "01", "\x01"},
		{1, " 09", "\x09"},
		{1, ":0a", "\x0a"},
		{1, " :0b :", "\x0b"},
		{1, "10", "\x10"},
		{1, " 90", "\x90"},
		{1, ":a0", "\xa0"},
		{1, " :B0 :", "\xb0"},
		{1, " 11:", "\x11"},
		{1, " :11:", "\x11"},
		{1, ":a1", "\xa1"},
		{2, "01:10", "\x01\x10"},
		{2, "10:10", "\x10\x10"},
		{2, " 12ab", "\x12\xab"},
		{3, "10:20:30", "\x10\x20\x30"},
		{3, "1020:30", "\x10\x20\x30"},
		{3, "1020: :30", "\x10\x20\x30"},
		{3, "102030", "\x10\x20\x30"},
		{3, ":102030", "\x10\x20\x30"},
		{3, ":102030:", "\x10\x20\x30"},
		{3, ":102030::", "\x10\x20\x30"},
		{3, "b2:11 :22", "\xb2\x11\x22"},
		{3, "b2 11 22", "\xb2\x11\x22"},
		{9, "10:203040:5060708090", "\x10\x20\x30\x40\x50\x60\x70\x80\x90"},
		{0, "::::", ""},
		{0, ":", ""},
		{0, " ", ""},
		{0, "", ""},
		{C_ERROR, " :0 :", ""},
		{C_ERROR, " :b :", ""},
		{C_ERROR, " :c ", ""},
		{C_ERROR, "1:10", ""},
		{C_ERROR, " :b:2 :", ""},
		{C_ERROR, " ::1:2:a:b", ""},
		{C_ERROR, "1:1", ""},
		{C_ERROR, " :1 1:", ""},
		{C_ERROR, "0:0 :", ""},
		{C_ERROR, "1:234:56", ""},	/* odd number of characters between delimiters  (234) */
		{C_ERROR, " :b:211 :", ""},
		{C_ERROR, "02030", ""},	/* one char missing (to have full byte) */
		{C_ERROR, "111", ""},
		{C_ERROR, "b:211 :2", ""},
		{C_ERROR, "G", ""},
		{C_ERROR, " z", ""},
		{C_ERROR, ":a1:1", ""},
		{C_END, "", ""}
	};
	uint8_t res[LEN];
	size_t len;
	int rv, r;

	for (t = test; t->result_len != C_END; t++) {
		r = t->result_len;
		len = LEN;
		rv = sc_hex_to_bin(t->input, res, &len);
		if (rv) {
			if (r != C_ERROR) {
				fprintf(stderr, "fail at string %s (return code %d, %d\n", t->input,
					rv, r);
				return 1;
			}
		} else {
			if (r == C_ERROR) {
				fprintf(stderr, "fail at string %s (return code %d, %d)\n",
					t->input, rv, r);
				return 2;
			}
			if ((int)len != r) {
				fprintf(stderr, "fail at string %s (length %zu %d)\n", t->input,
					len, r);
				return 3;
			}
			if (memcmp(t->output, res, len)) {
				fprintf(stderr, "fail at string %s (return value)\n", t->input);
				return 4;
			}
		}
	}
	return 0;
}
