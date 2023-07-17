/*
 * wchar_from_char_str.h: Conversion from string to wide string
 *
 * Copyright (C) 2017 Frank Morgner <frankmorgner@gmail.com>
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

static WCHAR *wchar_from_char_str(const char *in)
{
	WCHAR *out;
	int out_len;

	if (!in)
		return NULL;

	out_len = MultiByteToWideChar(CP_UTF8, 0, in, -1, NULL, 0);
	if (0 >= out_len)
		return NULL;

	out = LocalAlloc(0, (sizeof *out) * out_len);
	if (!out)
		return NULL;

	out_len = MultiByteToWideChar(CP_UTF8, 0, in, -1, out, out_len);
	if (out_len == 0xFFFD || 0 >= out_len) {
		LocalFree(out);
		return NULL;
	}

	return out;
}
