/*
 * openpgp-tool-helpers.c: OpenPGP card utility
 *
 * Copyright (C) 2012-2020 Peter Marschall <peter@adpm.de>
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

#include "config.h"

#include <stdio.h>
#include <time.h>
#include "common/compat_strnlen.h"
#include "openpgp-tool-helpers.h"
#include "util.h"


/* prettify hex */
char *prettify_hex(const u8 *data, size_t length, char *buffer, size_t buflen)
{
	if (data != NULL) {
		int r = sc_bin_to_hex(data, length, buffer, buflen, ':');

		if (r == SC_SUCCESS)
			return buffer;
	}
	return NULL;
}


/* prettify algorithm parameters */
char *prettify_algorithm(const u8 *data, size_t length)
{
	if (data != NULL && length >= 1) {
		static char result[64];	/* large enough */

		if (data[0] == 0x01 && length >= 5) {		/* RSA */
			unsigned short modulus = (data[1] << 8) + data[2];
			snprintf(result, sizeof(result), "RSA%u", modulus);
			return result;
		}
		else if (data[0] == 0x12) {			/* ECDH */
			strcpy(result, "ECDH");
			return result;
		}
		else if (data[0] == 0x13) {			/* ECDSA */
			strcpy(result, "ECDSA");
			return result;
		}
		else if (data[0] == 0x16) {			/* EDDSA */
			strcpy(result, "EDDSA");
			return result;
		}
	}
	return NULL;
}


/* prettify date/time */
char *prettify_date(const u8 *data, size_t length)
{
	if (data != NULL && length == 4) {
		time_t time = (time_t) (data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3]);
		struct tm tm;
		static char result[64];	/* large enough */

#ifdef _WIN32
		if (0 != gmtime_s(&tm, &time))
			return NULL;
#else
		if (NULL == gmtime_r(&time, &tm))
			return NULL;
#endif
		strftime(result, sizeof(result), "%Y-%m-%d %H:%M:%S", &tm);
		return result;
	}
	return NULL;
}


#define BCD2CHAR(x) (((((x) & 0xF0) >> 4) * 10) + ((x) & 0x0F))

/* prettify OpenPGP card version */
char *prettify_version(const u8 *data, size_t length)
{
	if (data != NULL && length >= 2) {
		static char result[10];	/* large enough for even 2*3 digits + separator */
		int major = BCD2CHAR(data[0]);
		int minor = BCD2CHAR(data[1]);

		sprintf(result, "%d.%d", major, minor);
		return result;
	}
	return NULL;
}


/* prettify manufacturer */
char *prettify_manufacturer(const u8 *data, size_t length)
{
	if (data != NULL && length >= 2) {
		unsigned int manuf = (data[0] << 8) + data[1];

		switch (manuf) {
			case 0x0001: return "PPC Card Systems";
			case 0x0002: return "Prism";
			case 0x0003: return "OpenFortress";
			case 0x0004: return "Wewid";
			case 0x0005: return "ZeitControl";
			case 0x0006: return "Yubico";
			case 0x0007: return "OpenKMS";
			case 0x0008: return "LogoEmail";
			case 0x0009: return "Fidesmo";
			case 0x000A: return "Dangerous Things";
			case 0x000B: return "Feitian Technologies";

			case 0x002A: return "Magrathea";
			case 0x0042: return "GnuPG e.V.";

			case 0x1337: return "Warsaw Hackerspace";
			case 0x2342: return "warpzone"; /* hackerspace Muenster.  */
			case 0x4354: return "Confidential Technologies";   /* cotech.de */
			case 0x5443: return "TIF-IT e.V.";
			case 0x63AF: return "Trustica";
			case 0xBA53: return "c-base e.V.";
			case 0xBD0E: return "Paranoidlabs";
			case 0xF517: return "FSIJ";
			case 0xF5EC: return "F-Secure";

			/* 0x0000 and 0xFFFF are defined as test cards per spec,
			   0xFF00 to 0xFFFE are assigned for use with randomly created
			   serial numbers.  */
			case 0x0000:
			case 0xffff: return "test card";
			default: return (manuf & 0xff00) == 0xff00 ? "unmanaged S/N range" : "unknown";
		}
	}
	return NULL;
}


/* prettify pure serial number */
char *prettify_serialnumber(const u8 *data, size_t length)
{
	if (data != NULL && length >= 4) {
		static char result[15];	/* large enough for even 2*3 digits + separator */
		sprintf(result, "%02X%02X%02X%02X", data[0], data[1], data[2], data[3]);
		return result;
	}
	return NULL;
}


/* prettify card holder's name */
char *prettify_name(const u8 *data, size_t length)
{
	if (data != NULL && length > 0) {
		static char result[100]; /* should be large enough */
		char *src = (char *) data;
		char *dst = result;
		if (length > sizeof(result) - 1)
		    length = sizeof(result) - 1;

		while (*src != '\0' && length > 0) {
			*dst = *src++;
			length--;
			if (*dst == '<') {
				if (length > 0 && *src == '<') {
					src++;
					length--;
				}
				*dst = ' ';
			}
			dst++;
		}
		*dst = '\0';
		return result;
	}
	return NULL;
}


/* prettify language */
char *prettify_language(const u8 *data, size_t length)
{
	if (data != NULL && length > 0) {
		static char result[12]; /* 8 chars, 3 separators, 1 null */
		char *src = (char *) data;
		size_t used_length = strnlen(src, length) >> 1;
		int i = 0;

		while (used_length) {
			used_length--;
			result[i++] = *src++;
			result[i++] = *src++;
			result[i++] = used_length ? ',' : '\0';
		}
		return result;
	}
	return NULL;
}


/* convert the raw ISO-5218 SEX value to an english word */
char *prettify_gender(const u8 *data, size_t length)
{
	if (data != NULL && length > 0) {
		switch (*data) {
			case '0': return "unknown";
			case '1': return "male";
			case '2': return "female";
			case '9': return "not announced";
		}
	}
	return NULL;
}
