/*
 * pkcs15-init driver for JavaCards with IsoApplet installed.
 *
 * Copyright (C) 2014 Philip Wendland <wendlandphilip@gmail.com>
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

#include "config.h"

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>

#include "../libopensc/log.h"
#include "../libopensc/internal.h"
#include "../libopensc/opensc.h"
#include "../libopensc/cardctl.h"
#include "../libopensc/asn1.h"
#include "pkcs15-init.h"
#include "profile.h"

#define ISOAPPLET_KEY_ID_MIN 0
#define ISOAPPLET_KEY_ID_MAX 15

/* Curve parameters of a curve specified by the OID. */
struct ec_curve
{
	const struct sc_lv_data oid; /* Object ID in hex, including structural information */
	const struct sc_lv_data prime;
	const struct sc_lv_data coefficientA;
	const struct sc_lv_data coefficientB;
	const struct sc_lv_data basePointG;
	const struct sc_lv_data order;
	const struct sc_lv_data coFactor;
};

/* OpenSC only works with named curves, but we need the
 * explicit parameters for ECC key generation or import. */
static const struct ec_curve curves[] =
{
	{
		/* brainpoolP192r1 */
		{ (unsigned char *) "\x06\x09\x2B\x24\x03\x03\x02\x08\x01\x01\x03", 11},
		{ (unsigned char *) "\xC3\x02\xF4\x1D\x93\x2A\x36\xCD\xA7\xA3\x46\x30\x93\xD1\x8D\xB7\x8F\xCE\x47\x6D\xE1\xA8\x62\x97", 24},
		{ (unsigned char *) "\x6A\x91\x17\x40\x76\xB1\xE0\xE1\x9C\x39\xC0\x31\xFE\x86\x85\xC1\xCA\xE0\x40\xE5\xC6\x9A\x28\xEF", 24},
		{ (unsigned char *) "\x46\x9A\x28\xEF\x7C\x28\xCC\xA3\xDC\x72\x1D\x04\x4F\x44\x96\xBC\xCA\x7E\xF4\x14\x6F\xBF\x25\xC9", 24},
		{ (unsigned char *) "\x04\xC0\xA0\x64\x7E\xAA\xB6\xA4\x87\x53\xB0\x33\xC5\x6C\xB0\xF0\x90\x0A\x2F\x5C\x48\x53\x37\x5F\xD6\x14\xB6\x90\x86\x6A\xBD\x5B\xB8\x8B\x5F\x48\x28\xC1\x49\x00\x02\xE6\x77\x3F\xA2\xFA\x29\x9B\x8F", 49},
		{ (unsigned char *) "\xC3\x02\xF4\x1D\x93\x2A\x36\xCD\xA7\xA3\x46\x2F\x9E\x9E\x91\x6B\x5B\xE8\xF1\x02\x9A\xC4\xAC\xC1", 24},
		{ (unsigned char *) "\x00\x01", 2}
	},

	{
		/* brainpoolP224r1 */
		{ (unsigned char *) "\x06\x09\x2B\x24\x03\x03\x02\x08\x01\x01\x05", 11},
		{ (unsigned char *) "\xD7\xC1\x34\xAA\x26\x43\x66\x86\x2A\x18\x30\x25\x75\xD1\xD7\x87\xB0\x9F\x07\x57\x97\xDA\x89\xF5\x7E\xC8\xC0\xFF", 28},
		{ (unsigned char *) "\x68\xA5\xE6\x2C\xA9\xCE\x6C\x1C\x29\x98\x03\xA6\xC1\x53\x0B\x51\x4E\x18\x2A\xD8\xB0\x04\x2A\x59\xCA\xD2\x9F\x43", 28},
		{ (unsigned char *) "\x25\x80\xF6\x3C\xCF\xE4\x41\x38\x87\x07\x13\xB1\xA9\x23\x69\xE3\x3E\x21\x35\xD2\x66\xDB\xB3\x72\x38\x6C\x40\x0B", 28},
		{ (unsigned char *) "\x04\x0D\x90\x29\xAD\x2C\x7E\x5C\xF4\x34\x08\x23\xB2\xA8\x7D\xC6\x8C\x9E\x4C\xE3\x17\x4C\x1E\x6E\xFD\xEE\x12\xC0\x7D\x58\xAA\x56\xF7\x72\xC0\x72\x6F\x24\xC6\xB8\x9E\x4E\xCD\xAC\x24\x35\x4B\x9E\x99\xCA\xA3\xF6\xD3\x76\x14\x02\xCD", 57},
		{ (unsigned char *) "\xD7\xC1\x34\xAA\x26\x43\x66\x86\x2A\x18\x30\x25\x75\xD0\xFB\x98\xD1\x16\xBC\x4B\x6D\xDE\xBC\xA3\xA5\xA7\x93\x9F", 28},
		{ (unsigned char *) "\x00\x01", 2}
	},

	{
		/* brainpoolP256r1 */
		{ (unsigned char *) "\x06\x09\x2B\x24\x03\x03\x02\x08\x01\x01\x07", 11},
		{ (unsigned char *) "\xA9\xFB\x57\xDB\xA1\xEE\xA9\xBC\x3E\x66\x0A\x90\x9D\x83\x8D\x72\x6E\x3B\xF6\x23\xD5\x26\x20\x28\x20\x13\x48\x1D\x1F\x6E\x53\x77", 32},
		{ (unsigned char *) "\x7D\x5A\x09\x75\xFC\x2C\x30\x57\xEE\xF6\x75\x30\x41\x7A\xFF\xE7\xFB\x80\x55\xC1\x26\xDC\x5C\x6C\xE9\x4A\x4B\x44\xF3\x30\xB5\xD9", 32},
		{ (unsigned char *) "\x26\xDC\x5C\x6C\xE9\x4A\x4B\x44\xF3\x30\xB5\xD9\xBB\xD7\x7C\xBF\x95\x84\x16\x29\x5C\xF7\xE1\xCE\x6B\xCC\xDC\x18\xFF\x8C\x07\xB6", 32},
		{ (unsigned char *) "\x04\x8B\xD2\xAE\xB9\xCB\x7E\x57\xCB\x2C\x4B\x48\x2F\xFC\x81\xB7\xAF\xB9\xDE\x27\xE1\xE3\xBD\x23\xC2\x3A\x44\x53\xBD\x9A\xCE\x32\x62\x54\x7E\xF8\x35\xC3\xDA\xC4\xFD\x97\xF8\x46\x1A\x14\x61\x1D\xC9\xC2\x77\x45\x13\x2D\xED\x8E\x54\x5C\x1D\x54\xC7\x2F\x04\x69\x97", 65},
		{ (unsigned char *) "\xA9\xFB\x57\xDB\xA1\xEE\xA9\xBC\x3E\x66\x0A\x90\x9D\x83\x8D\x71\x8C\x39\x7A\xA3\xB5\x61\xA6\xF7\x90\x1E\x0E\x82\x97\x48\x56\xA7", 32},
		{ (unsigned char *) "\x00\x01", 2}
	},

	{
		/* brainpoolP320r1 */
		{ (unsigned char *) "\x06\x09\x2B\x24\x03\x03\x02\x08\x01\x01\x09", 11},
		{ (unsigned char *) "\xD3\x5E\x47\x20\x36\xBC\x4F\xB7\xE1\x3C\x78\x5E\xD2\x01\xE0\x65\xF9\x8F\xCF\xA6\xF6\xF4\x0D\xEF\x4F\x92\xB9\xEC\x78\x93\xEC\x28\xFC\xD4\x12\xB1\xF1\xB3\x2E\x27", 40},
		{ (unsigned char *) "\x3E\xE3\x0B\x56\x8F\xBA\xB0\xF8\x83\xCC\xEB\xD4\x6D\x3F\x3B\xB8\xA2\xA7\x35\x13\xF5\xEB\x79\xDA\x66\x19\x0E\xB0\x85\xFF\xA9\xF4\x92\xF3\x75\xA9\x7D\x86\x0E\xB4", 40},
		{ (unsigned char *) "\x52\x08\x83\x94\x9D\xFD\xBC\x42\xD3\xAD\x19\x86\x40\x68\x8A\x6F\xE1\x3F\x41\x34\x95\x54\xB4\x9A\xCC\x31\xDC\xCD\x88\x45\x39\x81\x6F\x5E\xB4\xAC\x8F\xB1\xF1\xA6", 40},
		{ (unsigned char *) "\x04\x43\xBD\x7E\x9A\xFB\x53\xD8\xB8\x52\x89\xBC\xC4\x8E\xE5\xBF\xE6\xF2\x01\x37\xD1\x0A\x08\x7E\xB6\xE7\x87\x1E\x2A\x10\xA5\x99\xC7\x10\xAF\x8D\x0D\x39\xE2\x06\x11\x14\xFD\xD0\x55\x45\xEC\x1C\xC8\xAB\x40\x93\x24\x7F\x77\x27\x5E\x07\x43\xFF\xED\x11\x71\x82\xEA\xA9\xC7\x78\x77\xAA\xAC\x6A\xC7\xD3\x52\x45\xD1\x69\x2E\x8E\xE1", 81},
		{ (unsigned char *) "\xD3\x5E\x47\x20\x36\xBC\x4F\xB7\xE1\x3C\x78\x5E\xD2\x01\xE0\x65\xF9\x8F\xCF\xA5\xB6\x8F\x12\xA3\x2D\x48\x2E\xC7\xEE\x86\x58\xE9\x86\x91\x55\x5B\x44\xC5\x93\x11", 40},
		{ (unsigned char *) "\x00\x01", 2}
	},

	{
		/* prime192v1, secp192r1, ansiX9p192r1 */
		{ (unsigned char *) "\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x01", 10},
		{ (unsigned char *) "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 24},
		{ (unsigned char *) "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFC", 24},
		{ (unsigned char *) "\x64\x21\x05\x19\xE5\x9C\x80\xE7\x0F\xA7\xE9\xAB\x72\x24\x30\x49\xFE\xB8\xDE\xEC\xC1\x46\xB9\xB1", 24},
		{ (unsigned char *) "\x04\x18\x8D\xA8\x0E\xB0\x30\x90\xF6\x7C\xBF\x20\xEB\x43\xA1\x88\x00\xF4\xFF\x0A\xFD\x82\xFF\x10\x12\x07\x19\x2B\x95\xFF\xC8\xDA\x78\x63\x10\x11\xED\x6B\x24\xCD\xD5\x73\xF9\x77\xA1\x1E\x79\x48\x11", 49},
		{ (unsigned char *) "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x99\xDE\xF8\x36\x14\x6B\xC9\xB1\xB4\xD2\x28\x31", 24},
		{ (unsigned char *) "\x00\x01", 2}
	},

	{
		/* prime224v1, nistp224 */
		{ (unsigned char *) "\x06\x05\x2b\x81\x04\x00\x21", 7},
		{ (unsigned char *) "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", 28},
		{ (unsigned char *) "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE", 28},
		{ (unsigned char *) "\xB4\x05\x0A\x85\x0C\x04\xB3\xAB\xF5\x41\x32\x56\x50\x44\xB0\xB7\xD7\xBF\xD8\xBA\x27\x0B\x39\x43\x23\x55\xFF\xB4", 28},
		{ (unsigned char *) "\x04\xB7\x0E\x0C\xBD\x6B\xB4\xBF\x7F\x32\x13\x90\xB9\x4A\x03\xC1\xD3\x56\xC2\x11\x22\x34\x32\x80\xD6\x11\x5C\x1D\x21\xBD\x37\x63\x88\xB5\xF7\x23\xFB\x4C\x22\xDF\xE6\xCD\x43\x75\xA0\x5A\x07\x47\x64\x44\xD5\x81\x99\x85\x00\x7E\x34", 57},
		{ (unsigned char *) "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x16\xA2\xE0\xB8\xF0\x3E\x13\xDD\x29\x45\x5C\x5C\x2A\x3D", 28},
		{ (unsigned char *) "\x00\x01", 2}
	},

	{
		/* prime256v1, secp256r1, ansiX9p256r1 */
		{ (unsigned char *) "\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07", 10},
		{ (unsigned char *) "\xFF\xFF\xFF\xFF\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 32},
		{ (unsigned char *) "\xFF\xFF\xFF\xFF\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFC", 32},
		{ (unsigned char *) "\x5A\xC6\x35\xD8\xAA\x3A\x93\xE7\xB3\xEB\xBD\x55\x76\x98\x86\xBC\x65\x1D\x06\xB0\xCC\x53\xB0\xF6\x3B\xCE\x3C\x3E\x27\xD2\x60\x4B", 32},
		{ (unsigned char *) "\x04\x6B\x17\xD1\xF2\xE1\x2C\x42\x47\xF8\xBC\xE6\xE5\x63\xA4\x40\xF2\x77\x03\x7D\x81\x2D\xEB\x33\xA0\xF4\xA1\x39\x45\xD8\x98\xC2\x96\x4F\xE3\x42\xE2\xFE\x1A\x7F\x9B\x8E\xE7\xEB\x4A\x7C\x0F\x9E\x16\x2B\xCE\x33\x57\x6B\x31\x5E\xCE\xCB\xB6\x40\x68\x37\xBF\x51\xF5", 65},
		{ (unsigned char *) "\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xBC\xE6\xFA\xAD\xA7\x17\x9E\x84\xF3\xB9\xCA\xC2\xFC\x63\x25\x51", 32},
		{ (unsigned char *) "\x00\x01", 2}
	},

	{
		/* prime384v1, secp384r1, ansiX9p384r1 */
		{ (unsigned char *) "\x06\x05\x2B\x81\x04\x00\x22", 7},
		{ (unsigned char *) "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF", 48},
		{ (unsigned char *) "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFC", 48},
		{ (unsigned char *) "\xB3\x31\x2F\xA7\xE2\x3E\xE7\xE4\x98\x8E\x05\x6B\xE3\xF8\x2D\x19\x18\x1D\x9C\x6E\xFE\x81\x41\x12\x03\x14\x08\x8F\x50\x13\x87\x5A\xC6\x56\x39\x8D\x8A\x2E\xD1\x9D\x2A\x85\xC8\xED\xD3\xEC\x2A\xEF", 48},
		{ (unsigned char *) "\x04\xAA\x87\xCA\x22\xBE\x8B\x05\x37\x8E\xB1\xC7\x1E\xF3\x20\xAD\x74\x6E\x1D\x3B\x62\x8B\xA7\x9B\x98\x59\xF7\x41\xE0\x82\x54\x2A\x38\x55\x02\xF2\x5D\xBF\x55\x29\x6C\x3A\x54\x5E\x38\x72\x76\x0A\xB7\x36\x17\xDE\x4A\x96\x26\x2C\x6F\x5D\x9E\x98\xBF\x92\x92\xDC\x29\xF8\xF4\x1D\xBD\x28\x9A\x14\x7C\xE9\xDA\x31\x13\xB5\xF0\xB8\xC0\x0A\x60\xB1\xCE\x1D\x7E\x81\x9D\x7A\x43\x1D\x7C\x90\xEA\x0E\x5F", 97},
		{ (unsigned char *) "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xC7\x63\x4D\x81\xF4\x37\x2D\xDF\x58\x1A\x0D\xB2\x48\xB0\xA7\x7A\xEC\xEC\x19\x6A\xCC\xC5\x29\x73", 48},
		{ (unsigned char *) "\x00\x01", 2}
	},

	{
		/* secp192k1 */
		{ (unsigned char *) "\x06\x05\x2B\x81\x04\x00\x1F", 7},
		{ (unsigned char *) "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xFF\xFF\xEE\x37", 24},
		{ (unsigned char *) "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 24},
		{ (unsigned char *) "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03", 24},
		{ (unsigned char *) "\x04\xDB\x4F\xF1\x0E\xC0\x57\xE9\xAE\x26\xB0\x7D\x02\x80\xB7\xF4\x34\x1D\xA5\xD1\xB1\xEA\xE0\x6C\x7D\x9B\x2F\x2F\x6D\x9C\x56\x28\xA7\x84\x41\x63\xD0\x15\xBE\x86\x34\x40\x82\xAA\x88\xD9\x5E\x2F\x9D", 49},
		{ (unsigned char *) "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\x26\xF2\xFC\x17\x0F\x69\x46\x6A\x74\xDE\xFD\x8D", 24},
		{ (unsigned char *) "\x00\x01", 2}
	},

	{
		/* secp256k1 */
		{ (unsigned char *) "\x06\x05\x2B\x81\x04\x00\x0A", 7},
		{ (unsigned char *) "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xFF\xFF\xFC\x2F", 32},
		{ (unsigned char *) "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 32},
		{ (unsigned char *) "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07", 32},
		{ (unsigned char *) "\x04\x79\xBE\x66\x7E\xF9\xDC\xBB\xAC\x55\xA0\x62\x95\xCE\x87\x0B\x07\x02\x9B\xFC\xDB\x2D\xCE\x28\xD9\x59\xF2\x81\x5B\x16\xF8\x17\x98\x48\x3A\xDA\x77\x26\xA3\xC4\x65\x5D\xA4\xFB\xFC\x0E\x11\x08\xA8\xFD\x17\xB4\x48\xA6\x85\x54\x19\x9C\x47\xD0\x8F\xFB\x10\xD4\xB8", 65},
		{ (unsigned char *) "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xBA\xAE\xDC\xE6\xAF\x48\xA0\x3B\xBF\xD2\x5E\x8C\xD0\x36\x41\x41", 32},
		{ (unsigned char *) "\x00\x01", 2}
	},

	{
		{ NULL, 0},
		{ NULL, 0},
		{ NULL, 0},
		{ NULL, 0},
		{ NULL, 0},
		{ NULL, 0},
		{ NULL, 0}
	}
};


/*
 * Create DF, using default pkcs15init functions.
 */
static int
isoApplet_create_dir(sc_profile_t *profile, sc_pkcs15_card_t *p15card, sc_file_t *df)
{
	sc_card_t *card = p15card->card;
	int r = SC_SUCCESS;

	LOG_FUNC_CALLED(card->ctx);

	if(!profile || !df || !p15card->card->ctx)
	{
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	}
	r = sc_pkcs15init_create_file(profile, p15card, df);
	LOG_FUNC_RETURN(card->ctx, r);
}

/*
 * Select a PIN reference.
 *
 * Basically (as I understand it) the caller passes an auth_info object and the
 * auth_info->attrs.pin.reference is supposed to be set accordingly and return.
 *
 * The IsoApplet only supports a PIN and a PUK at the moment.
 * The reference for the PIN is 1, for the PUK 2.
 */
static int
isoApplet_select_pin_reference(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
                               sc_pkcs15_auth_info_t *auth_info)
{
	sc_card_t *card = p15card->card;
	int	preferred;
	int current;

	LOG_FUNC_CALLED(card->ctx);

	if (auth_info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
	{
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OBJECT_NOT_VALID);
	}

	current = auth_info->attrs.pin.reference;
	if (current < 0)
	{
		current = 0;
	}

	if(current > 2)
	{
		/* Only two PINs supported: User PIN and PUK. */
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_TOO_MANY_OBJECTS);
	}
	else
	{
		if(auth_info->attrs.pin.flags & SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN)
		{
			/* PUK */
			preferred = 2;
		}
		else
		{
			/* PIN */
			preferred = 1;
		}
	}

	auth_info->attrs.pin.reference = preferred;
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

/*
 * Create a PIN and store it on the card using CHANGE REFERENCE DATA for PIN transmission.
 * First, the PUK is transmitted, then the PIN. Now, the IsoApplet is in the
 * "STATE_OPERATIONAL_ACTIVATED" lifecycle state.
 */
static int
isoApplet_create_pin(sc_profile_t *profile, sc_pkcs15_card_t *p15card, sc_file_t *df,
                     sc_pkcs15_object_t *pin_obj,
                     const u8 *pin, size_t pin_len,
                     const u8 *puk, size_t puk_len)
{
	sc_card_t *card = p15card->card;
	sc_pkcs15_auth_info_t *auth_info = (sc_pkcs15_auth_info_t *) pin_obj->data;
	struct sc_pkcs15_pin_attributes *pin_attrs = &auth_info->attrs.pin;
	int r;

	LOG_FUNC_CALLED(card->ctx);

	if(!pin || !pin_len || !df)
	{
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	}

	if(pin_attrs->reference != 1 &&	pin_attrs->reference != 2)
	{
		/* Reject PIN reference. */
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_PIN_REFERENCE);
	}

	/* If we have a PUK, set it first. */
	if(puk && puk_len)
	{
		/* The PUK has a incremented reference, i.e. pins are odd, puks are equal (+1). */
		r = sc_change_reference_data(p15card->card, SC_AC_CHV,
		                             pin_attrs->reference+1,
		                             NULL, 0,
		                             puk, puk_len, NULL);
		if(r < 0)
		{
			LOG_FUNC_RETURN(card->ctx, r);
		}
	}

	/* Store PIN: (use CHANGE REFERENCE DATA). */
	r = sc_change_reference_data(p15card->card, SC_AC_CHV,
	                             pin_attrs->reference,
	                             NULL, 0,
	                             pin, pin_len, NULL);
	LOG_TEST_RET(card->ctx, r, "Failed to set PIN");

	sc_pkcs15_pincache_add(p15card, pin_obj, pin, pin_len);
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

/*
 * @brief Get the curve parameters associated with the curve specified by an OID.
 *
 * @param[in]  oid       The DER encoded OID of the curve.
 * @param[in]  oid_len   The length of oid.
 * @param[out] curve_out The ec_curve containing the set of parameters.
 *
 * @returns	SC_SUCCESS: If the curve was found.
 *			SC_ERROR_INVALID_ARGUMENTS: If named_curve was null or the curve
 *										was not found
 */
static int
isoApplet_get_curve(u8 *oid, size_t oid_len, const struct ec_curve **curve_out)
{
	int i;

	if(!oid)
		return SC_ERROR_INVALID_ARGUMENTS;

	/* Search the curve parameters. */
	for (i = 0; curves[i].oid.value; i++)
	{
		if (oid_len == curves[i].oid.len && memcmp(oid, curves[i].oid.value, curves[i].oid.len) == 0)
		{
			*curve_out = &curves[i];
			return SC_SUCCESS;
		}
	}

	return SC_ERROR_INVALID_ARGUMENTS;
}


/*
 * @brief Generate a RSA private key on the card.
 *
 * A MANAGE SECURITY ENVIRONMENT apdu must have been sent before.
 * This function uses card_ctl to access the card-isoApplet driver.
 *
 * @param[in] key_info
 * @param[in] card
 * @param[in] pubkey The public key of the generated key pair
 *                   returned by the card.
 *
 * @return	SC_ERROR_INVALID_ARGURMENTS: Invalid key length.
 *          SC_ERROR_OUT_OF_MEMORY
 */
static int
isoApplet_generate_key_rsa(sc_pkcs15_prkey_info_t *key_info, sc_card_t *card,
                           sc_pkcs15_pubkey_t *pubkey)
{
	int rv;
	size_t keybits;
	struct sc_cardctl_isoApplet_genkey args;

	LOG_FUNC_CALLED(card->ctx);

	/* Check key size: */
	keybits = key_info->modulus_length;
	if (keybits != 2048)
	{
		rv = SC_ERROR_INVALID_ARGUMENTS;
		sc_log(card->ctx, "%s: RSA private key length is unsupported, correct length is 2048", sc_strerror(rv));
		goto err;
	}

	/* Generate the key.
	 * Note: key size is not explicitly passed to the card.
	 * It assumes 2048 along with the algorithm reference. */
	memset(&args, 0, sizeof(args));
	args.algorithm_ref = SC_ISOAPPLET_ALG_REF_RSA_GEN_2048;
	args.priv_key_ref = key_info->key_reference;

	args.pubkey.rsa.modulus.len = keybits / 8;
	args.pubkey.rsa.modulus.value = malloc(args.pubkey.rsa.modulus.len);
	if (!args.pubkey.rsa.modulus.value)
	{
		rv = SC_ERROR_OUT_OF_MEMORY;
		sc_log(card->ctx, "%s: Unable to allocate public key buffer.", sc_strerror(rv));
		goto err;
	}

	args.pubkey.rsa.exponent.len = 3;
	args.pubkey.rsa.exponent.value = malloc(args.pubkey.rsa.exponent.len);
	if(!args.pubkey.rsa.exponent.value)
	{
		rv = SC_ERROR_OUT_OF_MEMORY;
		sc_log(card->ctx, "%s: Unable to allocate public key exponent buffer.", sc_strerror(rv));
		goto err;
	}

	rv = sc_card_ctl(card, SC_CARDCTL_ISOAPPLET_GENERATE_KEY, &args);
	if (rv < 0)
	{
		sc_log(card->ctx, "%s: Error in card_ctl", sc_strerror(rv));
		goto err;
	}

	/* extract the public key */
	pubkey->algorithm = SC_ALGORITHM_RSA;
	pubkey->u.rsa.modulus.len	= args.pubkey.rsa.modulus.len;
	pubkey->u.rsa.modulus.data	= args.pubkey.rsa.modulus.value;
	pubkey->u.rsa.exponent.len	= args.pubkey.rsa.exponent.len;
	pubkey->u.rsa.exponent.data	= args.pubkey.rsa.exponent.value;
	rv = SC_SUCCESS;
	LOG_FUNC_RETURN(card->ctx, rv);
err:
	if (args.pubkey.rsa.modulus.value)
	{
		free(args.pubkey.rsa.modulus.value);
		pubkey->u.rsa.modulus.data = NULL;
		pubkey->u.rsa.modulus.len = 0;
	}
	if (args.pubkey.rsa.exponent.value)
	{
		free(args.pubkey.rsa.exponent.value);
		pubkey->u.rsa.exponent.data = NULL;
		pubkey->u.rsa.exponent.len = 0;
	}
	LOG_FUNC_RETURN(card->ctx, rv);
}

/*
 * @brief Generate a EC private key on the card.
 *
 * A MANAGE SECURITY ENVIRONMENT apdu must have been sent before.
 * This function uses card_ctl to access the card-isoApplet driver.
 *
 * @param[in]     key_info
 * @param[in]     card
 * @param[in/out] pubkey The public key of the generated key pair
 *						 returned by the card.
 *
 * @return SC_ERROR_INVALID_ARGURMENTS: Invalid key length or curve.
 *         SC_ERROR_OUT_OF_MEMORY
 *         SC_ERROR_INCOMPATIBLE_KEY: The data returned by the card
 *                                    was unexpected and can not be
 *                                    handled.
 */
static int
isoApplet_generate_key_ec(const sc_pkcs15_prkey_info_t *key_info, sc_card_t *card,
                          sc_pkcs15_pubkey_t *pubkey)
{
	int	r;
	const struct ec_curve *curve = NULL;
	struct sc_ec_parameters *alg_id_params = NULL;
	sc_cardctl_isoApplet_genkey_t args;
	const struct sc_ec_parameters *info_ecp =
	    (struct sc_ec_parameters *) key_info->params.data;

	LOG_FUNC_CALLED(card->ctx);

	/* Check key size: */
	if(key_info->field_length == 0)
	{
		sc_log(card->ctx, "Unknown field length.");
		r = SC_ERROR_INVALID_ARGUMENTS;
		goto out;
	}

	r = isoApplet_get_curve(info_ecp->der.value, info_ecp->der.len, &curve);
	if(r < 0)
	{
		sc_log(card->ctx, "EC key generation failed: Unsupported curve: [%s].", info_ecp->named_curve);
		goto out;
	}

	/* Generate the key.
	 * Note: The field size is not explicitly passed to the card.
	 *       As we only support FP curves, the field length can be calculated from any parameter. */
	memset(&args, 0, sizeof(args));

	args.pubkey.ec.params.prime.value			= curve->prime.value;
	args.pubkey.ec.params.prime.len				= curve->prime.len;
	args.pubkey.ec.params.coefficientA.value	= curve->coefficientA.value;
	args.pubkey.ec.params.coefficientA.len		= curve->coefficientA.len;
	args.pubkey.ec.params.coefficientB.value	= curve->coefficientB.value;
	args.pubkey.ec.params.coefficientB.len		= curve->coefficientB.len;
	args.pubkey.ec.params.basePointG.value 		= curve->basePointG.value;
	args.pubkey.ec.params.basePointG.len		= curve->basePointG.len;
	args.pubkey.ec.params.order.value 			= curve->order.value;
	args.pubkey.ec.params.order.len				= curve->order.len;
	args.pubkey.ec.params.coFactor.value 		= curve->coFactor.value;
	args.pubkey.ec.params.coFactor.len			= curve->coFactor.len;
	/* The length of the public key point will be:
	 * Uncompressed tag + 2 * field length in bytes. */
	args.pubkey.ec.ecPointQ.len = 1 + (key_info->field_length + 7) / 8 * 2;
	args.pubkey.ec.ecPointQ.value = malloc(args.pubkey.ec.ecPointQ.len);
	if(!args.pubkey.ec.ecPointQ.value)
	{
		r = SC_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	args.algorithm_ref = SC_ISOAPPLET_ALG_REF_EC_GEN;
	args.priv_key_ref = key_info->key_reference;

	/* On-card key generation */
	r = sc_card_ctl(card, SC_CARDCTL_ISOAPPLET_GENERATE_KEY, &args);
	if (r < 0)
	{
		sc_log(card->ctx, "%s: Error in card_ctl.", sc_strerror(r));
		goto out;
	}

	/* Extract and compose the public key. */
	pubkey->algorithm = SC_ALGORITHM_EC;

	/* der-encoded parameters */
	alg_id_params = calloc(1, sizeof(*alg_id_params));
	if(!alg_id_params)
	{
		r = SC_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	alg_id_params->der.len = curve->oid.len;
	alg_id_params->der.value = malloc(alg_id_params->der.len);
	if(!alg_id_params->der.value)
	{
		r = SC_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	memcpy(alg_id_params->der.value, curve->oid.value, curve->oid.len);
	alg_id_params->type = 1; /* named curve */

	pubkey->alg_id = malloc(sizeof(*pubkey->alg_id));
	if(!pubkey->alg_id)
	{
		r = SC_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	pubkey->alg_id->algorithm = SC_ALGORITHM_EC;
	pubkey->alg_id->params = alg_id_params;

	/* Extract ecpointQ */
	pubkey->u.ec.ecpointQ.len = args.pubkey.ec.ecPointQ.len;
	pubkey->u.ec.ecpointQ.value = malloc(pubkey->u.ec.ecpointQ.len);
	if(!pubkey->u.ec.ecpointQ.value)
	{
		r = SC_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	memcpy(pubkey->u.ec.ecpointQ.value, args.pubkey.ec.ecPointQ.value, args.pubkey.ec.ecPointQ.len);

	/* The OID is also written to the pubkey->u.ec.params */
	pubkey->u.ec.params.der.value = malloc(alg_id_params->der.len);
	if(!pubkey->u.ec.params.der.value)
	{
		r = SC_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	memcpy(pubkey->u.ec.params.der.value, alg_id_params->der.value, alg_id_params->der.len);
	pubkey->u.ec.params.der.len = alg_id_params->der.len;
	r = sc_pkcs15_fix_ec_parameters(card->ctx, &pubkey->u.ec.params);
out:
	if(args.pubkey.ec.ecPointQ.value)
	{
		free(args.pubkey.ec.ecPointQ.value);
		args.pubkey.ec.ecPointQ.value = NULL;
	}
	if(r < 0 && pubkey)
	{
		if(pubkey->alg_id)
		{
			free(pubkey->alg_id);
			pubkey->alg_id = NULL;
		}
		if(pubkey->u.ec.params.der.value)
		{
			free(pubkey->u.ec.params.der.value);
			pubkey->u.ec.params.der.value = NULL;
			pubkey->u.ec.params.der.len = 0;
		}
		if(r < 0 && pubkey->u.ec.ecpointQ.value)
		{
			free(pubkey->u.ec.ecpointQ.value);
			pubkey->u.ec.ecpointQ.value = NULL;
			pubkey->u.ec.ecpointQ.len = 0;
		}
		memset(pubkey, 0, sizeof(sc_pkcs15_pubkey_t));
	}
	if(r < 0 && alg_id_params)
	{
		if(alg_id_params->der.value)
		{
			free(alg_id_params->der.value);
			alg_id_params->der.value = NULL;
		}
		free(alg_id_params);
		pubkey->alg_id->params = NULL;
	}
	LOG_FUNC_RETURN(card->ctx, r);
}

static int
isoApplet_generate_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
                       sc_pkcs15_object_t *obj,
                       sc_pkcs15_pubkey_t *pubkey)
{
	int r;
	sc_pkcs15_prkey_info_t *key_info = (sc_pkcs15_prkey_info_t *) obj->data;
	sc_file_t *privKeyFile=NULL;
	sc_card_t *card = p15card->card;

	LOG_FUNC_CALLED(card->ctx);

	/* Authentication stuff. */
	r = sc_profile_get_file_by_path(profile, &key_info->path, &privKeyFile);
	if(!privKeyFile)
	{
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_NOT_SUPPORTED);
	}
	r = sc_pkcs15init_authenticate(profile, p15card, privKeyFile, SC_AC_OP_CREATE_EF);
	if(r < 0)
	{
		sc_file_free(privKeyFile);
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_NOT_SUPPORTED);
	}
	sc_file_free(privKeyFile);

	/* Generate the key. */
	switch(obj->type)
	{
	case SC_PKCS15_TYPE_PRKEY_RSA:
		r = isoApplet_generate_key_rsa(key_info, card, pubkey);
		break;

	case SC_PKCS15_TYPE_PRKEY_EC:
		r = isoApplet_generate_key_ec(key_info, card, pubkey);
		break;

	default:
		r = SC_ERROR_NOT_SUPPORTED;
		sc_log(card->ctx, "%s: Key generation failed: Unknown/unsupported key type.", strerror(r));
	}

	LOG_FUNC_RETURN(card->ctx, r);
}


/*
 * Create a new key file. This is a no-op, because private keys are stored as key objects on the javacard.
 */
static int
isoApplet_create_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card, sc_pkcs15_object_t *obj)
{
	sc_card_t *card = p15card->card;
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

/*
 * Select a key reference.
 */
static int
isoApplet_select_key_reference(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
                               sc_pkcs15_prkey_info_t *key_info)
{
	int rv = SC_SUCCESS;
	sc_card_t *card = p15card->card;

	LOG_FUNC_CALLED(card->ctx);

	if(key_info->key_reference < ISOAPPLET_KEY_ID_MIN)
	{
		key_info->key_reference = ISOAPPLET_KEY_ID_MIN;
		rv = SC_SUCCESS;
	}
	if(key_info->key_reference > ISOAPPLET_KEY_ID_MAX)
	{
		rv = SC_ERROR_TOO_MANY_OBJECTS;
	}
	LOG_FUNC_RETURN(card->ctx, rv);
}

/*
 * Store a usable private key on the card.
 */
static int
isoApplet_store_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card, sc_pkcs15_object_t *object,
                    sc_pkcs15_prkey_t *key)
{
	sc_card_t *card = p15card->card;
	sc_pkcs15_prkey_info_t *key_info = (sc_pkcs15_prkey_info_t *) object->data;
	sc_file_t *privKeyFile=NULL;
	sc_cardctl_isoApplet_import_key_t args;
	int r;

	LOG_FUNC_CALLED(card->ctx);

	/* Authentication stuff. */
	r = sc_profile_get_file_by_path(profile, &key_info->path, &privKeyFile);
	if(!privKeyFile)
	{
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_NOT_SUPPORTED);
	}
	r = sc_pkcs15init_authenticate(profile, p15card, privKeyFile, SC_AC_OP_CREATE_EF);
	if(r < 0)
	{
		sc_file_free(privKeyFile);
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_NOT_SUPPORTED);
	}
	sc_file_free(privKeyFile);

	/* Key import. */
	switch(object->type)
	{
	case SC_PKCS15_TYPE_PRKEY_RSA:
		args.algorithm_ref = SC_ISOAPPLET_ALG_REF_RSA_GEN_2048;
		if(!key->u.rsa.p.data
		        ||!key->u.rsa.q.data
		        ||!key->u.rsa.iqmp.data
		        ||!key->u.rsa.dmp1.data
		        ||!key->u.rsa.dmq1.data)
		{
			LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS, "Only CRT RSA keys may be imported.");
		}
		args.privkey.rsa.p.value    = key->u.rsa.p.data;
		args.privkey.rsa.p.len      = key->u.rsa.p.len;
		args.privkey.rsa.q.value    = key->u.rsa.q.data;
		args.privkey.rsa.q.len      = key->u.rsa.q.len;
		args.privkey.rsa.iqmp.value = key->u.rsa.iqmp.data;
		args.privkey.rsa.iqmp.len   = key->u.rsa.iqmp.len;
		args.privkey.rsa.dmp1.value = key->u.rsa.dmp1.data;
		args.privkey.rsa.dmp1.len   = key->u.rsa.dmp1.len;
		args.privkey.rsa.dmq1.value = key->u.rsa.dmq1.data;
		args.privkey.rsa.dmq1.len   = key->u.rsa.dmq1.len;
		break;

	case SC_PKCS15_TYPE_PRKEY_EC:
	{
		const struct ec_curve *curve = NULL;

		args.algorithm_ref = SC_ISOAPPLET_ALG_REF_EC_GEN;
		if(key->u.ec.params.der.len == 0 || key->u.ec.params.der.value == NULL) {
			r = sc_pkcs15_fix_ec_parameters(card->ctx, &key->u.ec.params);
			LOG_TEST_RET(card->ctx, r, "EC key storing failed: Unkown curve.");
		}
		r = isoApplet_get_curve(key->u.ec.params.der.value, key->u.ec.params.der.len, &curve);
		LOG_TEST_RET(card->ctx, r, "EC key generation failed: Unsupported curve");
		args.privkey.ec.params.prime.value        = curve->prime.value;
		args.privkey.ec.params.prime.len          = curve->prime.len;
		args.privkey.ec.params.coefficientA.value = curve->coefficientA.value;
		args.privkey.ec.params.coefficientA.len   = curve->coefficientA.len;
		args.privkey.ec.params.coefficientB.value = curve->coefficientB.value;
		args.privkey.ec.params.coefficientB.len   = curve->coefficientB.len;
		args.privkey.ec.params.basePointG.value   = curve->basePointG.value;
		args.privkey.ec.params.basePointG.len     = curve->basePointG.len;
		args.privkey.ec.params.order.value        = curve->order.value;
		args.privkey.ec.params.order.len          = curve->order.len;
		args.privkey.ec.params.coFactor.value     = curve->coFactor.value;
		args.privkey.ec.params.coFactor.len       = curve->coFactor.len;
		args.privkey.ec.privateD.value            = key->u.ec.privateD.data;
		args.privkey.ec.privateD.len              = key->u.ec.privateD.len;
	}
	break;

	default:
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	}
	args.priv_key_ref = key_info->key_reference;

	r = sc_card_ctl(card, SC_CARDCTL_ISOAPPLET_IMPORT_KEY, &args);
	if (r < 0)
	{
		sc_log(card->ctx, "%s: Error in card_ctl", sc_strerror(r));
		LOG_FUNC_RETURN(card->ctx, r);
	}

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static struct sc_pkcs15init_operations sc_pkcs15init_isoApplet_operations =
{
	NULL,                           /* erase_card */
	NULL,                           /* init_card */
	isoApplet_create_dir,           /* create_dir */
	NULL,                           /* create_domain */
	isoApplet_select_pin_reference, /* pin_reference*/
	isoApplet_create_pin,           /* create_pin */
	isoApplet_select_key_reference, /* key_reference */
	isoApplet_create_key,           /* create_key */
	isoApplet_store_key,            /* store_key */
	isoApplet_generate_key,         /* generate_key */
	NULL, NULL,                     /* encode private/public key */
	NULL,                           /* finalize */
	NULL,                           /* delete_object */
	NULL, NULL, NULL, NULL, NULL,   /* pkcs15init emulation */
	NULL,                           /* sanity_check*/
};

struct
sc_pkcs15init_operations *sc_pkcs15init_get_isoApplet_ops(void)
{
	return &sc_pkcs15init_isoApplet_operations;
}
