/*
 * Support for the eOI card
 *
 * Copyright (C) 2022 Luka Logar <luka.logar@iname.com>
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

#include <openssl/aes.h>
#include "pkcs15.h"

#define MAX_OBJECTS 8

struct eoi_privdata {
	/* App version */
	char version[10];
	/* Serial + encrypted CAN */
	struct sc_pkcs15_u8 enc_can;
	/* CAN from the conf file */
	char can[AES_BLOCK_SIZE];
	/* Cached data for signing operation */
	size_t key_len;
	struct sc_security_env sec_env;
	int se_num;
	/* PINs that shouldn't report an error when selected */
	struct sc_path *pin_paths[MAX_OBJECTS];
	/* PrKey reference to eOI mappings */
	int prkey_mappings[MAX_OBJECTS][2];
};
