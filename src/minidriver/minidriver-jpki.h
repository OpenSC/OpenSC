/*
 * minidriver-jpki.h: Windows minidriver adapter for JPKI cards
 *
 * Copyright (C) 2009,2010 francois.leblanc@cev-sa.com
 * Copyright (C) 2015 vincent.letoux@mysmartlogon.com
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
 *
 * This interface is private to opensc-minidriver.dll. Platform-neutral JPKI
 * APDU and PKCS#15 behavior remains in src/libopensc.
 */
#ifndef OPENSC_MINIDRIVER_JPKI_H
#define OPENSC_MINIDRIVER_JPKI_H

#ifndef __MINGW32__

#define MD_JPKI_RSA_PUBLIC_KEY_BLOB_SIZE 276

struct md_pkcs15_container;
struct md_jpki_sign_context;

BOOL md_jpki_is_card(PCARD_DATA pCardData);
BOOL md_jpki_build_card_identifier(PCARD_DATA pCardData,
		BYTE *card_identifier);
BOOL md_jpki_is_signature_container(PCARD_DATA pCardData,
		BYTE container_index, struct md_pkcs15_container **container);
BOOL md_jpki_get_signature_container_index(PCARD_DATA pCardData,
		BYTE *container_index);
DWORD md_jpki_cert_cache_encode_public_key_locked(PCARD_DATA pCardData,
		struct sc_pkcs15_der *public_key);
DWORD md_jpki_signature_certificate_encode_public_key(
		PCARD_DATA pCardData, struct md_pkcs15_container *container,
		struct sc_pkcs15_der *public_key);
DWORD md_jpki_public_key_snapshot_store(PCARD_DATA pCardData,
		const BYTE *public_key, DWORD public_key_len);
void md_jpki_prefetch_signature_certificate(PCARD_DATA pCardData);
DWORD md_jpki_restore_signature_public_key_snapshot(
		PCARD_DATA pCardData);
DWORD md_jpki_sign_prepare(PCARD_DATA pCardData, BYTE container_index,
		struct md_jpki_sign_context **context);
void md_jpki_sign_finish(PCARD_DATA pCardData,
		struct md_jpki_sign_context **context, BOOL signature_succeeded);
BOOL md_jpki_has_signature_public_key(PCARD_DATA pCardData);
void md_jpki_public_key_snapshot_clear(PCARD_DATA pCardData);

#else

static inline BOOL
md_jpki_is_card(PCARD_DATA pCardData)
{
	(void)pCardData;
	return FALSE;
}

#endif
#endif
