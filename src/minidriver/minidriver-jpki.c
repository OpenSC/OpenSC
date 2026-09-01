/*
 * minidriver-jpki.c: Windows minidriver compatibility for JPKI cards
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
 * Platform-neutral card and PKCS#15 behavior belongs in src/libopensc.
 * This module contains only Windows KSP, certificate-store, and smart-card
 * resource-manager integration.
 */

#include "config.h"
#ifdef ENABLE_MINIDRIVER
#ifndef __MINGW32__

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <windows.h>

#include "libopensc/internal.h"
#include "libopensc/opensc.h"
#include "libopensc/pkcs15.h"

#include "cardmod.h"
#include "minidriver-jpki.h"
#include "minidriver-private.h"

#define MD_JPKI_CARD_FINGERPRINT_SIZE	    32
#define MD_JPKI_RSA_MODULUS_BITS	    2048
#define MD_JPKI_RSA_MODULUS_SIZE	    (MD_JPKI_RSA_MODULUS_BITS / 8)
#define MD_JPKI_RSA1_MAGIC		    0x31415352UL
#define MD_JPKI_CACHE_MAGIC_SIZE	    8
#define MD_JPKI_CACHE_FRESHNESS		    1
#define MD_JPKI_RSA_PUBLIC_KEY_DER_MAX_SIZE 1024
#define MD_JPKI_CERTIFICATE_CACHE_VERSION   2
#define MD_JPKI_CERTIFICATE_CACHE_MAX_SIZE  (64 * 1024)
#define MD_JPKI_CERTIFICATE_CACHE_TTL_100NS \
	(90ULL * 24ULL * 60ULL * 60ULL * 10000000ULL)
#define MD_JPKI_CERT_VALIDITY_START_SKEW_100NS \
	(60ULL * 10000000ULL)
#define MD_JPKI_PROCESS_CACHE_MAX_ENTRIES 8

struct md_jpki_cert_cache_key {
	BYTE card_fingerprint[MD_JPKI_CARD_FINGERPRINT_SIZE];
};

/* Serialized public-certificate data stored by the Windows Smart Card
 * Resource Manager. Only the live authentication-certificate fingerprint is
 * card identity; ATR is transport metadata and deliberately is not persisted. */
struct md_jpki_certificate_cache_header {
	BYTE magic[MD_JPKI_CACHE_MAGIC_SIZE];
	DWORD version;
	BYTE card_fingerprint[MD_JPKI_CARD_FINGERPRINT_SIZE];
	FILETIME expires_at;
	DWORD certificate_len;
};

struct md_jpki_rsa_public_key_blob {
	PUBLICKEYSTRUC publickeystruc;
	RSAPUBKEY rsapubkey;
	BYTE modulus[MD_JPKI_RSA_MODULUS_SIZE];
};

typedef char md_jpki_certificate_cache_header_size_must_be_56[(sizeof(struct md_jpki_certificate_cache_header) == 56) ? 1 : -1];
typedef char md_jpki_certificate_cache_expiration_offset_must_be_44[(offsetof(struct md_jpki_certificate_cache_header, expires_at) == 44) ? 1 : -1];
typedef char md_jpki_certificate_cache_length_offset_must_be_52[(offsetof(struct md_jpki_certificate_cache_header, certificate_len) == 52) ? 1 : -1];
typedef char md_jpki_rsa_blob_size_must_be_276[(sizeof(struct md_jpki_rsa_public_key_blob) ==
							       MD_JPKI_RSA_PUBLIC_KEY_BLOB_SIZE)
							       ? 1
							       : -1];

static const BYTE md_jpki_certificate_cache_magic[MD_JPKI_CACHE_MAGIC_SIZE] = {
		'O', 'S', 'J', 'P', 'K', 'I', 'C', 'T'};
static const WCHAR md_jpki_certificate_cache_tag[] =
		L"OpenSC.JPKI.SignatureCertificate.v2";

struct md_jpki_process_cache_entry {
	struct md_jpki_cert_cache_key key;
	BYTE *certificate;
	DWORD certificate_len;
	FILETIME expires_at;
	ULONGLONG sequence;
};

static SRWLOCK md_jpki_process_cache_lock = SRWLOCK_INIT;
static struct md_jpki_process_cache_entry
		md_jpki_process_cache[MD_JPKI_PROCESS_CACHE_MAX_ENTRIES];
static ULONGLONG md_jpki_process_cache_sequence;

static DWORD md_jpki_cert_cache_copy_to_file_locked(
		PCARD_DATA pCardData, struct md_file *file);

struct md_jpki_state {
	BYTE *signature_public_key;
	DWORD signature_public_key_len;
};

struct md_jpki_sign_context {
	struct sc_pkcs15_cert *certificate;
	int saved_use_pin_cache;
	BOOL pin_cache_disabled;
	BOOL card_lock_held;
};

static struct md_jpki_state *
md_jpki_get_state(PCARD_DATA pCardData, BOOL create)
{
	VENDOR_SPECIFIC *vs = pCardData ? (VENDOR_SPECIFIC *)pCardData->pvVendorSpecific : NULL;

	if (!vs)
		return NULL;
	if (!vs->jpki && create)
		vs->jpki = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
				sizeof(*vs->jpki));
	return vs->jpki;
}

static void
md_jpki_public_key_snapshot_reset(struct md_jpki_state *state)
{
	if (!state)
		return;
	if (state->signature_public_key) {
		SecureZeroMemory(state->signature_public_key,
				state->signature_public_key_len);
		HeapFree(GetProcessHeap(), 0, state->signature_public_key);
	}
	state->signature_public_key = NULL;
	state->signature_public_key_len = 0;
}

BOOL
md_jpki_is_card(PCARD_DATA pCardData)
{
	VENDOR_SPECIFIC *vs = pCardData ? (VENDOR_SPECIFIC *)pCardData->pvVendorSpecific : NULL;

	return vs && vs->card && vs->card->type == SC_CARD_TYPE_JPKI_BASE;
}

static struct sc_pkcs15_object *
md_jpki_find_auth_certificate_object(VENDOR_SPECIFIC *vs)
{
	struct sc_pkcs15_object *cert_objects[MD_MAX_KEY_CONTAINERS];
	struct sc_pkcs15_object *auth_object = NULL;
	int cert_count, index;

	if (!vs || !vs->p15card)
		return NULL;
	cert_count = sc_pkcs15_get_objects(vs->p15card,
			SC_PKCS15_TYPE_CERT_X509, cert_objects, ARRAYSIZE(cert_objects));
	if (cert_count < 0)
		return NULL;
	for (index = 0; index < cert_count; index++) {
		struct sc_pkcs15_cert_info *cert_info =
				(struct sc_pkcs15_cert_info *)cert_objects[index]->data;

		if (!cert_info || cert_info->authority ||
				(cert_objects[index]->flags & SC_PKCS15_CO_FLAG_PRIVATE))
			continue;
		if (auth_object)
			return NULL;
		auth_object = cert_objects[index];
	}
	return auth_object;
}

BOOL
md_jpki_build_card_identifier(PCARD_DATA pCardData,
		BYTE card_identifier[MD_CARDID_SIZE])
{
	VENDOR_SPECIFIC *vs = pCardData ? (VENDOR_SPECIFIC *)pCardData->pvVendorSpecific : NULL;
	struct sc_pkcs15_object *auth_object;
	struct sc_pkcs15_cert_info *auth_info;
	struct sc_pkcs15_cert *certificate = NULL;
	BYTE digest[MD_JPKI_CARD_FINGERPRINT_SIZE] = {0};
	DWORD digest_len = sizeof(digest);
	int rv;
	BOOL result = FALSE;

	if (!vs || !vs->p15card || !md_jpki_is_card(pCardData) ||
			!card_identifier)
		return FALSE;
	auth_object = md_jpki_find_auth_certificate_object(vs);
	if (!auth_object || !auth_object->data)
		goto out;
	auth_info = (struct sc_pkcs15_cert_info *)auth_object->data;
	rv = sc_pkcs15_read_certificate(vs->p15card, auth_info, 0,
			&certificate);
	if (rv != SC_SUCCESS || !certificate || !certificate->data.value ||
			!certificate->data.len || certificate->data.len > MAXDWORD)
		goto out;
	if (!CryptHashCertificate(0, CALG_SHA_256, 0,
			    certificate->data.value, (DWORD)certificate->data.len,
			    digest, &digest_len) ||
			digest_len != sizeof(digest))
		goto out;

	CopyMemory(card_identifier, digest, MD_CARDID_SIZE);
	result = TRUE;

out:
	if (certificate)
		sc_pkcs15_free_certificate(certificate);
	SecureZeroMemory(digest, sizeof(digest));
	return result;
}

/* JPKI protects the signature certificate and public key with its signature
 * PIN, although Windows requires the public key before it can request that
 * PIN.  The compatibility path below is restricted to the JPKI signature
 * container and never collects credentials itself. */
BOOL
md_jpki_is_signature_container(PCARD_DATA pCardData,
		BYTE bContainerIndex,
		struct md_pkcs15_container **container)
{
	VENDOR_SPECIFIC *vs = NULL;
	struct md_pkcs15_container *cont = NULL;
	struct sc_pkcs15_object *sign_pin = NULL;
	struct sc_pkcs15_auth_info *sign_pin_info = NULL;

	if (container)
		*container = NULL;
	if (!pCardData || bContainerIndex >= MD_MAX_KEY_CONTAINERS)
		return FALSE;

	vs = (VENDOR_SPECIFIC *)pCardData->pvVendorSpecific;
	if (!vs || !vs->p15card || !md_jpki_is_card(pCardData))
		return FALSE;

	cont = &vs->p15_containers[bContainerIndex];
	sign_pin = vs->pin_objs[MD_ROLE_USER_SIGN];
	if (!cont->prkey_obj || !cont->prkey_obj->data ||
			(!cont->pubkey_obj && !cont->cert_obj) ||
			!sign_pin || !sign_pin->data)
		return FALSE;

	sign_pin_info = (struct sc_pkcs15_auth_info *)sign_pin->data;
	if (!cont->prkey_obj->auth_id.len || !sign_pin_info->auth_id.len ||
			!sc_pkcs15_compare_id(&cont->prkey_obj->auth_id,
					&sign_pin_info->auth_id))
		return FALSE;
	if (cont->pubkey_obj &&
			(!cont->pubkey_obj->auth_id.len ||
					!sc_pkcs15_compare_id(&cont->pubkey_obj->auth_id,
							&cont->prkey_obj->auth_id)))
		return FALSE;
	if (cont->cert_obj &&
			(!cont->cert_obj->auth_id.len ||
					!sc_pkcs15_compare_id(&cont->cert_obj->auth_id,
							&cont->prkey_obj->auth_id)))
		return FALSE;

	if (container)
		*container = cont;
	return TRUE;
}

BOOL
md_jpki_get_signature_container_index(PCARD_DATA pCardData,
		BYTE *container_index)
{
	BYTE index;
	BOOL found = FALSE;

	if (!container_index)
		return FALSE;
	for (index = 0; index < MD_MAX_KEY_CONTAINERS; index++) {
		if (!md_jpki_is_signature_container(pCardData, index, NULL))
			continue;
		if (found)
			return FALSE;
		*container_index = index;
		found = TRUE;
	}
	return found;
}

static BOOL
md_jpki_cert_cache_key_matches(const struct md_jpki_cert_cache_key *left,
		const struct md_jpki_cert_cache_key *right)
{
	/* The full SHA-256 of the live, unprotected authentication certificate is
	 * the card identity.  ATR is reader/transport metadata and was observed to
	 * change length across a PC/SC reset for the same certificate. */
	return left && right &&
	       memcmp(left->card_fingerprint, right->card_fingerprint,
			       MD_JPKI_CARD_FINGERPRINT_SIZE) == 0;
}

static BOOL
md_jpki_rsa_public_key_der_is_valid(const BYTE *public_key,
		DWORD public_key_len)
{
	struct md_jpki_rsa_public_key_blob csp_blob;
	BYTE canonical_der[MD_JPKI_RSA_PUBLIC_KEY_DER_MAX_SIZE];
	DWORD csp_blob_len = sizeof(csp_blob);
	DWORD canonical_der_len = sizeof(canonical_der);
	BOOL result = FALSE;

	SecureZeroMemory(&csp_blob, sizeof(csp_blob));
	SecureZeroMemory(canonical_der, sizeof(canonical_der));
	if (!public_key || !public_key_len ||
			public_key_len > MD_JPKI_RSA_PUBLIC_KEY_DER_MAX_SIZE ||
			!CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
					RSA_CSP_PUBLICKEYBLOB, public_key, public_key_len, 0,
					&csp_blob, &csp_blob_len) ||
			csp_blob_len != sizeof(csp_blob))
		goto out;

	if (csp_blob.publickeystruc.bType != PUBLICKEYBLOB ||
			csp_blob.publickeystruc.bVersion != CUR_BLOB_VERSION ||
			csp_blob.publickeystruc.reserved != 0 ||
			(csp_blob.publickeystruc.aiKeyAlg != CALG_RSA_SIGN &&
					csp_blob.publickeystruc.aiKeyAlg != CALG_RSA_KEYX) ||
			csp_blob.rsapubkey.magic != MD_JPKI_RSA1_MAGIC ||
			csp_blob.rsapubkey.bitlen != MD_JPKI_RSA_MODULUS_BITS ||
			csp_blob.rsapubkey.pubexp < 3 ||
			!(csp_blob.rsapubkey.pubexp & 1) ||
			!(csp_blob.modulus[0] & 1) ||
			!(csp_blob.modulus[MD_JPKI_RSA_MODULUS_SIZE - 1] & 0x80))
		goto out;

	/* CryptDecodeObject accepts a valid RSAPublicKey followed by trailing
	 * bytes.  Re-encode the decoded blob and require one canonical, fully
	 * consumed DER value before trusting cache data or taking a snapshot. */
	if (!CryptEncodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
			    RSA_CSP_PUBLICKEYBLOB, &csp_blob, canonical_der,
			    &canonical_der_len) ||
			canonical_der_len != public_key_len ||
			memcmp(canonical_der, public_key, public_key_len) != 0)
		goto out;

	result = TRUE;

out:
	SecureZeroMemory(&csp_blob, sizeof(csp_blob));
	SecureZeroMemory(canonical_der, sizeof(canonical_der));
	return result;
}

static BOOL
md_jpki_cache_get_expiration(const FILETIME *certificate_not_after,
		FILETIME *expires_at)
{
	FILETIME now;
	ULARGE_INTEGER now_value, expiry_value, certificate_value;

	if (!certificate_not_after || !expires_at)
		return FALSE;
	GetSystemTimeAsFileTime(&now);
	now_value.LowPart = now.dwLowDateTime;
	now_value.HighPart = now.dwHighDateTime;
	certificate_value.LowPart = certificate_not_after->dwLowDateTime;
	certificate_value.HighPart = certificate_not_after->dwHighDateTime;
	if (certificate_value.QuadPart <= now_value.QuadPart)
		return FALSE;

	expiry_value.QuadPart =
			now_value.QuadPart + MD_JPKI_CERTIFICATE_CACHE_TTL_100NS;
	if (certificate_value.QuadPart < expiry_value.QuadPart)
		expiry_value.QuadPart = certificate_value.QuadPart;
	expires_at->dwLowDateTime = expiry_value.LowPart;
	expires_at->dwHighDateTime = expiry_value.HighPart;
	return TRUE;
}

static BOOL
md_jpki_cache_is_unexpired(const FILETIME *expires_at)
{
	FILETIME now;

	if (!expires_at)
		return FALSE;
	GetSystemTimeAsFileTime(&now);
	return CompareFileTime(expires_at, &now) > 0;
}

static struct md_jpki_process_cache_entry *
md_jpki_process_cache_find_locked(
		const struct md_jpki_cert_cache_key *key)
{
	size_t index;

	for (index = 0; index < ARRAYSIZE(md_jpki_process_cache); index++) {
		struct md_jpki_process_cache_entry *entry =
				&md_jpki_process_cache[index];

		if (entry->certificate &&
				md_jpki_cache_is_unexpired(&entry->expires_at) &&
				md_jpki_cert_cache_key_matches(&entry->key, key))
			return entry;
	}
	return NULL;
}

static DWORD
md_jpki_process_cache_store(const struct md_jpki_cert_cache_key *key,
		const BYTE *certificate, DWORD certificate_len,
		const FILETIME *expires_at)
{
	struct md_jpki_process_cache_entry *entry = NULL;
	BYTE *copy, *old_certificate = NULL;
	DWORD old_certificate_len = 0;
	size_t index;

	if (!key || !certificate || !certificate_len || !expires_at ||
			!md_jpki_cache_is_unexpired(expires_at))
		return SCARD_E_INVALID_VALUE;
	copy = HeapAlloc(GetProcessHeap(), 0, certificate_len);
	if (!copy)
		return SCARD_E_NO_MEMORY;
	CopyMemory(copy, certificate, certificate_len);

	AcquireSRWLockExclusive(&md_jpki_process_cache_lock);
	entry = md_jpki_process_cache_find_locked(key);
	if (!entry) {
		for (index = 0; index < ARRAYSIZE(md_jpki_process_cache);
				index++) {
			struct md_jpki_process_cache_entry *candidate =
					&md_jpki_process_cache[index];

			if (!candidate->certificate ||
					!md_jpki_cache_is_unexpired(
							&candidate->expires_at)) {
				entry = candidate;
				break;
			}
			if (!entry || candidate->sequence < entry->sequence)
				entry = candidate;
		}
	}
	if (entry) {
		old_certificate = entry->certificate;
		old_certificate_len = entry->certificate_len;
		CopyMemory(&entry->key, key, sizeof(entry->key));
		entry->certificate = copy;
		entry->certificate_len = certificate_len;
		CopyMemory(&entry->expires_at, expires_at,
				sizeof(entry->expires_at));
		entry->sequence = ++md_jpki_process_cache_sequence;
		copy = NULL;
	}
	ReleaseSRWLockExclusive(&md_jpki_process_cache_lock);

	if (old_certificate) {
		SecureZeroMemory(old_certificate, old_certificate_len);
		HeapFree(GetProcessHeap(), 0, old_certificate);
	}
	if (copy)
		HeapFree(GetProcessHeap(), 0, copy);
	return entry ? SCARD_S_SUCCESS : SCARD_E_NO_MEMORY;
}

static DWORD
md_jpki_process_cache_copy(PCARD_DATA pCardData,
		const struct md_jpki_cert_cache_key *key, BYTE **certificate,
		DWORD *certificate_len)
{
	struct md_jpki_process_cache_entry *entry;
	BYTE *copy = NULL;
	DWORD copy_len = 0;

	if (!pCardData || !pCardData->pfnCspAlloc || !key ||
			!certificate || !certificate_len)
		return SCARD_E_INVALID_PARAMETER;
	*certificate = NULL;
	*certificate_len = 0;

	AcquireSRWLockShared(&md_jpki_process_cache_lock);
	entry = md_jpki_process_cache_find_locked(key);
	if (entry) {
		copy_len = entry->certificate_len;
		copy = pCardData->pfnCspAlloc(copy_len);
		if (copy)
			CopyMemory(copy, entry->certificate, copy_len);
	}
	ReleaseSRWLockShared(&md_jpki_process_cache_lock);

	if (!copy)
		return copy_len ? SCARD_E_NO_MEMORY : SCARD_E_FILE_NOT_FOUND;
	*certificate = copy;
	*certificate_len = copy_len;
	return SCARD_S_SUCCESS;
}

static PCCERT_CONTEXT
md_jpki_process_cache_certificate_context(
		const struct md_jpki_cert_cache_key *key)
{
	struct md_jpki_process_cache_entry *entry;
	PCCERT_CONTEXT certificate = NULL;

	AcquireSRWLockShared(&md_jpki_process_cache_lock);
	entry = md_jpki_process_cache_find_locked(key);
	if (entry)
		certificate = CertCreateCertificateContext(X509_ASN_ENCODING,
				entry->certificate, entry->certificate_len);
	ReleaseSRWLockShared(&md_jpki_process_cache_lock);
	return certificate;
}

static BOOL
md_jpki_certificate_cache_header_is_valid(const BYTE *cache_data,
		DWORD cache_len, const struct md_jpki_cert_cache_key *key)
{
	const struct md_jpki_certificate_cache_header *header;

	if (!cache_data || !key ||
			cache_len < sizeof(struct md_jpki_certificate_cache_header))
		return FALSE;
	header = (const struct md_jpki_certificate_cache_header *)cache_data;
	return memcmp(header->magic, md_jpki_certificate_cache_magic,
			       sizeof(header->magic)) == 0 &&
	       header->version == MD_JPKI_CERTIFICATE_CACHE_VERSION &&
	       memcmp(header->card_fingerprint, key->card_fingerprint,
			       sizeof(header->card_fingerprint)) == 0 &&
	       md_jpki_cache_is_unexpired(&header->expires_at) &&
	       header->certificate_len > 0 &&
	       header->certificate_len <= MD_JPKI_CERTIFICATE_CACHE_MAX_SIZE &&
	       (SIZE_T)cache_len == sizeof(*header) +
						    (SIZE_T)header->certificate_len;
}

void
md_jpki_public_key_snapshot_clear(PCARD_DATA pCardData)
{
	VENDOR_SPECIFIC *vs = pCardData ? (VENDOR_SPECIFIC *)pCardData->pvVendorSpecific : NULL;

	if (!vs || !vs->jpki)
		return;
	md_jpki_public_key_snapshot_reset(vs->jpki);
	HeapFree(GetProcessHeap(), 0, vs->jpki);
	vs->jpki = NULL;
}

BOOL
md_jpki_has_signature_public_key(PCARD_DATA pCardData)
{
	struct md_jpki_state *state = md_jpki_get_state(pCardData, FALSE);

	return state && state->signature_public_key &&
	       state->signature_public_key_len;
}

DWORD
md_jpki_public_key_snapshot_store(PCARD_DATA pCardData,
		const BYTE *public_key, DWORD public_key_len)
{
	struct md_jpki_state *state;
	BYTE *copy;

	if (!md_jpki_rsa_public_key_der_is_valid(public_key, public_key_len))
		return SCARD_E_INVALID_VALUE;
	state = md_jpki_get_state(pCardData, TRUE);
	if (!state)
		return SCARD_E_NO_MEMORY;
	copy = HeapAlloc(GetProcessHeap(), 0, public_key_len);
	if (!copy)
		return SCARD_E_NO_MEMORY;
	CopyMemory(copy, public_key, public_key_len);
	md_jpki_public_key_snapshot_reset(state);
	state->signature_public_key = copy;
	state->signature_public_key_len = public_key_len;
	return SCARD_S_SUCCESS;
}

static void
md_jpki_cache_identifier(
		const struct md_jpki_cert_cache_key *key, UUID *identifier)
{
	/* The full SHA-256 fingerprint is also stored in and checked against the
	 * payload.  The first 128 fingerprint bits merely provide the UUID-sized
	 * namespace required by the Windows smart-card global cache. */
	CopyMemory(identifier, key->card_fingerprint, sizeof(*identifier));
}

static DWORD
md_jpki_certificate_cache_store_global(PCARD_DATA pCardData,
		const struct md_jpki_cert_cache_key *key,
		const BYTE *certificate, DWORD certificate_len,
		const FILETIME *expires_at)
{
	struct md_jpki_certificate_cache_header *header = NULL;
	PCCERT_CONTEXT cert_context = NULL;
	PCERT_PUBLIC_KEY_INFO public_key;
	UUID identifier;
	SIZE_T cache_len = 0;
	LONG rv = SCARD_E_INVALID_VALUE;

	if (!pCardData || !pCardData->hSCardCtx || !key ||
			!certificate || !certificate_len ||
			certificate_len > MD_JPKI_CERTIFICATE_CACHE_MAX_SIZE ||
			!expires_at || !md_jpki_cache_is_unexpired(expires_at))
		return SCARD_E_INVALID_VALUE;
	cert_context = CertCreateCertificateContext(X509_ASN_ENCODING,
			certificate, certificate_len);
	if (!cert_context)
		return SCARD_E_INVALID_VALUE;
	public_key = &cert_context->pCertInfo->SubjectPublicKeyInfo;
	if (!public_key->PublicKey.pbData || public_key->PublicKey.cUnusedBits ||
			!md_jpki_rsa_public_key_der_is_valid(public_key->PublicKey.pbData,
					public_key->PublicKey.cbData))
		goto out;

	cache_len = sizeof(*header) + (SIZE_T)certificate_len;
	header = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cache_len);
	if (!header) {
		rv = SCARD_E_NO_MEMORY;
		goto out;
	}
	CopyMemory(header->magic, md_jpki_certificate_cache_magic,
			sizeof(header->magic));
	header->version = MD_JPKI_CERTIFICATE_CACHE_VERSION;
	CopyMemory(header->card_fingerprint, key->card_fingerprint,
			sizeof(header->card_fingerprint));
	CopyMemory(&header->expires_at, expires_at,
			sizeof(header->expires_at));
	header->certificate_len = certificate_len;
	CopyMemory((BYTE *)header + sizeof(*header), certificate,
			certificate_len);
	md_jpki_cache_identifier(key, &identifier);

	rv = SCardWriteCacheW(pCardData->hSCardCtx, &identifier,
			MD_JPKI_CACHE_FRESHNESS,
			(LPWSTR)md_jpki_certificate_cache_tag, (PBYTE)header,
			(DWORD)cache_len);
	if (rv != SCARD_S_SUCCESS)
		logprintf(pCardData, 2,
				"JPKI signature-certificate global cache write skipped: "
				"0x%08lX\n",
				(unsigned long)rv);

	SecureZeroMemory(&identifier, sizeof(identifier));

out:
	if (header) {
		SecureZeroMemory(header, cache_len);
		HeapFree(GetProcessHeap(), 0, header);
	}
	if (cert_context)
		CertFreeCertificateContext(cert_context);
	return (DWORD)rv;
}

/* Always re-read the unprotected authentication certificate.
 * A virtual-file copy can belong to a card that was exchanged after this
 * context was created, so it is not sufficient for a cross-process key. */
static BOOL
md_get_jpki_live_card_key_and_certificate(PCARD_DATA pCardData,
		struct md_jpki_cert_cache_key *key,
		PCCERT_CONTEXT *auth_certificate)
{
	VENDOR_SPECIFIC *vs = pCardData ? (VENDOR_SPECIFIC *)pCardData->pvVendorSpecific : NULL;
	struct sc_pkcs15_object *auth_object;
	struct sc_pkcs15_cert *certificate = NULL;
	DWORD fingerprint_len;
	int debug, use_file_cache, rv;
	BOOL card_locked = FALSE;
	BOOL result = FALSE;

	if (auth_certificate)
		*auth_certificate = NULL;
	if (!vs || !vs->p15card || !vs->ctx || !key)
		return FALSE;
	auth_object = md_jpki_find_auth_certificate_object(vs);
	if (!auth_object || !auth_object->data)
		return FALSE;

	rv = sc_lock(vs->p15card->card);
	if (rv != SC_SUCCESS)
		return FALSE;
	card_locked = TRUE;
	debug = vs->ctx->debug;
	use_file_cache = vs->p15card->opts.use_file_cache;
	vs->ctx->debug = 0;
	vs->p15card->opts.use_file_cache = SC_PKCS15_OPTS_CACHE_NO_FILES;
	rv = sc_pkcs15_read_certificate(vs->p15card,
			(struct sc_pkcs15_cert_info *)auth_object->data, 0, &certificate);
	vs->p15card->opts.use_file_cache = use_file_cache;
	vs->ctx->debug = debug;
	if (rv != SC_SUCCESS || !certificate || !certificate->data.value ||
			!certificate->data.len || certificate->data.len > MAXDWORD)
		goto out;
	SecureZeroMemory(key, sizeof(*key));
	fingerprint_len = sizeof(key->card_fingerprint);
	if (!CryptHashCertificate(0, CALG_SHA_256, 0,
			    certificate->data.value, (DWORD)certificate->data.len,
			    key->card_fingerprint, &fingerprint_len) ||
			fingerprint_len != sizeof(key->card_fingerprint)) {
		SecureZeroMemory(key, sizeof(*key));
		goto out;
	}
	if (auth_certificate) {
		*auth_certificate = CertCreateCertificateContext(X509_ASN_ENCODING,
				certificate->data.value, (DWORD)certificate->data.len);
		if (!*auth_certificate) {
			SecureZeroMemory(key, sizeof(*key));
			goto out;
		}
	}
	result = TRUE;

out:
	if (certificate)
		sc_pkcs15_free_certificate(certificate);
	if (card_locked)
		(void)sc_unlock(vs->p15card->card);
	return result;
}

static BOOL
md_get_jpki_live_card_key(PCARD_DATA pCardData,
		struct md_jpki_cert_cache_key *key)
{
	return md_get_jpki_live_card_key_and_certificate(pCardData, key, NULL);
}

/* Windows can create several minidriver contexts while enumerating one card.
 * Cache only the public signature certificate DER so later contexts can expose
 * the same key without reading the protected object again.  JPKI exposes only
 * a dummy token serial, so use the full SHA-256 of its unprotected
 * authentication certificate as the cross-context card identity. */
static DWORD
md_jpki_cert_cache_store(PCARD_DATA pCardData, const BYTE *cert,
		size_t cert_len)
{
	struct md_jpki_cert_cache_key key;
	PCCERT_CONTEXT cert_context = NULL;
	PCERT_PUBLIC_KEY_INFO certificate_public_key = NULL;
	DWORD ret;
	FILETIME expires_at;

	if (!cert || !cert_len || cert_len > MAXDWORD ||
			cert_len > MD_JPKI_CERTIFICATE_CACHE_MAX_SIZE)
		return SCARD_E_INVALID_VALUE;

	cert_context = CertCreateCertificateContext(X509_ASN_ENCODING,
			cert, (DWORD)cert_len);
	if (!cert_context)
		return SCARD_E_INVALID_VALUE;
	certificate_public_key =
			&cert_context->pCertInfo->SubjectPublicKeyInfo;
	if (!certificate_public_key->PublicKey.pbData ||
			certificate_public_key->PublicKey.cUnusedBits ||
			!md_jpki_rsa_public_key_der_is_valid(
					certificate_public_key->PublicKey.pbData,
					certificate_public_key->PublicKey.cbData) ||
			!md_jpki_cache_get_expiration(
					&cert_context->pCertInfo->NotAfter, &expires_at) ||
			!md_get_jpki_live_card_key(pCardData, &key)) {
		CertFreeCertificateContext(cert_context);
		return SCARD_E_INVALID_VALUE;
	}

	ret = md_jpki_process_cache_store(&key, cert, (DWORD)cert_len,
			&expires_at);
	if (ret != SCARD_S_SUCCESS) {
		SecureZeroMemory(&key, sizeof(key));
		CertFreeCertificateContext(cert_context);
		return ret;
	}
	/* CardGetContainerInfo must succeed before Windows can select this key and
	 * request its PIN.  Persist only the complete public certificate; its RSA
	 * public key is derived from that same validated object. */
	(void)md_jpki_certificate_cache_store_global(pCardData, &key,
			cert, (DWORD)cert_len, &expires_at);
	SecureZeroMemory(&key, sizeof(key));
	CertFreeCertificateContext(cert_context);
	/* Once the process-local public certificate cache is valid, a Resource
	 * Manager global-cache write failure is advisory.
	 * Enumeration and KSP binding must not disappear merely because
	 * SCardWriteCacheW is unavailable for this host process. */
	return SCARD_S_SUCCESS;
}

/* Windows requires CardGetContainerInfo to succeed before collecting a PIN.
 * JPKI is unusual because both the signature certificate and its public key
 * are protected by the signature PIN.  If the user has already imported that
 * public certificate, use it only as a one-time KSP bootstrap.  Selection is
 * deliberately fail-closed: the certificate must be the unique, currently
 * valid RSA signature/non-repudiation certificate issued for exactly the same
 * validity interval as the live card's unprotected authentication certificate.
 * CardSignData still compares this public key with the protected certificate
 * read from the live card after Windows authenticates role 3. */
static BOOL
md_jpki_is_user_store_signature_candidate(
		PCCERT_CONTEXT auth_certificate, PCCERT_CONTEXT candidate)
{
	BYTE intended_usage[2] = {0};
	PCERT_EXTENSION key_usage_extension;
	PCERT_PUBLIC_KEY_INFO public_key;
	ULARGE_INTEGER auth_not_before, candidate_not_before;
	ULONGLONG not_before_skew;

	if (!auth_certificate || !candidate || !candidate->pCertInfo ||
			candidate->cbCertEncoded == auth_certificate->cbCertEncoded &&
					memcmp(candidate->pbCertEncoded, auth_certificate->pbCertEncoded,
							candidate->cbCertEncoded) == 0)
		return FALSE;
	auth_not_before.LowPart = auth_certificate->pCertInfo->NotBefore.dwLowDateTime;
	auth_not_before.HighPart = auth_certificate->pCertInfo->NotBefore.dwHighDateTime;
	candidate_not_before.LowPart = candidate->pCertInfo->NotBefore.dwLowDateTime;
	candidate_not_before.HighPart = candidate->pCertInfo->NotBefore.dwHighDateTime;
	not_before_skew = auth_not_before.QuadPart > candidate_not_before.QuadPart ? auth_not_before.QuadPart - candidate_not_before.QuadPart : candidate_not_before.QuadPart - auth_not_before.QuadPart;
	/* JPKI issues the authentication and signature certificates as one card
	 * personalization transaction, but their NotBefore timestamps can differ by
	 * a few seconds.  Keep the match bounded and fail closed on ambiguity. */
	if (not_before_skew > MD_JPKI_CERT_VALIDITY_START_SKEW_100NS ||
			CompareFileTime(&candidate->pCertInfo->NotAfter,
					&auth_certificate->pCertInfo->NotAfter) != 0 ||
			CertVerifyTimeValidity(NULL, candidate->pCertInfo) != 0)
		return FALSE;
	key_usage_extension = CertFindExtension(szOID_KEY_USAGE,
			candidate->pCertInfo->cExtension,
			candidate->pCertInfo->rgExtension);
	if (!key_usage_extension ||
			!CertGetIntendedKeyUsage(X509_ASN_ENCODING,
					candidate->pCertInfo, intended_usage, sizeof(intended_usage)) ||
			(intended_usage[0] & (CERT_DIGITAL_SIGNATURE_KEY_USAGE |
							     CERT_NON_REPUDIATION_KEY_USAGE)) !=
					(CERT_DIGITAL_SIGNATURE_KEY_USAGE |
							CERT_NON_REPUDIATION_KEY_USAGE))
		return FALSE;
	public_key = &candidate->pCertInfo->SubjectPublicKeyInfo;
	return public_key->Algorithm.pszObjId &&
	       strcmp(public_key->Algorithm.pszObjId, szOID_RSA_RSA) == 0 &&
	       public_key->PublicKey.pbData && !public_key->PublicKey.cUnusedBits &&
	       md_jpki_rsa_public_key_der_is_valid(public_key->PublicKey.pbData,
			       public_key->PublicKey.cbData);
}

static DWORD
md_jpki_certificate_cache_load_global(PCARD_DATA pCardData)
{
	struct md_jpki_cert_cache_key key;
	struct md_jpki_certificate_cache_header *header = NULL;
	PCCERT_CONTEXT auth_certificate = NULL;
	PCCERT_CONTEXT candidate = NULL;
	UUID identifier;
	BYTE *cache_data = NULL;
	DWORD cache_capacity = sizeof(*header) +
			       MD_JPKI_CERTIFICATE_CACHE_MAX_SIZE;
	DWORD cache_len = cache_capacity;
	DWORD ret = SCARD_E_FILE_NOT_FOUND;
	LONG rv;

	SecureZeroMemory(&key, sizeof(key));
	SecureZeroMemory(&identifier, sizeof(identifier));
	if (!pCardData || !pCardData->hSCardCtx ||
			!md_get_jpki_live_card_key_and_certificate(pCardData, &key,
					&auth_certificate))
		goto out;
	cache_data = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
			cache_capacity);
	if (!cache_data) {
		ret = SCARD_E_NO_MEMORY;
		goto out;
	}
	header = (struct md_jpki_certificate_cache_header *)cache_data;
	md_jpki_cache_identifier(&key, &identifier);
	rv = SCardReadCacheW(pCardData->hSCardCtx, &identifier,
			MD_JPKI_CACHE_FRESHNESS,
			(LPWSTR)md_jpki_certificate_cache_tag, cache_data, &cache_len);
	if (rv != SCARD_S_SUCCESS) {
		logprintf(pCardData, 3,
				"JPKI signature-certificate global cache unavailable: "
				"0x%08lX\n",
				(unsigned long)rv);
		ret = (DWORD)rv;
		goto out;
	}

	if (!md_jpki_certificate_cache_header_is_valid(cache_data, cache_len,
			    &key)) {
		logprintf(pCardData, 2,
				"JPKI signature-certificate global cache rejected\n");
		ret = SCARD_E_INVALID_VALUE;
		goto out;
	}

	candidate = CertCreateCertificateContext(X509_ASN_ENCODING,
			cache_data + sizeof(*header), header->certificate_len);
	if (!candidate ||
			!md_jpki_is_user_store_signature_candidate(auth_certificate,
					candidate)) {
		logprintf(pCardData, 2,
				"JPKI signature-certificate global cache did not match the "
				"live card\n");
		ret = SCARD_E_INVALID_VALUE;
		goto out;
	}

	ret = md_jpki_cert_cache_store(pCardData,
			cache_data + sizeof(*header), header->certificate_len);
	if (ret == SCARD_S_SUCCESS)
		logprintf(pCardData, 3,
				"JPKI signature certificate loaded from the Windows "
				"smart-card global cache\n");

out:
	if (candidate)
		CertFreeCertificateContext(candidate);
	if (auth_certificate)
		CertFreeCertificateContext(auth_certificate);
	if (cache_data) {
		SecureZeroMemory(cache_data, cache_capacity);
		HeapFree(GetProcessHeap(), 0, cache_data);
	}
	SecureZeroMemory(&identifier, sizeof(identifier));
	SecureZeroMemory(&key, sizeof(key));
	return ret;
}

static BOOL
md_jpki_bind_signature_certificate_to_ksp(PCARD_DATA pCardData,
		struct md_pkcs15_container *container, PCCERT_CONTEXT certificate)
{
	static WCHAR ksp_name[] =
			L"Microsoft Smart Card Key Storage Provider";
	CRYPT_KEY_PROV_INFO provider_info;
	WCHAR container_name[MAX_CONTAINER_NAME_LEN + 1] = {0};
	int converted;

	if (!container || !container->guid[0] || !certificate)
		return FALSE;
	converted = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
			container->guid, -1, container_name, ARRAYSIZE(container_name));
	if (!converted)
		return FALSE;

	SecureZeroMemory(&provider_info, sizeof(provider_info));
	provider_info.pwszContainerName = container_name;
	provider_info.pwszProvName = ksp_name;
	provider_info.dwProvType = 0;
	provider_info.dwFlags = 0;
	provider_info.dwKeySpec = 0;
	if (!CertSetCertificateContextProperty(certificate,
			    CERT_KEY_PROV_INFO_PROP_ID, 0, &provider_info)) {
		logprintf(pCardData, 2,
				"JPKI signature certificate KSP binding failed: 0x%08lX\n",
				(unsigned long)GetLastError());
		SecureZeroMemory(container_name, sizeof(container_name));
		return FALSE;
	}
	SecureZeroMemory(container_name, sizeof(container_name));
	logprintf(pCardData, 2,
			"JPKI signature certificate bound to the Microsoft smart-card KSP\n");
	return TRUE;
}

/* Once the user has authenticated and the protected public certificate has
 * been read, retain that public certificate in the current user's MY store.
 * Future minidriver contexts can enumerate the signature certificate file
 * and bind it to the
 * Microsoft smart-card KSP without another protected-certificate read.
 * The certificate is public; neither the PIN nor private-key material is
 * persisted here. */
static DWORD
md_jpki_persist_signature_certificate_to_user_store(PCARD_DATA pCardData,
		const BYTE *certificate_data,
		DWORD certificate_len)
{
	struct md_pkcs15_container *container = NULL;
	PCCERT_CONTEXT certificate = NULL;
	HCERTSTORE store = NULL;
	DWORD ret = SCARD_F_INTERNAL_ERROR;
	BYTE container_index;

	if (!pCardData || !certificate_data || !certificate_len ||
			!md_jpki_get_signature_container_index(pCardData,
					&container_index) ||
			!md_jpki_is_signature_container(pCardData, container_index,
					&container))
		return SCARD_E_INVALID_PARAMETER;
	certificate = CertCreateCertificateContext(X509_ASN_ENCODING,
			certificate_data, certificate_len);
	if (!certificate)
		goto out;
	store = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
			CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG,
			L"MY");
	if (!store)
		goto out;
	if (!md_jpki_bind_signature_certificate_to_ksp(pCardData, container,
			    certificate))
		goto out;
	if (!CertAddCertificateContextToStore(store, certificate,
			    CERT_STORE_ADD_REPLACE_EXISTING, NULL))
		goto out;
	logprintf(pCardData, 2,
			"JPKI signature public certificate persisted in the current user's "
			"certificate store\n");
	ret = SCARD_S_SUCCESS;

out:
	if (store)
		CertCloseStore(store, 0);
	if (certificate)
		CertFreeCertificateContext(certificate);
	return ret;
}

static DWORD
md_jpki_seed_signature_cache_from_user_store(PCARD_DATA pCardData)
{
	struct md_jpki_cert_cache_key key;
	struct md_pkcs15_container *container = NULL;
	PCCERT_CONTEXT auth_certificate = NULL;
	PCCERT_CONTEXT current = NULL, candidate = NULL;
	HCERTSTORE store = NULL;
	DWORD ret = SCARD_E_FILE_NOT_FOUND;
	BOOL ambiguous = FALSE;
	BYTE container_index;

	if (!md_jpki_get_signature_container_index(pCardData,
			    &container_index) ||
			!md_jpki_is_signature_container(pCardData, container_index,
					&container) ||
			!md_get_jpki_live_card_key_and_certificate(pCardData, &key,
					&auth_certificate))
		goto out;
	store = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
			CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG,
			L"MY");
	if (!store)
		goto out;

	while ((current = CertEnumCertificatesInStore(store, current)) != NULL) {
		if (!md_jpki_is_user_store_signature_candidate(auth_certificate,
				    current))
			continue;
		if (candidate) {
			ambiguous = TRUE;
			break;
		}
		candidate = CertDuplicateCertificateContext(current);
		if (!candidate) {
			ret = SCARD_E_NO_MEMORY;
			goto out;
		}
	}
	if (!candidate || ambiguous)
		goto out;

	ret = md_jpki_cert_cache_store(pCardData, candidate->pbCertEncoded,
			candidate->cbCertEncoded);
	if (ret != SCARD_S_SUCCESS) {
		logprintf(pCardData, 2,
				"JPKI signature KSP bootstrap cache failed: 0x%08lX\n",
				(unsigned long)ret);
		goto out;
	}
	if (!md_jpki_bind_signature_certificate_to_ksp(pCardData, container,
			    candidate))
		logprintf(pCardData, 2,
				"JPKI signature public key was cached, but its user-store KSP "
				"binding was not persisted\n");
	logprintf(pCardData, 2,
			"JPKI signature public key seeded from the current user's certificate "
			"store\n");

out:
	if (current)
		CertFreeCertificateContext(current);
	if (candidate)
		CertFreeCertificateContext(candidate);
	if (store)
		CertCloseStore(store, 0);
	if (auth_certificate)
		CertFreeCertificateContext(auth_certificate);
	SecureZeroMemory(&key, sizeof(key));
	return ambiguous ? SCARD_E_INVALID_VALUE : ret;
}

void
md_jpki_prefetch_signature_certificate(PCARD_DATA pCardData)
{
	struct md_file *signature_file = NULL;
	char file_name[9];
	DWORD ret;
	BYTE container_index;

	if (!md_jpki_get_signature_container_index(pCardData,
			    &container_index))
		return;
	if (snprintf(file_name, sizeof(file_name), "ksc%02u",
			    (unsigned int)container_index) < 0)
		return;
	if (md_fs_find_file(pCardData, szBASE_CSP_DIR, file_name,
			    &signature_file) != SCARD_S_SUCCESS ||
			!signature_file || signature_file->blob)
		return;

	ret = md_jpki_cert_cache_copy_to_file_locked(pCardData,
			signature_file);
	if (ret != SCARD_S_SUCCESS) {
		ret = md_jpki_seed_signature_cache_from_user_store(pCardData);
		if (ret == SCARD_S_SUCCESS)
			ret = md_jpki_cert_cache_copy_to_file_locked(pCardData,
					signature_file);
	}
	if (ret == SCARD_S_SUCCESS && signature_file->blob &&
			signature_file->size <= MAXDWORD &&
			md_jpki_persist_signature_certificate_to_user_store(pCardData,
					signature_file->blob, (DWORD)signature_file->size) !=
					SCARD_S_SUCCESS)
		logprintf(pCardData, 2,
				"JPKI signature public certificate store persistence skipped\n");
	if (ret != SCARD_S_SUCCESS)
		logprintf(pCardData, 2,
				"JPKI signature certificate prefetch skipped: 0x%08lX\n",
				(unsigned long)ret);
}

static DWORD
md_jpki_cert_cache_copy_to_file(PCARD_DATA pCardData, struct md_file *file)
{
	struct md_jpki_cert_cache_key key;
	BYTE *copy = NULL;
	DWORD copy_len = 0;
	DWORD ret;

	if (!pCardData || !file || !pCardData->pfnCspAlloc ||
			!md_get_jpki_live_card_key(pCardData, &key))
		return SCARD_E_FILE_NOT_FOUND;

	ret = md_jpki_process_cache_copy(pCardData, &key, &copy,
			&copy_len);
	SecureZeroMemory(&key, sizeof(key));
	if (ret != SCARD_S_SUCCESS)
		return ret;
	file->blob = copy;
	file->size = copy_len;
	return SCARD_S_SUCCESS;
}

static DWORD
md_jpki_cert_cache_encode_public_key(PCARD_DATA pCardData,
		struct sc_pkcs15_der *public_key)
{
	struct md_jpki_cert_cache_key key;
	PCCERT_CONTEXT cert_context = NULL;
	PCERT_PUBLIC_KEY_INFO certificate_public_key = NULL;
	DWORD ret;

	if (!pCardData || !public_key || public_key->value ||
			!md_get_jpki_live_card_key(pCardData, &key))
		return SCARD_E_FILE_NOT_FOUND;

	cert_context = md_jpki_process_cache_certificate_context(&key);
	if (!cert_context &&
			md_jpki_certificate_cache_load_global(pCardData) ==
					SCARD_S_SUCCESS)
		cert_context =
				md_jpki_process_cache_certificate_context(&key);
	if (!cert_context) {
		ret = md_jpki_seed_signature_cache_from_user_store(pCardData);
		if (ret != SCARD_S_SUCCESS) {
			SecureZeroMemory(&key, sizeof(key));
			return ret;
		}
		cert_context =
				md_jpki_process_cache_certificate_context(&key);
		if (!cert_context) {
			SecureZeroMemory(&key, sizeof(key));
			return SCARD_E_FILE_NOT_FOUND;
		}
	}
	SecureZeroMemory(&key, sizeof(key));

	/* sc_pkcs15_encode_pubkey(), used by the normal path below, returns the
	 * PKCS#1 RSAPublicKey value rather than the complete SubjectPublicKeyInfo.
	 * CERT_PUBLIC_KEY_INFO::PublicKey is already that BIT STRING payload.
	 * Passing a re-encoded SPKI makes CryptDecodeObject report no CSP key even
	 * though CardGetContainerInfo itself returns success. */
	certificate_public_key =
			&cert_context->pCertInfo->SubjectPublicKeyInfo;
	if (!certificate_public_key->PublicKey.pbData ||
			!certificate_public_key->PublicKey.cbData ||
			certificate_public_key->PublicKey.cUnusedBits ||
			!md_jpki_rsa_public_key_der_is_valid(
					certificate_public_key->PublicKey.pbData,
					certificate_public_key->PublicKey.cbData)) {
		CertFreeCertificateContext(cert_context);
		return SCARD_F_INTERNAL_ERROR;
	}

	public_key->value = malloc(certificate_public_key->PublicKey.cbData);
	if (!public_key->value) {
		CertFreeCertificateContext(cert_context);
		return SCARD_E_NO_MEMORY;
	}
	CopyMemory(public_key->value,
			certificate_public_key->PublicKey.pbData,
			certificate_public_key->PublicKey.cbData);
	public_key->len = certificate_public_key->PublicKey.cbData;
	CertFreeCertificateContext(cert_context);
	return SCARD_S_SUCCESS;
}

/* Keep the live-card identity read and the corresponding process/global cache
 * lookup in one PC/SC transaction.  Otherwise a card exchange between those
 * two operations could return public material belonging to the previous card. */
static DWORD
md_jpki_cert_cache_copy_to_file_locked(PCARD_DATA pCardData,
		struct md_file *file)
{
	VENDOR_SPECIFIC *vs = pCardData ? (VENDOR_SPECIFIC *)pCardData->pvVendorSpecific : NULL;
	DWORD ret;
	int rv, unlock_r;

	if (!vs || !vs->p15card || !vs->p15card->card)
		return SCARD_E_INVALID_PARAMETER;
	rv = sc_lock(vs->p15card->card);
	if (rv != SC_SUCCESS)
		return md_translate_OpenSC_to_Windows_error(rv,
				SCARD_F_INTERNAL_ERROR);
	ret = md_jpki_cert_cache_copy_to_file(pCardData, file);
	if (ret == SCARD_E_FILE_NOT_FOUND &&
			md_jpki_certificate_cache_load_global(pCardData) ==
					SCARD_S_SUCCESS)
		ret = md_jpki_cert_cache_copy_to_file(pCardData, file);
	unlock_r = sc_unlock(vs->p15card->card);
	if (unlock_r != SC_SUCCESS)
		logprintf(pCardData, 1,
				"JPKI cache lookup card unlock failed: %s\n",
				sc_strerror(unlock_r));
	return ret;
}

DWORD
md_jpki_cert_cache_encode_public_key_locked(PCARD_DATA pCardData,
		struct sc_pkcs15_der *public_key)
{
	VENDOR_SPECIFIC *vs = pCardData ? (VENDOR_SPECIFIC *)pCardData->pvVendorSpecific : NULL;
	DWORD ret;
	int rv, unlock_r;

	if (!vs || !vs->p15card || !vs->p15card->card)
		return SCARD_E_INVALID_PARAMETER;
	rv = sc_lock(vs->p15card->card);
	if (rv != SC_SUCCESS)
		return md_translate_OpenSC_to_Windows_error(rv,
				SCARD_F_INTERNAL_ERROR);
	ret = md_jpki_cert_cache_encode_public_key(pCardData, public_key);
	unlock_r = sc_unlock(vs->p15card->card);
	if (unlock_r != SC_SUCCESS)
		logprintf(pCardData, 1,
				"JPKI public-key cache card unlock failed: %s\n",
				sc_strerror(unlock_r));
	return ret;
}

/* check_card_reader_status() may rebuild the OpenSC card context after
 * Windows has already selected the signature key and displayed its KSP PIN
 * UI.  Re-create the exact public-key snapshot from the imported certificate
 * instead of surfacing SCARD_W_RESET_CARD before the supplied PIN is checked.
 * CardSignData still compares the protected live certificate after role-3
 * authentication, so a stale or wrong certificate cannot be used to sign. */
DWORD
md_jpki_restore_signature_public_key_snapshot(PCARD_DATA pCardData)
{
	struct sc_pkcs15_der public_key = {0};
	DWORD ret;

	ret = md_jpki_cert_cache_encode_public_key_locked(pCardData, &public_key);
	if (ret == SCARD_S_SUCCESS)
		ret = md_jpki_public_key_snapshot_store(pCardData,
				public_key.value, public_key.len);
	if (public_key.value) {
		SecureZeroMemory(public_key.value, public_key.len);
		free(public_key.value);
	}
	return ret;
}

/* Read the PIN-protected certificate and bind its cache entry to the live
 * authentication-certificate fingerprint without releasing the card in
 * between.  The caller must never hold this lock while displaying PIN UI. */
DWORD
md_jpki_signature_certificate_encode_public_key(PCARD_DATA pCardData,
		struct md_pkcs15_container *container,
		struct sc_pkcs15_der *public_key)
{
	VENDOR_SPECIFIC *vs = pCardData ? (VENDOR_SPECIFIC *)pCardData->pvVendorSpecific : NULL;
	struct sc_pkcs15_cert *certificate = NULL;
	DWORD ret, cache_ret;
	int private_object, rv, unlock_r, debug, use_file_cache;

	if (!vs || !vs->ctx || !vs->p15card || !vs->p15card->card || !container ||
			!container->cert_obj || !container->cert_obj->data ||
			!public_key || public_key->value)
		return SCARD_E_INVALID_PARAMETER;

	private_object = container->cert_obj->flags & SC_PKCS15_CO_FLAG_PRIVATE;
	rv = sc_lock(vs->p15card->card);
	if (rv != SC_SUCCESS)
		return md_translate_OpenSC_to_Windows_error(rv,
				SCARD_F_INTERNAL_ERROR);

	debug = vs->ctx->debug;
	use_file_cache = vs->p15card->opts.use_file_cache;
	vs->ctx->debug = 0;
	vs->p15card->opts.use_file_cache = SC_PKCS15_OPTS_CACHE_NO_FILES;
	rv = sc_pkcs15_read_certificate(vs->p15card,
			(struct sc_pkcs15_cert_info *)container->cert_obj->data,
			private_object, &certificate);
	vs->p15card->opts.use_file_cache = use_file_cache;
	vs->ctx->debug = debug;
	if (rv != SC_SUCCESS) {
		ret = md_translate_OpenSC_to_Windows_error(rv,
				SCARD_E_FILE_NOT_FOUND);
		goto out;
	}
	if (!certificate || !certificate->data.value ||
			!certificate->data.len || certificate->data.len > MAXDWORD ||
			!certificate->key) {
		ret = SCARD_F_INTERNAL_ERROR;
		goto out;
	}

	rv = sc_pkcs15_encode_pubkey(vs->ctx, certificate->key,
			&public_key->value, &public_key->len);
	ret = rv == SC_SUCCESS ? SCARD_S_SUCCESS : SCARD_F_INTERNAL_ERROR;
	if (ret == SCARD_S_SUCCESS) {
		cache_ret = md_jpki_cert_cache_store(pCardData,
				certificate->data.value, certificate->data.len);
		if (cache_ret != SCARD_S_SUCCESS)
			logprintf(pCardData, 2,
					"JPKI signature public-key cache refresh failed; "
					"using the live public key for this request: "
					"0x%08lX\n",
					(unsigned long)cache_ret);
		if (cache_ret == SCARD_S_SUCCESS &&
				md_jpki_persist_signature_certificate_to_user_store(pCardData,
						certificate->data.value,
						(DWORD)certificate->data.len) != SCARD_S_SUCCESS)
			logprintf(pCardData, 2,
					"JPKI signature public certificate store persistence skipped\n");
	}

out:
	if (certificate)
		sc_pkcs15_free_certificate(certificate);
	unlock_r = sc_unlock(vs->p15card->card);
	if (unlock_r != SC_SUCCESS)
		logprintf(pCardData, 1,
				"JPKI signature public-key card unlock failed: %s\n",
				sc_strerror(unlock_r));
	return ret;
}

/* KSP/CSP receives the signature public key before Windows can ask for the
 * role-3 PIN.  Once CardAuthenticateEx has succeeded, read the protected
 * certificate from the live card and compare its exact PKCS#1 public key with
 * the value previously returned by CardGetContainerInfo.  A mismatch refreshes
 * the public cache but fails this operation, so Windows must re-open the key
 * and cannot sign against stale or substituted public material. */
static DWORD
md_jpki_signature_certificate_for_sign(PCARD_DATA pCardData,
		BYTE bContainerIndex,
		struct sc_pkcs15_cert **certificate_out)
{
	VENDOR_SPECIFIC *vs = pCardData ? (VENDOR_SPECIFIC *)pCardData->pvVendorSpecific : NULL;
	struct md_jpki_state *state =
			md_jpki_get_state(pCardData, FALSE);
	struct md_pkcs15_container *container = NULL;
	struct sc_pkcs15_cert *certificate = NULL;
	PCCERT_CONTEXT cert_context = NULL;
	PCERT_PUBLIC_KEY_INFO public_key = NULL;
	int private_object, debug, use_file_cache, rv;
	DWORD ret = SCARD_W_SECURITY_VIOLATION;
	BOOL snapshot_matches = FALSE;

	if (!certificate_out)
		return SCARD_E_INVALID_PARAMETER;
	*certificate_out = NULL;
	if (!vs || !vs->p15card || !vs->ctx ||
			!md_jpki_is_signature_container(pCardData, bContainerIndex,
					&container) ||
			!container || !container->cert_obj || !container->cert_obj->data)
		return SCARD_E_INVALID_PARAMETER;

	private_object = container->cert_obj->flags &
			 SC_PKCS15_CO_FLAG_PRIVATE;
	debug = vs->ctx->debug;
	use_file_cache = vs->p15card->opts.use_file_cache;
	vs->ctx->debug = 0;
	vs->p15card->opts.use_file_cache = SC_PKCS15_OPTS_CACHE_NO_FILES;
	rv = sc_pkcs15_read_certificate(vs->p15card,
			(struct sc_pkcs15_cert_info *)container->cert_obj->data,
			private_object, &certificate);
	vs->p15card->opts.use_file_cache = use_file_cache;
	vs->ctx->debug = debug;
	if (rv != SC_SUCCESS || !certificate || !certificate->data.value ||
			!certificate->data.len || certificate->data.len > MAXDWORD) {
		ret = rv == SC_SUCCESS ? SCARD_F_INTERNAL_ERROR : md_translate_OpenSC_to_Windows_error(rv, SCARD_F_INTERNAL_ERROR);
		goto out;
	}

	cert_context = CertCreateCertificateContext(X509_ASN_ENCODING,
			certificate->data.value, (DWORD)certificate->data.len);
	if (!cert_context)
		goto out;
	public_key = &cert_context->pCertInfo->SubjectPublicKeyInfo;
	if (!public_key->PublicKey.pbData ||
			public_key->PublicKey.cUnusedBits ||
			!md_jpki_rsa_public_key_der_is_valid(
					public_key->PublicKey.pbData, public_key->PublicKey.cbData))
		goto out;

	snapshot_matches = state && state->signature_public_key &&
			   state->signature_public_key_len ==
					   public_key->PublicKey.cbData &&
			   memcmp(state->signature_public_key,
					   public_key->PublicKey.pbData,
					   public_key->PublicKey.cbData) == 0;
	if (!snapshot_matches) {
		/* The real public certificate is safe to publish after role-3
		 * authentication.  Refresh for the next open, but do not let this
		 * operation continue with a key Windows selected from stale data. */
		(void)md_jpki_cert_cache_store(pCardData,
				certificate->data.value, certificate->data.len);
		(void)md_jpki_persist_signature_certificate_to_user_store(pCardData,
				certificate->data.value, (DWORD)certificate->data.len);
		logprintf(pCardData, 1,
				"JPKI signature public-key snapshot mismatch; cache refreshed "
				"and signing rejected\n");
		goto out;
	}

	*certificate_out = certificate;
	certificate = NULL;
	ret = SCARD_S_SUCCESS;

out:
	if (cert_context)
		CertFreeCertificateContext(cert_context);
	if (certificate)
		sc_pkcs15_free_certificate(certificate);
	return ret;
}

void
md_jpki_sign_finish(PCARD_DATA pCardData,
		struct md_jpki_sign_context **context, BOOL signature_succeeded)
{
	VENDOR_SPECIFIC *vs = pCardData ? (VENDOR_SPECIFIC *)pCardData->pvVendorSpecific : NULL;
	struct md_jpki_sign_context *sign_context;

	if (!context || !*context)
		return;
	sign_context = *context;
	if (sign_context->pin_cache_disabled && vs && vs->p15card) {
		vs->p15card->opts.use_pin_cache =
				sign_context->saved_use_pin_cache;
		sign_context->pin_cache_disabled = FALSE;
	}
	if (signature_succeeded && sign_context->certificate) {
		DWORD cache_ret = md_jpki_cert_cache_store(pCardData,
				sign_context->certificate->data.value,
				sign_context->certificate->data.len);

		if (cache_ret != SCARD_S_SUCCESS)
			logprintf(pCardData, 2,
					"JPKI signature public-key cache refresh skipped: "
					"0x%08lX\n",
					(unsigned long)cache_ret);
		if (cache_ret == SCARD_S_SUCCESS &&
				md_jpki_persist_signature_certificate_to_user_store(
						pCardData,
						sign_context->certificate->data.value,
						(DWORD)sign_context->certificate->data.len) !=
						SCARD_S_SUCCESS)
			logprintf(pCardData, 2,
					"JPKI signature public certificate store persistence "
					"skipped\n");
	}
	if (sign_context->card_lock_held && vs && vs->p15card) {
		(void)sc_unlock(vs->p15card->card);
		sign_context->card_lock_held = FALSE;
	}
	if (sign_context->certificate)
		sc_pkcs15_free_certificate(sign_context->certificate);
	SecureZeroMemory(sign_context, sizeof(*sign_context));
	HeapFree(GetProcessHeap(), 0, sign_context);
	*context = NULL;
}

DWORD
md_jpki_sign_prepare(PCARD_DATA pCardData, BYTE container_index,
		struct md_jpki_sign_context **context)
{
	VENDOR_SPECIFIC *vs = pCardData ? (VENDOR_SPECIFIC *)pCardData->pvVendorSpecific : NULL;
	struct md_jpki_sign_context *sign_context;
	DWORD ret;
	int rv;

	if (!context)
		return SCARD_E_INVALID_PARAMETER;
	*context = NULL;
	if (!md_jpki_is_signature_container(pCardData, container_index,
			    NULL))
		return SCARD_S_SUCCESS;
	if (!vs || !vs->p15card || !vs->p15card->card)
		return SCARD_E_INVALID_PARAMETER;

	sign_context = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
			sizeof(*sign_context));
	if (!sign_context)
		return SCARD_E_NO_MEMORY;
	*context = sign_context;
	rv = sc_lock(vs->p15card->card);
	if (rv != SC_SUCCESS) {
		ret = md_translate_OpenSC_to_Windows_error(rv,
				SCARD_F_INTERNAL_ERROR);
		md_jpki_sign_finish(pCardData, context, FALSE);
		return ret;
	}
	sign_context->card_lock_held = TRUE;
	ret = md_jpki_signature_certificate_for_sign(pCardData,
			container_index, &sign_context->certificate);
	if (ret != SCARD_S_SUCCESS) {
		md_jpki_sign_finish(pCardData, context, FALSE);
		return ret;
	}

	/* Windows owns role-3 prompting. Make exactly one signing attempt against
	 * the authentication state it established; never replay a cached PIN. */
	sign_context->saved_use_pin_cache =
			vs->p15card->opts.use_pin_cache;
	vs->p15card->opts.use_pin_cache = 0;
	sign_context->pin_cache_disabled = TRUE;
	return SCARD_S_SUCCESS;
}

#endif
#endif
