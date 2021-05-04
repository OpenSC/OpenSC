/**
 * SmartCard-HSM PKCS#11 Module
 *
 * Copyright (c) 2017, CardContact Systems GmbH, Minden, Germany
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of CardContact Systems GmbH nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL CardContact Systems GmbH BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @file    opensc-minidriver-test.c
 * @author  Andreas Schwier
 * @brief   Test framework for the CSP minidriver implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

static int testscompleted = 0;
static int testsfailed = 0;
static char *reader = NULL;


#include <windows.h>
#include <malloc.h>
#include <cardmod.h>



char *SystemErrorMsg(DWORD rc)
{
	char *msg = "UNKNOWN";

	if (!FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_HMODULE, 0, rc, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (char*)&msg, 0, 0)) {
		FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_HMODULE, GetModuleHandle("crypt32.dll"), rc, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (char*)&msg, 0, 0);
	}
	return msg;
}



char *NTSTATUSErrorMsg(NTSTATUS nts)
{
	char *msg = "UNKNOWN";

	HMODULE hmod = GetModuleHandle("ntdll.dll");
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_HMODULE, hmod, nts, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (char*)&msg, 0, 0);
	return msg;
}



char *SECURITY_STATUSErrorMsg(SECURITY_STATUS secstat)
{
	char *msg = "UNKNOWN";

	HMODULE hmod = GetModuleHandle("crypt32.dll");
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_HMODULE, hmod, secstat, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (char*)&msg, 0, 0);
	return msg;
}



/*
char *ErrorMsg(DWORD rc)
{
	char *msg = "UNKNOWN";
	HMODULE hmod;

	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_HMODULE, 0, rc, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (char*)&msg, 0, 0);
	hmod = GetModuleHandle("bcrypt.dll");
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_HMODULE, hmod, rc, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (char*)&msg, 0, 0);
	hmod = GetModuleHandle("ncrypt.dll");
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_HMODULE, hmod, rc, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (char*)&msg, 0, 0);
	hmod = GetModuleHandle("crypt32.dll");
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_HMODULE, hmod, rc, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (char*)&msg, 0, 0);
	hmod = GetModuleHandle("ntdll.dll");
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_HMODULE, hmod, rc, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (char*)&msg, 0, 0);
	hmod = GetModuleHandle("kernel32.dll");
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_HMODULE, hmod, rc, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (char*)&msg, 0, 0);
	hmod = GetModuleHandle("KernelBase.dll");
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_HMODULE, hmod, rc, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (char*)&msg, 0, 0);
	hmod = GetModuleHandle("msvcrt.dll");
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_HMODULE, hmod, rc, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (char*)&msg, 0, 0);
	hmod = GetModuleHandle("cryptbase.dll");
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_HMODULE, hmod, rc, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (char*)&msg, 0, 0);

	return msg;
}
*/


static char *verdict(int condition) {
	testscompleted++;

	if (condition) {
		return "Passed";
	} else {
		testsfailed++;
		return "Failed";
	}
}



LPVOID WINAPI CSP_ALLOC(__in SIZE_T Size) {
	return calloc(1, Size);
}



LPVOID WINAPI CSP_REALLOC(__in LPVOID Address, __in SIZE_T Size) {
	return realloc(Address, Size);
}



void WINAPI CSP_FREE(__in LPVOID Address) {
	free(Address);
}



int testSignRSA(NCRYPT_KEY_HANDLE hKey, DWORD padding, LPCWSTR hashAlg )
{
	BCRYPT_KEY_HANDLE hPubKey;
	SECURITY_STATUS secstat;
	BCRYPT_PKCS1_PADDING_INFO p1padinfo;
	BCRYPT_PSS_PADDING_INFO psspadinfo;
	BCRYPT_ALG_HANDLE hSignAlg;
	void *paddingInfo;
	PCCERT_CONTEXT certctx;
	NTSTATUS ntstat;
	unsigned char cert[4096],hash[64],signature[256],pubkeyblob[1024];
	DWORD dwrc,dwlen,hashlen;

	printf(" RSA signing with %S and %s padding", hashAlg, (padding == BCRYPT_PAD_PKCS1 ? "V1.5" : "PSS"));

	memset(hash, 0xA5, sizeof(hash));
	hashlen = sizeof(hash);

	if (!wcscmp(hashAlg, BCRYPT_SHA1_ALGORITHM)) {
		hashlen = 20;
	} else if (!wcscmp(hashAlg, BCRYPT_SHA256_ALGORITHM)) {
		hashlen = 32;
	} else if (!wcscmp(hashAlg, BCRYPT_SHA384_ALGORITHM)) {
		hashlen = 48;
	} else if (!wcscmp(hashAlg, BCRYPT_SHA512_ALGORITHM)) {
		hashlen = 64;
	} else if (!wcscmp(hashAlg, BCRYPT_MD5_ALGORITHM)) {
		hashlen = 16;
	}

	if (padding == BCRYPT_PAD_PKCS1) {
		memset(&p1padinfo, 0, sizeof(p1padinfo));
		p1padinfo.pszAlgId = hashAlg;
		paddingInfo = &p1padinfo;
	} else {
		memset(&psspadinfo, 0, sizeof(psspadinfo));
		psspadinfo.pszAlgId = hashAlg;
		psspadinfo.cbSalt = hashlen;
		paddingInfo = &psspadinfo;
	}

	// Export public key from smart card
	secstat = NCryptExportKey(hKey, 0, BCRYPT_RSAPUBLIC_BLOB, 0, pubkeyblob, sizeof(pubkeyblob), &dwlen, 0);

	if (secstat != ERROR_SUCCESS) {
		printf("\nNCryptExportKey failed: %08lx %s\n", secstat, SECURITY_STATUSErrorMsg(secstat));
		return -1;
	}

	ntstat = BCryptOpenAlgorithmProvider(&hSignAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);

	if (ntstat != ERROR_SUCCESS) {
		printf("\nBCryptOpenAlgorithmProvider failed: %08lx %s", ntstat, NTSTATUSErrorMsg(ntstat));
		return -1;
	}

	ntstat = BCryptImportKeyPair(hSignAlg, 0, BCRYPT_RSAPUBLIC_BLOB, &hPubKey, pubkeyblob, dwlen, 0);

	if (ntstat != ERROR_SUCCESS) {
		printf("\nBCryptImportKeyPair failed: %08lx %s", ntstat, NTSTATUSErrorMsg(ntstat));
		return -1;
	}

	secstat = NCryptSignHash(hKey, paddingInfo, hash, hashlen, signature, sizeof(signature), &dwlen, padding);

	if (secstat != ERROR_SUCCESS) {
		printf("\nNCryptSignHash failed: %08lx %s\n", secstat, SECURITY_STATUSErrorMsg(secstat));
		return -1;
	}

	ntstat = BCryptVerifySignature(hPubKey, paddingInfo, hash, hashlen, signature, dwlen, padding);

	if (ntstat != ERROR_SUCCESS) {
		printf("\nBCryptVerifySignature failed: %08lx %s", ntstat, NTSTATUSErrorMsg(ntstat));
		return -1;
	}

	BCryptDestroyKey(hPubKey);

	// Verify with certificate
	// Get certificate for key
	secstat = NCryptGetProperty(hKey, NCRYPT_CERTIFICATE_PROPERTY, cert, sizeof(cert), &dwlen, 0);

	if (secstat != ERROR_SUCCESS) {
		printf("\nNCryptGetProperty failed: %08lx %s\n", secstat, SECURITY_STATUSErrorMsg(secstat));
		return -1;
	}

	certctx = CertCreateCertificateContext(X509_ASN_ENCODING, cert, dwlen);

	if (certctx == NULL) {
		dwrc = GetLastError();
		printf("\nCertCreateCertificateContext failed: %04x %s\n", dwrc, SystemErrorMsg(dwrc));
		return -1;
	}

	if (!CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, &certctx->pCertInfo->SubjectPublicKeyInfo, 0, NULL, &hPubKey)) {
		dwrc = GetLastError();
		printf("\nCryptImportPublicKeyInfoEx2 failed: %04x %s\n", dwrc, SystemErrorMsg(dwrc));
		return -1;
	}

	secstat = NCryptSignHash(hKey, paddingInfo, hash, hashlen, signature, sizeof(signature), &dwlen, padding);

	if (secstat != ERROR_SUCCESS) {
		printf("\nNCryptSignHash failed: %08lx %s\n", secstat, SECURITY_STATUSErrorMsg(secstat));
		return -1;
	}

	ntstat = BCryptVerifySignature(hPubKey, paddingInfo, hash, hashlen, signature, dwlen, padding);

	if (ntstat != ERROR_SUCCESS) {
		printf("\nBCryptVerifySignature failed: %08lx %s", ntstat, NTSTATUSErrorMsg(ntstat));
		return -1;
	}

	BCryptDestroyKey(hPubKey);
	CertFreeCertificateContext(certctx);

	return 0;
}



int testSignECDSA(NCRYPT_KEY_HANDLE hKey, LPCWSTR hashAlg )
{
	BCRYPT_KEY_HANDLE hPubKey;
	SECURITY_STATUS secstat;
	PCCERT_CONTEXT certctx;
//	BCRYPT_ALG_HANDLE hSignAlg;
	NTSTATUS ntstat;
	unsigned char cert[4096],hash[64],signature[256];	// ,pubkeyblob[1024];
	DWORD dwrc,dwlen,hashlen;

	printf(" ECDSA with %S", hashAlg);

	memset(hash, 0xA5, sizeof(hash));
	hashlen = sizeof(hash);

	if (!wcscmp(hashAlg, BCRYPT_SHA1_ALGORITHM)) {
		hashlen = 20;
	} else if (!wcscmp(hashAlg, BCRYPT_SHA256_ALGORITHM)) {
		hashlen = 32;
	} else if (!wcscmp(hashAlg, BCRYPT_SHA384_ALGORITHM)) {
		hashlen = 48;
	} else if (!wcscmp(hashAlg, BCRYPT_SHA512_ALGORITHM)) {
		hashlen = 64;
	} else if (!wcscmp(hashAlg, BCRYPT_MD5_ALGORITHM)) {
		hashlen = 16;
	}

#if 0
	// Export public key from smart card
	secstat = NCryptExportKey(hKey, 0, BCRYPT_ECCPUBLIC_BLOB, 0, pubkeyblob, sizeof(pubkeyblob), &dwlen, 0);

	if (secstat != ERROR_SUCCESS) {
		printf("\nNCryptExportKey failed: %08lx %s\n", ntstat, SECURITY_STATUSErrorMsg(secstat));
		return -1;
	}

	ntstat = BCryptOpenAlgorithmProvider(&hSignAlg, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0);
	if (ntstat != ERROR_SUCCESS) {
		printf("\nBCryptOpenAlgorithmProvider failed: %ld\n", ntstat);
		return -1;
	}

	ntstat = BCryptImportKeyPair(hSignAlg, 0, BCRYPT_ECCPUBLIC_BLOB, &hPubKey, pubkeyblob, dwlen, 0);
	if (ntstat != ERROR_SUCCESS) {
		printf("\nBCryptImportKeyPair failed: %ld\n", ntstat);
		return -1;
	}

	secstat = NCryptSignHash(hKey, NULL, hash, hashlen, signature, dwlen, &dwlen, 0);

	if (secstat != ERROR_SUCCESS) {
		printf("\nNCryptSignHash failed: %08lx %s\n", ntstat, SECURITY_STATUSErrorMsg(secstat));
		return -1;
	}

	ntstat = BCryptVerifySignature(hPubKey, NULL, hash, hashlen, signature, dwlen, 0);

	if (ntstat != ERROR_SUCCESS) {
		printf("\nBCryptVerifySignature failed: %ld\n", ntstat);
		return -1;
	}

	BCryptDestroyKey(hPubKey);
#endif

	// Get certificate for key
	secstat = NCryptGetProperty(hKey, NCRYPT_CERTIFICATE_PROPERTY, cert, sizeof(cert), &dwlen, 0);

	if (secstat != ERROR_SUCCESS) {
		printf("\nNCryptGetProperty failed: %08lx %s\n", secstat, SECURITY_STATUSErrorMsg(secstat));
		return -1;
	}

	certctx = CertCreateCertificateContext(X509_ASN_ENCODING, cert, dwlen);

	if (certctx == NULL) {
		dwrc = GetLastError();
		printf("\nCertCreateCertificateContext failed: %04x %s\n", dwrc, SystemErrorMsg(dwrc));
		return -1;
	}

	if (!CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, &certctx->pCertInfo->SubjectPublicKeyInfo, 0, NULL, &hPubKey)) {
		dwrc = GetLastError();
		printf("\nCryptImportPublicKeyInfoEx2 failed: %04x %s\n", dwrc, SystemErrorMsg(dwrc));
		return -1;
	}

	secstat = NCryptSignHash(hKey, NULL, hash, hashlen, signature, dwlen, &dwlen, 0);

	if (secstat != ERROR_SUCCESS) {
		printf("\nNCryptSignHash failed: %08lx %s\n", secstat, SECURITY_STATUSErrorMsg(secstat));
		return -1;
	}

	ntstat = BCryptVerifySignature(hPubKey, NULL, hash, hashlen, signature, dwlen, 0);

	if (ntstat != ERROR_SUCCESS) {
		printf("\nBCryptVerifySignature failed: %08lx %s", ntstat, NTSTATUSErrorMsg(ntstat));
		return -1;
	}

	BCryptDestroyKey(hPubKey);
	CertFreeCertificateContext(certctx);

	return 0;
}



int testDecryptRSA(NCRYPT_KEY_HANDLE hKey, DWORD padding )
{
	BCRYPT_KEY_HANDLE hPubKey;
	SECURITY_STATUS secstat;
	BCRYPT_OAEP_PADDING_INFO oaeppadinfo;
	BCRYPT_ALG_HANDLE hSignAlg;
	void *paddingInfo;
	NTSTATUS ntstat;
	unsigned char secret[48],plain[256],cryptogram[256],pubkeyblob[1024];
	DWORD dwlen,secretlen;

	printf(" RSA decryption with %s padding", (padding == BCRYPT_PAD_PKCS1 ? "V1.5" : "OAEP"));

	memset(secret, 0xA5, sizeof(secret));
	secret[0] = 0x5A;
	secretlen = sizeof(secret);

	if (padding == BCRYPT_PAD_PKCS1) {
		paddingInfo = NULL;
	} else {
		memset(&oaeppadinfo, 0, sizeof(oaeppadinfo));
		oaeppadinfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
		paddingInfo = &oaeppadinfo;
	}

	// Export public key from smart card
	secstat = NCryptExportKey(hKey, 0, BCRYPT_RSAPUBLIC_BLOB, 0, pubkeyblob, sizeof(pubkeyblob), &dwlen, 0);

	if (secstat != ERROR_SUCCESS) {
		printf("\nNCryptExportKey failed: %08lx %s\n", secstat, SECURITY_STATUSErrorMsg(secstat));
		return -1;
	}

	ntstat = BCryptOpenAlgorithmProvider(&hSignAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);

	if (ntstat != ERROR_SUCCESS) {
		printf("\nBCryptOpenAlgorithmProvider failed: %08lx %s", ntstat, NTSTATUSErrorMsg(ntstat));
		return -1;
	}

	ntstat = BCryptImportKeyPair(hSignAlg, 0, BCRYPT_RSAPUBLIC_BLOB, &hPubKey, pubkeyblob, dwlen, 0);

	if (ntstat != ERROR_SUCCESS) {
		printf("\nBCryptImportKeyPair failed: %08lx %s", ntstat, NTSTATUSErrorMsg(ntstat));
		return -1;
	}

	ntstat = BCryptEncrypt(hPubKey, secret, secretlen, paddingInfo, NULL, 0, cryptogram, sizeof(cryptogram), &dwlen, padding);

	if (ntstat != ERROR_SUCCESS) {
		printf("\nBCryptEncrypt failed: %08lx %s", ntstat, NTSTATUSErrorMsg(ntstat));
		return -1;
	}

	secstat = NCryptDecrypt(hKey, cryptogram, dwlen, paddingInfo, plain, sizeof(plain), &dwlen, padding);

	if (secstat != ERROR_SUCCESS) {
		printf("\nNCryptExportKey failed: %08lx %s\n", secstat, SECURITY_STATUSErrorMsg(secstat));
		return -1;
	}

	BCryptDestroyKey(hPubKey);

	if ((secretlen != dwlen) || memcmp(plain, secret, secretlen)) {
		printf("\nDecrypted data does not match plain data\n");
		return -1;
	}
	return 0;
}



int cryptoTests()

{
	NCRYPT_PROV_HANDLE hProvider;
	NCRYPT_KEY_HANDLE hKey;
	NCryptKeyName *keyName;
	PVOID enumState = NULL;
	SECURITY_STATUS secstat;
	NCryptAlgorithmName *algos;
	DWORD dwlen, dwi;
	int rc;

	secstat = NCryptOpenStorageProvider(&hProvider, MS_SMART_CARD_KEY_STORAGE_PROVIDER, 0);

	if (secstat != ERROR_SUCCESS) {
		printf("NCryptOpenStorageProvider failed: %08lx %s\n", secstat, SECURITY_STATUSErrorMsg(secstat));
		return -1;
	}

	secstat = NCryptEnumAlgorithms(hProvider, NCRYPT_CIPHER_OPERATION|NCRYPT_HASH_OPERATION|NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION|NCRYPT_SECRET_AGREEMENT_OPERATION, &dwlen, &algos, 0);

	if (secstat != ERROR_SUCCESS) {
		printf("NCryptEnumAlgorithms failed: %08lx %s\n", secstat, SECURITY_STATUSErrorMsg(secstat));
		return -1;
	}

	for (dwi = 0; dwi < dwlen; dwi++) {
		printf("%S %lx %lx %lx\n", (algos + dwi)->pszName, (algos + dwi)->dwClass, (algos + dwi)->dwAlgOperations, (algos + dwi)->dwFlags);
	}

	NCryptFreeBuffer(algos);

	while (TRUE) {
		secstat = NCryptEnumKeys(hProvider, NULL, &keyName, &enumState, 0);

		if (secstat != ERROR_SUCCESS) {
			break;
		}

		printf("%S (%S)\n", keyName->pszName, keyName->pszAlgid);

		secstat = NCryptOpenKey(hProvider, &hKey, keyName->pszName, 0, 0);

		if (secstat != ERROR_SUCCESS) {
			printf("NCryptOpenKey failed: %08lx %s\n", secstat, SECURITY_STATUSErrorMsg(secstat));
			return -1;
		}

		if ((keyName->dwLegacyKeySpec == AT_KEYEXCHANGE) || (keyName->dwLegacyKeySpec == AT_SIGNATURE)) {
			rc = testSignRSA(hKey, BCRYPT_PAD_PKCS1, BCRYPT_SHA1_ALGORITHM );
			printf(" - %s\n", verdict(rc == 0));

			rc = testSignRSA(hKey, BCRYPT_PAD_PKCS1, BCRYPT_SHA256_ALGORITHM );
			printf(" - %s\n", verdict(rc == 0));

			rc = testSignRSA(hKey, BCRYPT_PAD_PKCS1, BCRYPT_SHA384_ALGORITHM );
			printf(" - %s\n", verdict(rc == 0));

			rc = testSignRSA(hKey, BCRYPT_PAD_PKCS1, BCRYPT_SHA512_ALGORITHM );
			printf(" - %s\n", verdict(rc == 0));

			rc = testSignRSA(hKey, BCRYPT_PAD_PKCS1, BCRYPT_MD5_ALGORITHM );
			printf(" - %s\n", verdict(rc == 0));

			rc = testSignRSA(hKey, BCRYPT_PAD_PSS, BCRYPT_SHA1_ALGORITHM );
			printf(" - %s\n", verdict(rc == 0));

			rc = testSignRSA(hKey, BCRYPT_PAD_PSS, BCRYPT_SHA256_ALGORITHM );
			printf(" - %s\n", verdict(rc == 0));

			rc = testDecryptRSA(hKey, BCRYPT_PAD_PKCS1 );
			printf(" - %s\n", verdict(rc == 0));

			rc = testDecryptRSA(hKey, BCRYPT_PAD_OAEP );
			printf(" - %s\n", verdict(rc == 0));
		} else {
			rc = testSignECDSA(hKey, BCRYPT_SHA1_ALGORITHM );
			printf(" - %s\n", verdict(rc == 0));

			rc = testSignECDSA(hKey, BCRYPT_SHA256_ALGORITHM );
			printf(" - %s\n", verdict(rc == 0));

			rc = testSignECDSA(hKey, BCRYPT_SHA384_ALGORITHM );
			printf(" - %s\n", verdict(rc == 0));

			rc = testSignECDSA(hKey, BCRYPT_SHA512_ALGORITHM );
			printf(" - %s\n", verdict(rc == 0));

			rc = testSignECDSA(hKey, BCRYPT_MD5_ALGORITHM );
			printf(" - %s\n", verdict(rc == 0));
		}

		NCryptFreeObject(hKey);
	}

	NCryptFreeObject(hProvider);

	return 0;
}



int listReaders()
{
	SCARDCONTEXT hSCardCtx;
	DWORD cch = 0;
	LPTSTR readers = NULL;

	if (SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hSCardCtx) != SCARD_S_SUCCESS) {
		printf("SCardEstablishContext() failed\n");
		exit(1);
	}

	if (SCardListReaders(hSCardCtx, NULL, NULL, &cch) != SCARD_S_SUCCESS) {
		printf("SCardListReaders() failed\n");
		exit(1);
	}

	readers = malloc(cch);
	reader = readers;

	if (SCardListReaders(hSCardCtx, NULL, readers, &cch) != SCARD_S_SUCCESS) {
		printf("SCardListReaders() failed\n");
		exit(1);
	}

	while(*readers) {
		printf("%s\n", readers);
		readers += strlen(readers) + 1;
	}

	SCardReleaseContext(hSCardCtx);

	return 0;
}



int apiTests(char *reader)
{
	HMODULE dlhandle;
	PFN_CARD_ACQUIRE_CONTEXT pcac;
	CARD_FREE_SPACE_INFO cardFreeSpaceInfo;
	CARD_CAPABILITIES cardCapabilities;
	CARD_DATA cardData;
	CARD_KEY_SIZES keySizes;
	CARD_FILE_INFO fileInfo;
	CONTAINER_INFO containerInfo;
	PIN_INFO pinInfo;
	LPSTR filenames;
	PBYTE pb;
	DWORD readernamelen, state, protocol, atrlen;
	unsigned char atr[36], cardid[16];
	DWORD dwrc,dwlen,dwparam;
	BOOL flag;
	char *pinEnv = getenv("MINIDRIVER_PIN");

	if (pinEnv)
		printf("Running tests using PIN=%s/len=%zd\n", pinEnv, strlen(pinEnv));
	else
		printf("Running tests wihtout any PIN\n");
	memset(&cardData, 0, sizeof(cardData));
	cardData.dwVersion = 7;
	cardData.pwszCardName = L"TestCard";

	cardData.pfnCspAlloc = CSP_ALLOC;
	cardData.pfnCspReAlloc = CSP_REALLOC;
	cardData.pfnCspFree = CSP_FREE;

	if (SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &cardData.hSCardCtx) != SCARD_S_SUCCESS) {
		printf("SCardEstablishContext() failed\n");
		exit(1);
	}

	dlhandle = LoadLibrary("opensc-minidriver.dll");

	if (!dlhandle) {
		dwrc = GetLastError();
		printf("LoadLibrary failed %04x %s\n", dwrc, SystemErrorMsg(dwrc));
		exit(1);
	}

	pcac = (PFN_CARD_ACQUIRE_CONTEXT)GetProcAddress(dlhandle, "CardAcquireContext");

	readernamelen = 0;
	atrlen = sizeof(atr);

	if (SCardConnect(cardData.hSCardCtx, reader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1, &cardData.hScard, &protocol) != SCARD_S_SUCCESS) {
		printf("SCardStatus(T1) failed, retry with T0\n");
		if (SCardConnect(cardData.hSCardCtx, reader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0, &cardData.hScard, &protocol) != SCARD_S_SUCCESS) {
			printf("SCardStatus() failed\n");
			exit(1);
		}
	}

	if (SCardStatus(cardData.hScard, NULL, &readernamelen, &state, &protocol, atr, &atrlen) != SCARD_S_SUCCESS) {
		printf("SCardStatus() failed\n");
		exit(1);
	}

	cardData.pbAtr = atr;
	cardData.cbAtr = atrlen;

	printf("Calling CardAcquireContext()");
	dwrc = (*pcac)(&cardData, 0);
	printf(" - %x : %s\n", dwrc, verdict(dwrc == SCARD_S_SUCCESS));

	printf("Calling CardQueryFreeSpace()");
	cardFreeSpaceInfo.dwVersion = CARD_FREE_SPACE_INFO_CURRENT_VERSION;
	dwrc = (*cardData.pfnCardQueryFreeSpace)(&cardData, 0, &cardFreeSpaceInfo);
	printf(" - %x : %s\n", dwrc, verdict(dwrc == SCARD_S_SUCCESS));

	printf("Calling CardGetProperty(CP_CARD_FREE_SPACE)");
	cardFreeSpaceInfo.dwVersion = CARD_FREE_SPACE_INFO_CURRENT_VERSION;
	dwrc = (*cardData.pfnCardGetProperty)(&cardData, CP_CARD_FREE_SPACE, (PBYTE)&cardFreeSpaceInfo, sizeof(cardFreeSpaceInfo), &dwlen, 0);
	printf(" - %x : %s\n", dwrc, verdict(dwrc == SCARD_S_SUCCESS));

	printf("Calling CardQueryCapabilities()");
	cardCapabilities.dwVersion = CARD_CAPABILITIES_CURRENT_VERSION;
	dwrc = (*cardData.pfnCardQueryCapabilities)(&cardData, &cardCapabilities);
	printf(" - %x : %s\n", dwrc, verdict(dwrc == SCARD_S_SUCCESS));

	printf("Calling CardGetProperty(CP_CARD_CAPABILITIES)");
	cardCapabilities.dwVersion = CARD_CAPABILITIES_CURRENT_VERSION;
	dwrc = (*cardData.pfnCardGetProperty)(&cardData, CP_CARD_CAPABILITIES, (PBYTE)&cardCapabilities, sizeof(cardCapabilities), &dwlen, 0);
	printf(" - %x : %s\n", dwrc, verdict(dwrc == SCARD_S_SUCCESS));

	printf("Calling CardQueryKeySizes()");
	keySizes.dwVersion = CARD_KEY_SIZES_CURRENT_VERSION;
	dwrc = (*cardData.pfnCardQueryKeySizes)(&cardData, AT_SIGNATURE, 0, &keySizes);
	printf(" - %x : %s\n", dwrc, verdict(dwrc == SCARD_S_SUCCESS));

	printf("Calling CardGetProperty(CP_CARD_KEYSIZES)");
	keySizes.dwVersion = CARD_KEY_SIZES_CURRENT_VERSION;
	dwrc = (*cardData.pfnCardGetProperty)(&cardData, CP_CARD_KEYSIZES, (PBYTE)&keySizes, sizeof(keySizes), &dwlen, 0);
	printf(" - %x : %s\n", dwrc, verdict(dwrc == SCARD_S_SUCCESS));

	printf("Calling CardGetProperty(CP_CARD_READ_ONLY)");
	dwrc = (*cardData.pfnCardGetProperty)(&cardData, CP_CARD_READ_ONLY, (PBYTE)&flag, sizeof(flag), &dwlen, 0);
	printf(" - %x : %s\n", dwrc, verdict((dwrc == SCARD_S_SUCCESS) && flag));

	printf("Calling CardGetProperty(CP_CARD_CACHE_MODE)");
	dwrc = (*cardData.pfnCardGetProperty)(&cardData, CP_CARD_CACHE_MODE, (PBYTE)&dwparam, sizeof(dwparam), &dwlen, 0);
	printf(" - %x : %s\n", dwrc, verdict((dwrc == SCARD_S_SUCCESS) && (dwparam == CP_CACHE_MODE_NO_CACHE)));

	printf("Calling CardGetProperty(CP_SUPPORTS_WIN_X509_ENROLLMENT)");
	dwrc = (*cardData.pfnCardGetProperty)(&cardData, CP_SUPPORTS_WIN_X509_ENROLLMENT, (PBYTE)&flag, sizeof(flag), &dwlen, 0);
	printf(" - %x : %s\n", dwrc, verdict((dwrc == SCARD_S_SUCCESS) && !flag));

	printf("Calling CardGetProperty(CP_CARD_GUID)");
	dwrc = (*cardData.pfnCardGetProperty)(&cardData, CP_CARD_GUID, (PBYTE)&cardid, sizeof(cardid), &dwlen, 0);
	printf(" - %x : %s\n", dwrc, verdict(dwrc == SCARD_S_SUCCESS));
	
	printf("Calling CardGetProperty(CP_CARD_SERIAL_NO)");
	dwrc = (*cardData.pfnCardGetProperty)(&cardData, CP_CARD_SERIAL_NO, (PBYTE)&cardid, sizeof(cardid), &dwlen, 0);
	printf(" - %x : %s\n", dwrc, verdict(dwrc == SCARD_S_SUCCESS));
	
	printf("Calling CardGetProperty(CP_CARD_PIN_INFO)");
	pinInfo.dwVersion = PIN_INFO_CURRENT_VERSION;
	dwrc = (*cardData.pfnCardGetProperty)(&cardData, CP_CARD_PIN_INFO, (PBYTE)&pinInfo, sizeof(pinInfo), &dwlen, ROLE_USER);
	printf(" - %x : %s\n", dwrc, verdict(dwrc == SCARD_S_SUCCESS));
	
	printf("Calling CardGetProperty(CP_CARD_LIST_PINS)");
	dwrc = (*cardData.pfnCardGetProperty)(&cardData, CP_CARD_LIST_PINS, (PBYTE)&dwparam, sizeof(dwparam), &dwlen, 0);
	printf(" - %x : %s\n", dwrc, verdict((dwrc == SCARD_S_SUCCESS) && (IS_PIN_SET(dwparam, ROLE_USER))));
	/* let's continue the tests only for the ROLE_USER */
	dwparam = 0;
	SET_PIN(dwparam, ROLE_USER);

	printf("Calling CardGetProperty(CP_CARD_AUTHENTICATED_STATE)");
	dwrc = (*cardData.pfnCardGetProperty)(&cardData, CP_CARD_AUTHENTICATED_STATE, (PBYTE)&dwparam, sizeof(dwparam), &dwlen, 0);
	printf(" - %x : %s\n", dwrc, verdict((dwrc == SCARD_S_SUCCESS) && (dwparam == 0)));

	printf("Calling CardGetProperty(CP_CARD_PIN_STRENGTH_VERIFY)");
	dwrc = (*cardData.pfnCardGetProperty)(&cardData, CP_CARD_PIN_STRENGTH_VERIFY, (PBYTE)&dwparam, sizeof(dwparam), &dwlen, ROLE_USER);
	printf(" - %x : %s\n", dwrc, verdict((dwrc == SCARD_S_SUCCESS) && (dwparam == CARD_PIN_STRENGTH_PLAINTEXT)));

	printf("Calling CardGetProperty(CP_KEY_IMPORT_SUPPORT)");
	dwrc = (*cardData.pfnCardGetProperty)(&cardData, CP_KEY_IMPORT_SUPPORT, (PBYTE)&dwparam, sizeof(dwparam), &dwlen, 0);
	printf(" - %x : %s\n", dwrc, verdict((dwrc == SCARD_S_SUCCESS) && (dwparam == 0)));

	printf("Calling CardReadFile(cardid)");
	dwrc = (*cardData.pfnCardReadFile)(&cardData, NULL, szCARD_IDENTIFIER_FILE, 0, &pb, &dwlen);
	printf(" - %x : %s\n", dwrc, verdict((dwrc == SCARD_S_SUCCESS) && (dwlen == 16)));

	printf("Calling CardReadFile(cardcf)");
	dwrc = (*cardData.pfnCardReadFile)(&cardData, NULL, szCACHE_FILE, 0, &pb, &dwlen);
	printf(" - %x : %s\n", dwrc, verdict((dwrc == SCARD_S_SUCCESS) && (dwlen == 6)));

	printf("Calling CardReadFile(cardapps)");
	dwrc = (*cardData.pfnCardReadFile)(&cardData, NULL, "cardapps", 0, &pb, &dwlen);
	printf(" - %x : %s\n", dwrc, verdict((dwrc == SCARD_S_SUCCESS) && (dwlen == 8)));

	printf("Calling CardReadFile(mscp/cmapfile)");
	dwrc = (*cardData.pfnCardReadFile)(&cardData, szBASE_CSP_DIR, szCONTAINER_MAP_FILE, 0, &pb, &dwlen);
	printf(" - %x : %s\n", dwrc, verdict((dwrc == SCARD_S_SUCCESS) && (dwlen > 0)));

	printf("Calling CardReadFile(mscp/msroots)");
	dwrc = (*cardData.pfnCardReadFile)(&cardData, szBASE_CSP_DIR, szROOT_STORE_FILE, 0, &pb, &dwlen);
	printf(" - %x : %s\n", dwrc, verdict((dwrc == SCARD_S_SUCCESS) && (dwlen > 0)));

	printf("Calling CardGetFileInfo(mscp/cmapfile)");
	fileInfo.dwVersion = CARD_FILE_INFO_CURRENT_VERSION;
	dwrc = (*cardData.pfnCardGetFileInfo)(&cardData, szBASE_CSP_DIR, szCONTAINER_MAP_FILE, &fileInfo);
	printf(" - %x : %s\n", dwrc, verdict((dwrc == SCARD_S_SUCCESS) && (dwlen > 0)));

	printf("Calling CardReadFile(mscp/kxc00)");
	dwrc = (*cardData.pfnCardReadFile)(&cardData, szBASE_CSP_DIR, szUSER_KEYEXCHANGE_CERT_PREFIX "00", 0, &pb, &dwlen);
	printf(" - %x : %s\n", dwrc, verdict((dwrc == SCARD_S_SUCCESS) && (dwlen > 0)));

	printf("Calling CardEnumFiles(root)");
	dwrc = (*cardData.pfnCardEnumFiles)(&cardData, NULL, &filenames, &dwlen, 0);
	printf(" - %x : %s\n", dwrc, verdict((dwrc == SCARD_S_SUCCESS) && (dwlen > 0)));

	printf("Calling CardGetContainerInfo(0)");
	containerInfo.dwVersion = CONTAINER_INFO_CURRENT_VERSION;
	dwrc = (*cardData.pfnCardGetContainerInfo)(&cardData, 0, 0, &containerInfo);
	printf(" - %x : %s\n", dwrc, verdict(dwrc == SCARD_S_SUCCESS));

	printf("Calling CardAuthenticatePin(wszCARD_USER_USER)");
	if (pinEnv) {
		dwrc = (*cardData.pfnCardAuthenticatePin)(&cardData, wszCARD_USER_USER, pinEnv, (DWORD)strlen(pinEnv), &dwparam);
		printf(" - %x : %s\n", dwrc, verdict((dwrc == SCARD_S_SUCCESS) && (dwparam == -1)));

		printf("Calling CardGetProperty(CP_CARD_AUTHENTICATED_STATE)");
		dwrc = (*cardData.pfnCardGetProperty)(&cardData, CP_CARD_AUTHENTICATED_STATE, (PBYTE)&dwparam, sizeof(dwparam), &dwlen, 0);
		printf(" - %x : %s\n", dwrc, verdict((dwrc == SCARD_S_SUCCESS) && (dwparam == 2)));

		printf("Calling CardAuthenticatePin(wszCARD_USER_USER) - Wrong PIN");
		dwrc = (*cardData.pfnCardAuthenticatePin)(&cardData, wszCARD_USER_USER, "3456", 4, &dwparam);
		printf(" - %x : %s\n", dwrc, verdict((dwrc == SCARD_W_WRONG_CHV) && (dwparam == 2)));

		printf("Calling CardGetProperty(CP_CARD_AUTHENTICATED_STATE)");
		dwrc = (*cardData.pfnCardGetProperty)(&cardData, CP_CARD_AUTHENTICATED_STATE, (PBYTE)&dwparam, sizeof(dwparam), &dwlen, 0);
		printf(" - %x : %s\n", dwrc, verdict((dwrc == SCARD_S_SUCCESS) && (dwparam == 0)));

		printf("Calling CardAuthenticatePin(wszCARD_USER_USER)");
		dwrc = (*cardData.pfnCardAuthenticatePin)(&cardData, wszCARD_USER_USER, pinEnv, (DWORD)strlen(pinEnv), &dwparam);
		printf(" - %x : %s\n", dwrc, verdict((dwrc == SCARD_S_SUCCESS) && (dwparam == -1)));

		printf("Calling CardGetProperty(CP_CARD_AUTHENTICATED_STATE)");
		dwrc = (*cardData.pfnCardGetProperty)(&cardData, CP_CARD_AUTHENTICATED_STATE, (PBYTE)&dwparam, sizeof(dwparam), &dwlen, 0);
		printf(" - %x : %s\n", dwrc, verdict((dwrc == SCARD_S_SUCCESS) && (dwparam == 2)));

		printf("Calling CardDeAuthenticate(wszCARD_USER_USER)");
		dwrc = (*cardData.pfnCardDeauthenticate)(&cardData, wszCARD_USER_USER, 0);
		printf(" - %x : %s\n", dwrc, verdict(dwrc == SCARD_S_SUCCESS));

		printf("Calling CardGetProperty(CP_CARD_AUTHENTICATED_STATE)");
		dwrc = (*cardData.pfnCardGetProperty)(&cardData, CP_CARD_AUTHENTICATED_STATE, (PBYTE)&dwparam, sizeof(dwparam), &dwlen, 0);
		printf(" - %x : %s\n", dwrc, verdict((dwrc == SCARD_S_SUCCESS) && (dwparam == 0)));
	} else {
		printf(" - skip: missing set MINIDRIVER_PIN=abcd\n");
	}

	printf("Calling CardDeleteContext()");
	dwrc = (*cardData.pfnCardDeleteContext)(&cardData);
	printf(" - %x : %s\n", dwrc, verdict(dwrc == SCARD_S_SUCCESS));

	SCardReleaseContext(cardData.hSCardCtx);

	return 0;
}



int main(int argc, char *argv[])

{
	if (argc == 1) {
		printf("Usage: opensc-minidriver-test [-l] [-r <name>] [-a] [-c]\n");
		printf("       -l         list readers\n");
		printf("       -r <name>  define readers\n");
		printf("       -a         run API tests\n");
		printf("       -c         run crypto tests\n");
		exit(1);
	}

	argc--;
	argv++;

	while (argc--) {
		if (!strcmp(*argv, "-l")) {
			listReaders();
		} else if (!strcmp(*argv, "-r")) {
			if (argc == 0) {
				printf("Reader name missing in -r parameter\n");
				exit(1);
			}
			argv++;
			argc--;
			reader = *argv;
		} else if (!strcmp(*argv, "-a")) {
			if (reader == NULL) {
				printf("Need a reader name set with -r or use -l to select first reader\n");
				exit(1);
			}
			apiTests(reader);
		} else if (!strcmp(*argv, "-c")) {
			cryptoTests();
		} else {
			printf("Unknown parameter %s\n", *argv);
		}
		argv++;
	}

	printf("Unit test finished.\n");
	printf("%d tests performed.\n", testscompleted);
	printf("%d tests failed.\n", testsfailed);

	exit(testsfailed ? 1 : 0);
}
