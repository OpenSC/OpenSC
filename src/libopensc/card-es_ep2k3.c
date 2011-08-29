/*
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

/* Initially written by Weitao Sun (weitao@ftsafe.com) 2008 */

#include "config.h"
#ifdef ENABLE_OPENSSL	/* empty file without openssl */

#include <assert.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

#include "internal.h"
#include "asn1.h"
#include "cardctl.h"

static struct sc_atr_table es_ep2k3_atrs[] = {
	{	//This is a FIPS(SCP01) certified card.
		"3B:9F:95:81:31:FE:9F:00:66:46:53:05:10:00:11:71:df:00:00:00:6a:82:5e", 
		"FF:FF:FF:FF:FF:00:FF:FF:FF:FF:FF:FF:00:00:00:ff:00:ff:ff:00:00:00:00",
		"FTCOS/ePass2003", SC_CARD_TYPE_ENTERSAFE_FTCOS_EP2K3, 0, NULL },
	{ NULL, NULL, NULL, 0, 0, NULL }
};

static struct sc_card_operations *iso_ops = NULL;
static struct sc_card_operations es_ep2k3_ops;

static struct sc_card_driver es_ep2k3_drv = {
	"es_ep2k3",
	"es_ep2k3",
	&es_ep2k3_ops,
	NULL, 0, NULL
};

#define KEY_TYPE_AES						0x01
#define KEY_TYPE_DES						0x02

#define KEY_LEN_AES	16
#define KEY_LEN_DES	8
#define KEY_LEN_DES3	24
#define HASH_LEN	24
static unsigned char DES_KeyID[10] = 
{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A
};
static unsigned char AES_KeyID[10] = 
{
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A
};

static unsigned char PIN_ID[2] = {ENTERSAFE_USER_PIN_ID, ENTERSAFE_SO_PIN_ID};
#define MAX_PIN_COUNTER						0x03

/*0x00:plain; 0x01:scp01 sm*/
#define SM_PLAIN				0x00
#define SM_SCP01				0x01

#define AES_BLOCK_LEN						0x10
#define DES_BLOCK_LEN						0x08

static unsigned char MF_aid[16] =
{
	0x31, 0x50, 0x41, 0x59, 0x2E, 0x53, 0x59, 0x53, 0x2E, 0x44, 0x44, 0x46,
	0x30, 0x31, 0x00, 0x00
};
static unsigned char ADF_aid[16] =
{
	0x45, 0x4E, 0x54, 0x45, 0x52, 0x53, 0x41, 0x46, 0x45, 0x2D, 0x45, 0x53, 
	0x50, 0x4B, 0x00, 0x00
};
static unsigned char INIT_KEYenc[16] = 
{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
	0x0D, 0x0E, 0x0F, 0x10
};
static unsigned char INIT_KEYmac[16] = 
{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
	0x0D, 0x0E, 0x0F, 0x10
};

static unsigned char MainRandom[8] =
{
	0xBF, 0xC3, 0x29, 0x11, 0xC7, 0x18, 0xC3, 0x40
};

static	unsigned char m_KSenc[16];	/* encrypt session key */
static	unsigned char m_KSmac[16];	/* mac session key */
static	unsigned char m_macICV[16];/* ins counter(for sm) */
static	unsigned char m_SMTrans;	/* if perform sm or not */
static	unsigned char m_SMtype;	/* sm cryption algorithm type */
static	unsigned char m_algRSALen;
static	unsigned long m_mechanismHW[128];
static	unsigned long m_mechanismHWNum;
static	unsigned long m_apduSize;

typedef unsigned long ES_RV;

#define ESR_OK								0x00000000
#define ESR_HOST_MEMORY						0x00000002
#define ESR_SLOT_ID_INVALID					0x00000003
#define ESR_GENERAL_ERROR					0x00000005
#define ESR_ARGUMENTS_BAD					0x00000007
#define ESR_TOKEN_NOT_PRESENT				0x000000E0
#define ESR_TOKEN_NOT_RECOGNIZED			0x000000E1
#define ESR_DEVICE_ERROR					0x00000030
#define ESR_PIN_LOCKED						0x000000A4
#define ESR_PIN_INCORRECT					0x000000A0
#define ESR_MECHANISM_INVALID				0x00000070
#define ESR_SEC_VIOLATION					0x00000101
#define ESR_ALREADY_EXIST					0x00010001
#define ESR_CONTAINER_NOT_PRESENT			0x00010002
#define ESR_NOT_EXIST	    				0x00010003
#define ESR_BUFFER_TOO_SMALL				0x00010004
#define ESR_NOT_SUPPORTED					0x00010005

#define ES_VERIFY(x,r) do{if(!(x))return(r);}while(0)
#define REVERSE_ORDER4(x)	(((unsigned long)x & 0xFF000000)>> 24  |		\
							 ((unsigned long)x & 0x00FF0000)>>  8  |		\
							 ((unsigned long)x & 0x0000FF00)<<  8  |		\
							 ((unsigned long)x & 0x000000FF)<< 24 )
int es_ep2k3_openssl_enc( const EVP_CIPHER *cipher, const unsigned char *key, const unsigned char *iv, 
		const unsigned char* input, unsigned long length, unsigned char* output)
{
	int r = SC_ERROR_INTERNAL;
	EVP_CIPHER_CTX ctx;
	int outl = 0;
	int outl_tmp = 0;
	unsigned char iv_tmp[EVP_MAX_IV_LENGTH] = {0};
	memcpy(iv_tmp, iv, EVP_MAX_IV_LENGTH);
	EVP_CIPHER_CTX_init(&ctx);
	EVP_CIPHER_CTX_set_padding(&ctx, 0);
	EVP_EncryptInit_ex(&ctx, cipher, NULL, key, iv_tmp);
	if(!EVP_EncryptUpdate(&ctx, output, &outl, input, length)) 
	{
		goto out;			   
	}
	if (!EVP_EncryptFinal_ex(&ctx, output+outl, &outl_tmp))
	{
		goto out;
	}
	if (!EVP_CIPHER_CTX_cleanup(&ctx)) 
	{
		goto out;			   
	}
	r = SC_SUCCESS;
out:
	return r;
}

int es_ep2k3_openssl_dec( const EVP_CIPHER *cipher, const unsigned char *key, const unsigned char *iv, 
		const unsigned char* input, unsigned long length, unsigned char* output)
{
	int r = SC_ERROR_INTERNAL;
	EVP_CIPHER_CTX ctx;
	int outl = 0;
	int outl_tmp = 0;
	unsigned char iv_tmp[EVP_MAX_IV_LENGTH] = {0};
	memcpy(iv_tmp, iv, EVP_MAX_IV_LENGTH);
	EVP_CIPHER_CTX_init(&ctx);
	EVP_CIPHER_CTX_set_padding(&ctx, 0);
	EVP_DecryptInit_ex(&ctx, cipher, NULL, key, iv_tmp);
	if(!EVP_DecryptUpdate(&ctx, output, &outl, input, length)) 
	{
		goto out;			   
	}
	if (!EVP_DecryptFinal_ex(&ctx, output+outl, &outl_tmp))
	{
		goto out;
	}
	if (!EVP_CIPHER_CTX_cleanup(&ctx)) 
	{
		goto out;			   
	}
	r = SC_SUCCESS;
out:
	return r;
}

int aes128_encrypt_ecb( const unsigned char *key, int keysize, 
		const unsigned char* input, unsigned long length, unsigned char* output)
{
	unsigned char iv[EVP_MAX_IV_LENGTH] = {0};
	return es_ep2k3_openssl_enc(EVP_aes_128_ecb(), key, iv, input, length, output);

}
int aes128_encrypt_cbc( const unsigned char *key, int keysize, unsigned char iv[16], 
		const unsigned char *input, unsigned long length, unsigned char *output )
{
	return es_ep2k3_openssl_enc(EVP_aes_128_cbc(), key, iv, input, length, output);
}

int aes128_decrypt_cbc( const unsigned char *key, int keysize, unsigned char iv[16], 
		const unsigned char *input, unsigned long length, unsigned char *output )
{
	return es_ep2k3_openssl_dec(EVP_aes_128_cbc(), key, iv, input, length, output);
}

int des3_encrypt_ecb( const unsigned char *key, int keysize, 
		const unsigned char* input, int length, unsigned char* output)
{
	unsigned char iv[EVP_MAX_IV_LENGTH] = {0};
	return es_ep2k3_openssl_enc(EVP_des_ede3(), key, iv, input, length, output);
}

int des3_encrypt_cbc( const unsigned char *key, int keysize, unsigned char iv[8], 
		const unsigned char *input, unsigned long length, unsigned char *output )
{
	return es_ep2k3_openssl_enc(EVP_des_ede3_cbc(), key, iv, input, length, output);
}

int des3_decrypt_cbc( const unsigned char *key, int keysize, unsigned char iv[8], 
		const unsigned char *input, unsigned long length, unsigned char *output )
{
	return es_ep2k3_openssl_dec(EVP_des_ede3_cbc(), key, iv, input, length, output);
}

int des_encrypt_cbc( const unsigned char *key, int keysize, unsigned char iv[8], 
		const unsigned char *input, unsigned long length, unsigned char *output )
{
	return es_ep2k3_openssl_enc(EVP_des_cbc(), key, iv, input, length, output);
}

int des_decrypt_cbc( const unsigned char *key, int keysize, unsigned char iv[8], 
		const unsigned char *input, unsigned long length, unsigned char *output )
{
	return es_ep2k3_openssl_dec(EVP_des_cbc(), key, iv, input, length, output);
}
int es_ep2k3_openssl_dig( const EVP_MD *digest, 
		const unsigned char* input, unsigned long length, unsigned char* output)
{
	int r;
	EVP_MD_CTX ctx;
	int outl = 0;
	EVP_MD_CTX_init(&ctx);
	EVP_DigestInit_ex(&ctx, digest, NULL);
	if(!EVP_DigestUpdate(&ctx, input, length)) 
	{
		r = SC_ERROR_INTERNAL;
		goto out;			   
	}
	if (!EVP_DigestFinal_ex(&ctx, output, &outl))
	{
		r = SC_ERROR_INTERNAL;
		goto out;
	}
	if (!EVP_MD_CTX_cleanup(&ctx)) 
	{
		r = SC_ERROR_INTERNAL;
		goto out;			   
	}
out:
	return r;
}

int sha1_digest(const unsigned char *input, unsigned long length, unsigned char *output )
{
	return es_ep2k3_openssl_dig(EVP_sha1(), input, length, output);
}

static ES_RV AddICV()
{
	int i;
	if (KEY_TYPE_AES == m_SMtype)
	{
		i = 15;
	}
	else
	{
		i = 7;
	}
	for(; i>=0; i--)
	{
		if (m_macICV[i] == 0xff)
		{
			m_macICV[i]=0;
		}
		else
		{
			m_macICV[i]++ ;
			break;
		}
	}
	return ESR_OK;
}

static int es_ep2k3_transmit_apdu(sc_card_t *card, sc_apdu_t *apdu);

static int cmdGenerateInitKey(sc_card_t *card, unsigned char* Kenc, unsigned char* Kmac, unsigned char* pResult, unsigned char keyType)
{
	int r;
	sc_apdu_t apdu;
	unsigned char data[256] = {0};
	unsigned char safeTransmit;
	unsigned long blocksize = 0;
	unsigned char keySecretC[256] = {0};
	unsigned char iv[16] = {0};
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	//	APDU apdu(0x80, 0x50, 0x00, 0x00, sizeof(MainRandom), MainRandom);	
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x50, 0x00, 0x00);
	apdu.cla = 0x80;
	apdu.lc = apdu.datalen = sizeof(MainRandom);
	apdu.data = MainRandom;
	apdu.le = apdu.resplen = 28;
	apdu.resp = pResult;

	safeTransmit = m_SMTrans;
	m_SMTrans = SM_PLAIN;
	r = es_ep2k3_transmit_apdu(card, &apdu); 
	m_SMTrans = safeTransmit;
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU GenerateInitKey failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "GenerateInitKey failed");

	memcpy(data, &pResult[16], 4);
	memcpy(&data[4], MainRandom, 4);
	memcpy(&data[8], &pResult[12], 4);
	memcpy(&data[12], &MainRandom[4], 4);
	blocksize = (keyType==KEY_TYPE_AES?16:8);
	if (KEY_TYPE_AES == keyType)
	{
		aes128_encrypt_ecb(Kenc, 16, data, 16, m_KSenc);
		aes128_encrypt_ecb(Kmac, 16, data, 16, m_KSmac);
	}
	else
	{
		des3_encrypt_ecb(Kenc, 16, data, 16, m_KSenc);
		des3_encrypt_ecb(Kmac, 16, data, 16, m_KSmac);
	}	
	//authenticate key secret content
	memcpy(data, MainRandom, 8);
	memcpy(&data[8], &pResult[12], 8);
	data[16] = 0x80;
	memset(&data[17], 0x00, blocksize-1);
	if (KEY_TYPE_AES == keyType)
	{
		aes128_encrypt_cbc(m_KSenc, 16, iv, data, 16+blocksize, keySecretC);	
	}
	else
	{
		des3_encrypt_cbc(m_KSenc, 16, iv, data, 16+blocksize, keySecretC);
	}	
	ES_VERIFY(0==memcmp(&keySecretC[16], &pResult[20], 8), SC_ERROR_CARD_CMD_FAILED);
	return SC_SUCCESS;
}

static int cmdGetICV_Auth(sc_card_t *card, unsigned char* keyRandom, unsigned char keyType)
{
	int r;
	sc_apdu_t apdu;
	unsigned long blocksize = (keyType==KEY_TYPE_AES?16:8);
	unsigned char data[256] = {0};	
	unsigned char mainSecretC[256] = {0};
	unsigned char iv[16] = {0};
	unsigned char mac[256] = {0};
	unsigned long macCursor;
	unsigned char safeTransmit;
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	memcpy(data, keyRandom, 8);
	memcpy(&data[8], MainRandom, 8);
	data[16] = 0x80;
	memset(&data[17], 0x00, blocksize-1);
	memset(iv, 0, 16);
	if (KEY_TYPE_AES == keyType)
	{
		aes128_encrypt_cbc(m_KSenc, 16, iv, data, 16+blocksize, mainSecretC);
	}
	else
	{
		des3_encrypt_cbc(m_KSenc, 16, iv, data, 16+blocksize, mainSecretC);
	}

	memset(data, 0, sizeof(data));
	memcpy(data, "\x84\x82\x03\x00\x10", 5);
	memcpy(&data[5], &mainSecretC[16], 8);
	memcpy(&data[13], "\x80\x00\x00", 3);
	memset(iv, 0x00, 16);
	if (KEY_TYPE_AES == keyType)
	{		
		aes128_encrypt_cbc(m_KSmac, 16, iv, data, 16, mac);
		macCursor = 0;
	}
	else
	{
		des3_encrypt_cbc(m_KSmac, 16, iv, data, 16, mac);
		macCursor = 8;
	}
	memset(m_macICV, 0x00, 16);
	memcpy(m_macICV, &mac[macCursor], 8);
	memcpy(data, &mainSecretC[16], 8);
	memcpy(&data[8], &mac[macCursor], 8);
	//	APDU apdu(0x84, 0x82, 0x03, 0x00, 0x10, data);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x82, 0x03, 0x00);
	apdu.cla = 0x84;
	apdu.lc   = apdu.datalen = 16;
	apdu.data = data;
	safeTransmit = m_SMTrans;
	m_SMTrans = SM_PLAIN;
	r = es_ep2k3_transmit_apdu(card, &apdu);
	m_SMTrans = safeTransmit;
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU GetICV_Auth failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "GetICV_Auth failed");
	return r;
}

static int GetInitKey(sc_card_t *card, unsigned char* Kenc, unsigned char* Kmac)
{
	int r;
	unsigned char result[256] = {0};
	unsigned char keyRandom[8] = {0};
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	r = cmdGenerateInitKey(card, Kenc, Kmac, result, m_SMtype);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "generateInitKey failed");
	memcpy(keyRandom, &result[12], 8);
	r = cmdGetICV_Auth(card, keyRandom, m_SMtype);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "getICV_Auth failed");
	return r;
}

int es_ep2k3_refresh(sc_card_t *card)
{
	int r = 0;
	if (m_SMTrans)
	{
		r = GetInitKey(card, INIT_KEYenc, INIT_KEYmac);
		SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "getInitKey failed");
	}
	return r;
}
static ES_RV BuildAPDUDataTLV(sc_apdu_t * apdu, unsigned char *safeApdu, unsigned char* pDataTLV, unsigned long* pulDataTLVLen, const unsigned char keyType)
{
	unsigned long ulBlockSize = (KEY_TYPE_AES==keyType?16:8);
	unsigned char dataPadding[4096] = {0};	
	unsigned long ulDataPaddingLen;
	unsigned long dataTLV_TL_more;
	unsigned char iv[16] = {0};
	//get data = T+L+V
	safeApdu[ulBlockSize] = 0x87;
	memcpy(dataPadding, apdu->data, apdu->lc);
	dataPadding[apdu->lc] = 0x80;							
	if ((apdu->lc+1)%ulBlockSize)
	{
		ulDataPaddingLen = ((apdu->lc+1)/ulBlockSize+1)*ulBlockSize;
	}
	else
	{
		ulDataPaddingLen = apdu->lc+1;
	}
	if (ulDataPaddingLen>0x7E)
	{
		safeApdu[ulBlockSize+1] = 0x82;
		safeApdu[ulBlockSize+2] = (unsigned char)((ulDataPaddingLen+1)/0x100);
		safeApdu[ulBlockSize+3] = (unsigned char)((ulDataPaddingLen+1)%0x100);
		safeApdu[ulBlockSize+4] = 0x01;	
		dataTLV_TL_more = 5;
	}
	else
	{
		safeApdu[ulBlockSize+1] = (unsigned char)ulDataPaddingLen + 1;
		safeApdu[ulBlockSize+2] = 0x01;
		dataTLV_TL_more = 3;
	}
	memcpy(pDataTLV, &safeApdu[ulBlockSize], dataTLV_TL_more);
	if (KEY_TYPE_AES == keyType)
	{	
		aes128_encrypt_cbc(m_KSenc, 16, iv, dataPadding, ulDataPaddingLen, safeApdu+ulBlockSize+dataTLV_TL_more);
	}
	else
	{
		des3_encrypt_cbc(m_KSenc, 16, iv, dataPadding, ulDataPaddingLen, safeApdu+ulBlockSize+dataTLV_TL_more);
	}				
	memcpy(pDataTLV+dataTLV_TL_more, safeApdu+ulBlockSize+dataTLV_TL_more, ulDataPaddingLen);
	*pulDataTLVLen = dataTLV_TL_more+ulDataPaddingLen;
	return ESR_OK;
}

static ES_RV BuildAPDULeTLV(sc_apdu_t *apdu, unsigned char* safeApdu, unsigned long dataTLVLen, unsigned char* pLeTLV, unsigned long* pulLeTLVLen, const unsigned char keyType)
{
	unsigned long ulBlockSize = (KEY_TYPE_AES==keyType?16:8);
	*(safeApdu+ulBlockSize+dataTLVLen) = 0x97;
	if (apdu->le > 0x7F)
	{
		*(safeApdu+ulBlockSize+dataTLVLen+1) = 2;
		*(safeApdu+ulBlockSize+dataTLVLen+2) = (unsigned char)(apdu->le/0x100);
		*(safeApdu+ulBlockSize+dataTLVLen+3) = (unsigned char)(apdu->le%0x100);
		memcpy(pLeTLV, safeApdu+ulBlockSize+dataTLVLen, 4);
		*pulLeTLVLen = 4;
	}
	else
	{
		*(safeApdu+ulBlockSize+dataTLVLen+1) = 1;
		*(safeApdu+ulBlockSize+dataTLVLen+2) = (unsigned char)apdu->le;
		memcpy(pLeTLV, safeApdu+ulBlockSize+dataTLVLen, 3);
		*pulLeTLVLen = 3;
	}
	return ESR_OK;
}

static ES_RV BuildAPDUMacTLV(unsigned char* safeApdu, unsigned long dataTLVLen, unsigned long leTLVLen, unsigned char* pmacTLV, unsigned long* pulmacTLVLen, const unsigned char keyType)
{
	unsigned long ulBlockSize = (KEY_TYPE_AES==keyType?16:8);
	unsigned char macValue[4096] = {0};
	unsigned long ulmacLen;
	unsigned char icv[16] = {0};
	if (0==dataTLVLen && 0==leTLVLen)
	{
		ulmacLen = ulBlockSize;
	}
	else
	{
		*(safeApdu+ulBlockSize+dataTLVLen+leTLVLen) = 0x80;				
		if ((dataTLVLen+leTLVLen+1)%ulBlockSize)
		{
			ulmacLen = (((dataTLVLen+leTLVLen+1)/ulBlockSize)+1)*ulBlockSize+ulBlockSize;
		}
		else
		{
			ulmacLen = dataTLVLen+leTLVLen+1+ulBlockSize;
		}
		memset((safeApdu+ulBlockSize+dataTLVLen+leTLVLen+1), 0, (ulmacLen - (dataTLVLen+leTLVLen+1)));				
	}			
	AddICV();
	memset(icv, 0, sizeof(icv));
	memcpy(icv, m_macICV, 16);			
	if (KEY_TYPE_AES == keyType)
	{
		aes128_encrypt_cbc(m_KSmac, 16, icv, safeApdu, ulmacLen, macValue);
		memcpy(pmacTLV+2, &macValue[ulmacLen-16], 8);
	}
	else
	{
		unsigned char iv[8] = {0};
		unsigned char valueTemp[8] = {0};
		des_encrypt_cbc(m_KSmac, 8, icv, safeApdu, ulmacLen, macValue);
		des_decrypt_cbc(&m_KSmac[8], 8, iv, &macValue[ulmacLen-8], 8, valueTemp);
		memset(iv, 0x00, 8);
		des_encrypt_cbc(m_KSmac, 8, iv, valueTemp, 8, pmacTLV+2);
	}
	*pulmacTLVLen = 2+8;
	return ESR_OK;
}

static size_t CalcLe(size_t le)
{
	size_t le_new = 0;
	size_t resp_len = 0;
	size_t sw12_len = 4;	//t 1 l 1 v 2
	size_t mac_len = 10;	//t 1 l 1 v 8
	size_t mod = 16;
	//TODO:先pading还是先算长度？
	//先padding。
	resp_len = 1 + ((le + (mod - 1)) / mod) * mod;

	if( 0x7f < resp_len )
	{
		resp_len += 0;

	} else if( 0x7f <= resp_len && resp_len < 0xff)
	{
		resp_len += 1;
	}
	else if( 0xff <= resp_len)
	{
		resp_len += 2;
	}
	resp_len += 2;	//加t加l；
	le_new = resp_len + sw12_len + mac_len;
	return le_new;
}

static ES_RV Build_Ciphertext_APDU(sc_apdu_t *plain, sc_apdu_t *sm, unsigned char *safeApdu, size_t *safeApduLen)
{
	unsigned long ulBlockSize = (KEY_TYPE_DES==m_SMtype?16:8);
	unsigned char dataTLV[4096] = {0};
	unsigned long dataTLVLen = 0;
	unsigned char leTLV[256] = {0};
	unsigned long leTLVLen = 0;
	unsigned char macTLV[256] = {0};
	macTLV[0] = 0x8E;
	macTLV[1] = 8;
	unsigned long macTLVLen = 10;			
	unsigned long tmp_lc;
	unsigned long tmp_le;
//	size_t plain_le = 0;

	sm->cse = SC_APDU_CASE_4_SHORT;
	safeApdu[0] = (unsigned char)plain->cla;
	safeApdu[1] = (unsigned char)plain->ins;
	safeApdu[2] = (unsigned char)plain->p1;
	safeApdu[3] = (unsigned char)plain->p2;	

//	plain_le = plain->le;

	/* padding */
	safeApdu[4] = 0x80;
	memset(&safeApdu[5], 0x00, ulBlockSize-5);

	if(plain->lc != 0)
	{			
		ES_VERIFY(ESR_OK == BuildAPDUDataTLV(plain, safeApdu, dataTLV, &dataTLVLen, m_SMtype), ESR_GENERAL_ERROR);
	}
	if(plain->le != 0 ||(plain->le == 0 && plain->resplen != 0))
	{
		ES_VERIFY(ESR_OK == BuildAPDULeTLV(plain, safeApdu, dataTLVLen, leTLV, &leTLVLen, m_SMtype), ESR_GENERAL_ERROR);				
	}
	ES_VERIFY(ESR_OK == BuildAPDUMacTLV(safeApdu, dataTLVLen, leTLVLen, macTLV, &macTLVLen, m_SMtype), ESR_GENERAL_ERROR);
	memset(safeApdu+4, 0, *safeApduLen-4);
	sm->lc = sm->datalen = dataTLVLen+leTLVLen+macTLVLen;
	if (sm->lc > 0xFF)
	{
		sm->cse = SC_APDU_CASE_4_EXT;
		safeApdu[4] = (unsigned char)((sm->lc)/0x10000);
		safeApdu[5] = (unsigned char)(((sm->lc)/0x100)%0x100);
		safeApdu[6] = (unsigned char)((sm->lc)%0x100);
		tmp_lc = 3;
	} 
	else
	{
		safeApdu[4] = (unsigned char)sm->lc;
		tmp_lc = 1;
	}
	memcpy(safeApdu+4+tmp_lc, dataTLV, dataTLVLen);
	memcpy(safeApdu+4+tmp_lc+dataTLVLen, leTLV, leTLVLen);
	memcpy(safeApdu+4+tmp_lc+dataTLVLen+leTLVLen, macTLV, macTLVLen);
	memcpy(sm->data, safeApdu + 4 + tmp_lc, sm->datalen);
	*safeApduLen = 0;
	if (4 == leTLVLen)
	{
		sm->cse = SC_APDU_CASE_4_EXT;
		*(safeApdu+4+tmp_lc+sm->lc)= (unsigned char)(plain->le/0x100);
		*(safeApdu+4+tmp_lc+sm->lc+1) = (unsigned char)(plain->le%0x100);
		tmp_le = 2;
	}
	else if (3 == leTLVLen)
	{
		*(safeApdu+4+tmp_lc+sm->lc) = (unsigned char)plain->le;
		tmp_le = 1;
	}
	*safeApduLen += 4+tmp_lc+dataTLVLen+leTLVLen+macTLVLen+tmp_le;
	//计算le
//	sm->le = CalcLe(plain_le);
	return ESR_OK;
}


static int es_ep2k3_sm_wrap_apdu(struct sc_card *card,
		struct sc_apdu *plain, struct sc_apdu *sm)
{
	int r;
	unsigned char safeApdu[4096] = {0};
	size_t safeApduLen = sizeof(safeApdu);
	size_t ssize=0;
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

//	es_ep2k3_refresh(card);
	if (m_SMTrans)
	{
		plain->cla |= 0x0C;
	}

	sm->cse = plain->cse;
	sm->cla = plain->cla;
	sm->ins = plain->ins;
	sm->p1 = plain->p1;
	sm->p2 = plain->p2;
	sm->lc = plain->lc;
	sm->le = plain->le;
	sm->control = plain->control;
	sm->flags = plain->flags;

	switch(sm->cla & 0x0C)
	{
		case 0x00:
		case 0x04:
			{
				sm->datalen = plain->datalen;
				sm->data = plain->data;
				sm->resplen = plain->resplen;
				sm->resp = plain->resp;
			}		
			break;
		case 0x0C:
			{
				memset(safeApdu, 0, sizeof(safeApdu));
				ES_VERIFY(ESR_OK == Build_Ciphertext_APDU(plain, sm, safeApdu, &safeApduLen), SC_ERROR_CARD_CMD_FAILED);
			}
			break;
		default:
			return SC_ERROR_INCORRECT_PARAMETERS;
	}
	return SC_SUCCESS;
}

static ES_RV Parse_Plaintext_APDU(unsigned char* pCiphertext, unsigned char* pPlaintext, unsigned long* pulPlaintextLen)
{
	unsigned long ulcipherLen;
	unsigned long ulCipherCursor;
	unsigned char iv[16] = {0};
	unsigned char plaintext[4096] = {0};
	if (pCiphertext[0] == 0x99)
	{
//		memcpy(pPlaintext, &pCiphertext[2], 2);
//		*pulPlaintextLen = 2;
		return ESR_OK;
	}
	if (0x01==pCiphertext[2] && 0x82!=pCiphertext[1])
	{
		ulcipherLen = pCiphertext[1];
		ulCipherCursor = 3;
	}
	else if (0x01==pCiphertext[3] && 0x81==pCiphertext[1])
	{
		ulcipherLen = pCiphertext[2];
		ulCipherCursor = 4;
	}
	else if (0x01==pCiphertext[4] && 0x82==pCiphertext[1])
	{
		ulcipherLen = pCiphertext[2]*0x100;
		ulcipherLen += pCiphertext[3];
		ulCipherCursor = 5;
	}
	else
	{
		return ESR_DEVICE_ERROR;			
	}
	if (KEY_TYPE_AES == m_SMtype)
	{
		aes128_decrypt_cbc(m_KSenc, 16, iv, &pCiphertext[ulCipherCursor], ulcipherLen-1, plaintext);
	}
	else
	{
		des3_decrypt_cbc(m_KSenc, 16, iv, &pCiphertext[ulCipherCursor], ulcipherLen-1, plaintext);
	}
	while(0x80!=plaintext[ulcipherLen-2] && (ulcipherLen-2>0))
	{
		ulcipherLen--;
	}
	if (2 == ulcipherLen)
	{
		return ESR_DEVICE_ERROR;
	}
	memcpy(pPlaintext, plaintext, ulcipherLen-2);
	*pulPlaintextLen = ulcipherLen-2;
	return ESR_OK;
}

static int es_ep2k3_sm_unwrap_apdu(struct sc_card *card,
		struct sc_apdu *sm, struct sc_apdu *plain)
{
	int r;
	size_t len = 0;
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	r = sc_check_sw(card, sm->sw1, sm->sw2);
	if (r == SC_SUCCESS)
	{
		if (m_SMTrans)
		{
			ES_VERIFY(ESR_OK == Parse_Plaintext_APDU(sm->resp, plain->resp, &len), SC_ERROR_CARD_CMD_FAILED);
			plain->resplen = len;
		}
		else
		{
			memcpy(plain->resp, sm->resp, sm->resplen);
			plain->resplen = sm->resplen;
		}
	}
	plain->sw1 = sm->sw1;
	plain->sw2 = sm->sw2;
//	if( sm->resplen != 0 )
//	{
//		sc_apdu_log(card->ctx, SC_LOG_DEBUG_VERBOSE, plain->resp, plain->resplen, 0);
//	}

	return SC_SUCCESS;
}

static int es_ep2k3_transmit_apdu(sc_card_t *card, sc_apdu_t *apdu)
{
	int r;
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
//	es_ep2k3_refresh(card);

	r = sc_transmit_apdu(card, apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	/* 	r = sc_check_sw(card, apdu->sw1, apdu->sw2);
		SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU check_sw failed");
		*/
	return r;
}

static int cmdGetData(sc_card_t *card, unsigned char type, unsigned char* data, size_t datalen)
{
	int r;
	sc_apdu_t apdu;
	unsigned char resp[SC_MAX_APDU_BUFFER_SIZE] = {0};
	size_t resplen = SC_MAX_APDU_BUFFER_SIZE;
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	//	APDU apdu(0x00, 0xCA, 0x01, type, 00);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xca, 0x01, type);
	apdu.resp = resp;
	apdu.le = 0;
	apdu.resplen = resplen;
	if (0x86 == type)
	{
		unsigned char safeTransmit = m_SMTrans;
		m_SMTrans = SM_PLAIN;
		r = sc_transmit_apdu(card, &apdu);
		m_SMTrans = safeTransmit;
	}
	else
	{
		r = sc_transmit_apdu(card, &apdu);
	}	
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU GetData failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "GetData failed");
	memcpy(data, resp, datalen);
	return r;
}




/* es_ep2k3_* functions */

static void es_ep2k3_reverse_buffer(u8* buff,size_t size)
{
	u8 t;
	u8 * end=buff+size-1;

	while(buff<end)
	{
		t = *buff;
		*buff = *end;
		*end=t;
		++buff;
		--end;
	}
}

static int es_ep2k3_match_card(sc_card_t *card)
{
	int i;
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	i = _sc_match_atr(card, es_ep2k3_atrs, &card->type);
	if (i < 0)
		return 0;		

	return 1;
}

static int es_ep2k3_init(sc_card_t *card)
{
	unsigned int flags;
	unsigned char data[SC_MAX_APDU_BUFFER_SIZE] = {0};
	size_t datalen = SC_MAX_APDU_BUFFER_SIZE;
	unsigned char size[SC_MAX_APDU_BUFFER_SIZE] = {0};
	size_t sizelen = SC_MAX_APDU_BUFFER_SIZE;
	unsigned char safeTransmit = 0x00;
	sc_apdu_t apdu;
	unsigned char rbuf[SC_MAX_APDU_BUFFER_SIZE] = {0};
	unsigned char random[16] = {0};
	int r;


	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	card->name = "es_ep2k3";
	card->cla  = 0x00;
	card->drv_data = NULL;
	card->ctx->use_sm = 1;

	m_SMTrans = SM_SCP01;
//	m_SMTrans = SM_PLAIN;
	m_algRSALen = 0x00;
	m_apduSize = 0;
	//	memset(m_mechanismHW, 0x00, sizeof(unsigned long)*128);
	//	m_mechanismHWNum = 0;

	ES_VERIFY(SC_SUCCESS == cmdGetData(card, 0x86, data, datalen), SC_ERROR_CARD_CMD_FAILED);
	if (0x01 == data[2])
	{
		m_SMtype = KEY_TYPE_AES;
	}
	else
	{
		m_SMtype = KEY_TYPE_DES;
	}

	es_ep2k3_refresh(card);

//	r = sc_get_challenge(card, random, 8);
//	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "get challenge GetExternalKeyRetries failed");
//	ES_VERIFY(SC_SUCCESS == cmdGetData(card, 0x84, size, sizelen), SC_ERROR_CARD_CMD_FAILED);
//	m_apduSize = size[0]*1024;

	m_apduSize = 1024;
	flags =SC_ALGORITHM_ONBOARD_KEY_GEN
		| SC_ALGORITHM_RSA_RAW
		| SC_ALGORITHM_RSA_HASH_NONE;

	_sc_card_add_rsa_alg(card, 512, flags, 0x10001);
	_sc_card_add_rsa_alg(card, 768, flags, 0x10001);
	_sc_card_add_rsa_alg(card,1024, flags, 0x10001);
	_sc_card_add_rsa_alg(card,2048, flags, 0x10001);

	card->caps = SC_CARD_CAP_RNG |
//		SC_CARD_CAP_USE_FCI_AC |
		SC_CARD_CAP_APDU_EXT;

	/* we need read_binary&friends with max 224 bytes per read */
//	if (card->max_send_size > 224)
		card->max_send_size = 224;
//	if (card->max_recv_size > 224)
		card->max_recv_size = 224;
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,SC_SUCCESS);
}

static int es_ep2k3_read_binary(sc_card_t *card,
			       unsigned int idx, u8 *buf, size_t count,
			       unsigned long flags)
{
	sc_apdu_t apdu;
	u8 recvbuf[SC_MAX_EXT_APDU_BUFFER_SIZE] = {0};
	int r;

	if (idx > 0x7fff) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "invalid EF offset: 0x%X > 0x7FFF", idx);
		return SC_ERROR_OFFSET_TOO_LARGE;
	}

	assert(count <= (card->max_recv_size > 0 ? card->max_recv_size : 256));
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xB0,
		       (idx >> 8) & 0x7F, idx & 0xFF);
	if( count > 255 )
	{
		apdu.cse = SC_APDU_CASE_2_EXT;
	}
	apdu.le = count;
	apdu.resplen = count;
	apdu.resp = recvbuf;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	if (apdu.resplen == 0)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, sc_check_sw(card, apdu.sw1, apdu.sw2));
	memcpy(buf, recvbuf, apdu.resplen);

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, apdu.resplen);
}
static int es_ep2k3_update_binary(sc_card_t *card,
				 unsigned int idx, const u8 *buf,
				size_t count, unsigned long flags)
{
	sc_apdu_t apdu;
	int r;

	assert(count <= (card->max_send_size > 0 ? card->max_send_size : 255));

	if (idx > 0x7fff) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "invalid EF offset: 0x%X > 0x7FFF", idx);
		return SC_ERROR_OFFSET_TOO_LARGE;
	}

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xD6,
		       (idx >> 8) & 0x7F, idx & 0xFF);
	if( count > 255 )
	{
		apdu.cse = SC_APDU_CASE_3_EXT;
	}
	apdu.lc = count;
	apdu.datalen = count;
	apdu.data = buf;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, sc_check_sw(card, apdu.sw1, apdu.sw2),
		    "Card returned error");
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, count);
}
static int es_ep2k3_hook_path(struct sc_path *path, int inc)
{
	u8 fid_h = path->value[path->len-2];
	u8 fid_l = path->value[path->len-1];
	switch ( fid_h )
	{
		case 0x29 :
		case 0x30 :
		case 0x31 :
		case 0x32 :
		case 0x33 :
		case 0x34 :
			if( inc )
			{
				fid_l = fid_l * FID_STEP;
			}
			else
			{
				fid_l = fid_l / FID_STEP;
			}
			path->value[path->len-1] = fid_l;

			return 1;
			break;
		default :
			break;
	}
	return 0;
}

static void es_ep2k3_hook_file(struct sc_file *file, int inc)
{
	int fidl = file->id & 0xff;
	int fidh = file->id & 0xff00;
	if( es_ep2k3_hook_path(&file->path, inc) )
	{
		if( inc )
		{
		file->id = fidh + fidl * FID_STEP;
		}
		else
		{
		file->id = fidh + fidl / FID_STEP;
		}
	}
}

static int es_ep2k3_select_fid_(sc_card_t *card,
			       const sc_path_t *in_path,
			       sc_file_t **file_out)
{
	sc_context_t *ctx;
	sc_apdu_t apdu;
	u8 buf[SC_MAX_APDU_BUFFER_SIZE] = {0};
	u8 pathbuf[SC_MAX_PATH_SIZE], *path = pathbuf;
	int r, pathlen;
	sc_file_t *file = NULL;

	assert(card != NULL && in_path != NULL);
	ctx = card->ctx;
	es_ep2k3_hook_path(in_path, 1);
	memcpy(path, in_path->value, in_path->len);
	pathlen = in_path->len;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, 0x00, 0x00);
	
	switch (in_path->type) {
	case SC_PATH_TYPE_FILE_ID:
		apdu.p1 = 0;
		if (pathlen != 2)
			return SC_ERROR_INVALID_ARGUMENTS;
		break;
	case SC_PATH_TYPE_DF_NAME:
		apdu.p1 = 4;
		break;
	case SC_PATH_TYPE_PATH:
		apdu.p1 = 8;
		if (pathlen >= 2 && memcmp(path, "\x3F\x00", 2) == 0) {
			if (pathlen == 2) {	/* only 3F00 supplied */
				apdu.p1 = 0;
				break;
			}
			path += 2;
			pathlen -= 2;
		}
		break;
	case SC_PATH_TYPE_FROM_CURRENT:
		apdu.p1 = 9;
		break;
	case SC_PATH_TYPE_PARENT:
		apdu.p1 = 3;
		pathlen = 0;
		apdu.cse = SC_APDU_CASE_2_SHORT;
		break;
	default:
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_ARGUMENTS);
	}
	apdu.p2 = 0;		/* first record, return FCI */
	apdu.lc = pathlen;
	apdu.data = path;
	apdu.datalen = pathlen;

	if (file_out != NULL) {
		apdu.resp = buf;
		apdu.resplen = sizeof(buf);
//		apdu.le = card->max_recv_size > 0 ? card->max_recv_size : 256;
		apdu.le = 0;
	} else
		apdu.cse = (apdu.lc == 0) ? SC_APDU_CASE_1 : SC_APDU_CASE_3_SHORT;

	if(path[0] == 0x29) {
		//Can't select prk file, so fake fci.
		//62 16 82 02 11 00 83 02 29 00 85 02 08 00 86 08 FF 90 90 90 FF FF FF FF
		apdu.resplen = 0x18;
		memcpy(apdu.resp, "\x6f\x16\x82\x02\x11\x00\x83\x02\x29\x00\x85\x02\x08\x00\x86\x08\xff\x90\x90\x90\xff\xff\xff\xff", apdu.resplen);
		apdu.resp[9] = path[1];
		apdu.sw1 = 0x90;
		apdu.sw2 = 0x00;
	}
	else {
		r = sc_transmit_apdu(card, &apdu);
		SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	}
	if (file_out == NULL) {
		if (apdu.sw1 == 0x61)
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, 0);
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, sc_check_sw(card, apdu.sw1, apdu.sw2));
	}

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);

	if (apdu.resplen < 2)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	switch (apdu.resp[0]) {
	case 0x6F:
		file = sc_file_new();
		if (file == NULL)
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_OUT_OF_MEMORY);
		file->path = *in_path;
		if (card->ops->process_fci == NULL) {
			sc_file_free(file);
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_NOT_SUPPORTED);
		}
		if ((size_t)apdu.resp[1] + 2 <= apdu.resplen)
			card->ops->process_fci(card, file, apdu.resp+2, apdu.resp[1]);
		es_ep2k3_hook_file(file, 0);
		*file_out = file;
		break;
	case 0x00:	/* proprietary coding */
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	default:
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	}
	return 0;
}
static int es_ep2k3_select_fid(sc_card_t *card,
								unsigned int id_hi, unsigned int id_lo,
								sc_file_t **file_out)
{
	int r;
	sc_file_t *file=0;
	sc_path_t path;

	path.type=SC_PATH_TYPE_FILE_ID;
	path.value[0]=id_hi;
	path.value[1]=id_lo;
	path.len=2;

	r = es_ep2k3_select_fid_(card,&path,&file);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");

	/* update cache */
	if (file->type == SC_FILE_TYPE_DF) {
		 card->cache.current_path.type = SC_PATH_TYPE_PATH;
		 card->cache.current_path.value[0] = 0x3f;
		 card->cache.current_path.value[1] = 0x00;
		 if (id_hi == 0x3f && id_lo == 0x00){
			  card->cache.current_path.len = 2;
		 }else{
			  card->cache.current_path.len = 4;
			  card->cache.current_path.value[2] = id_hi;
			  card->cache.current_path.value[3] = id_lo;
		 }
	}
	
	if (file_out)
		 *file_out = file;

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_SUCCESS);
}

static int es_ep2k3_select_aid(sc_card_t *card,
								const sc_path_t *in_path,
								sc_file_t **file_out)
{
	int r = 0;

	if (card->cache.valid 
		&& card->cache.current_path.type == SC_PATH_TYPE_DF_NAME
		&& card->cache.current_path.len == in_path->len
		&& memcmp(card->cache.current_path.value, in_path->value, in_path->len)==0 )
	{
		 if(file_out)
		 {
			  *file_out = sc_file_new();
			  if(!file_out)
				   SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_OUT_OF_MEMORY);
		 }
	}
	else
	{
		 r = iso_ops->select_file(card,in_path,file_out);
		 SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");

		 /* update cache */
		 card->cache.current_path.type = SC_PATH_TYPE_DF_NAME;
		 card->cache.current_path.len = in_path->len;
		 memcpy(card->cache.current_path.value,in_path->value,in_path->len);
	}
	if (file_out) {
		 sc_file_t *file = *file_out;
		 assert(file);

		 file->type = SC_FILE_TYPE_DF;
		 file->ef_structure = SC_FILE_EF_UNKNOWN;
		 file->path.len = 0;
		 file->size = 0;
		 /* AID */
		 memcpy(file->name,in_path->value,in_path->len);
		 file->namelen = in_path->len;
		 file->id = 0x0000;
	}
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
}

static int es_ep2k3_select_file(sc_card_t *card,
								 const sc_path_t *in_path,
								 sc_file_t **file_out);

static int es_ep2k3_select_path(sc_card_t *card,
								const u8 pathbuf[16], const size_t len,
								sc_file_t **file_out)
{
	 u8 n_pathbuf[SC_MAX_PATH_SIZE];
	 const u8 *path=pathbuf;
	 size_t pathlen=len;
	 int bMatch = -1;
	 unsigned int i;
	 int r;

	 if (pathlen%2 != 0 || pathlen > 6 || pathlen <= 0)
		  SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_ARGUMENTS);

	 /* if pathlen == 6 then the first FID must be MF (== 3F00) */
	 if (pathlen == 6 && ( path[0] != 0x3f || path[1] != 0x00 ))
		  SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_ARGUMENTS);

	 /* unify path (the first FID should be MF) */
	 if (path[0] != 0x3f || path[1] != 0x00)
	 {
		  n_pathbuf[0] = 0x3f;
		  n_pathbuf[1] = 0x00;
		  for (i=0; i< pathlen; i++)
			   n_pathbuf[i+2] = pathbuf[i];
		  path = n_pathbuf;
		  pathlen += 2; 
	 }
	
	 /* check current working directory */
	 if (card->cache.valid 
		 && card->cache.current_path.type == SC_PATH_TYPE_PATH
		 && card->cache.current_path.len >= 2
		 && card->cache.current_path.len <= pathlen )
	 {
		  bMatch = 0;
		  for (i=0; i < card->cache.current_path.len; i+=2)
			   if (card->cache.current_path.value[i] == path[i] 
				   && card->cache.current_path.value[i+1] == path[i+1] )
					bMatch += 2;
	 }

	 if ( card->cache.valid && bMatch > 2 )
	 {
		  if ( pathlen - bMatch == 2 )
		  {
			   /* we are in the rigth directory */
			   return es_ep2k3_select_fid(card, path[bMatch], path[bMatch+1], file_out);
		  }
		  else if ( pathlen - bMatch > 2 )
		  {
			   /* two more steps to go */
			   sc_path_t new_path;
	
			   /* first step: change directory */
			   r = es_ep2k3_select_fid(card, path[bMatch], path[bMatch+1], NULL);
			   SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "SELECT FILE (DF-ID) failed");
		
			   new_path.type = SC_PATH_TYPE_PATH;
			   new_path.len  = pathlen - bMatch-2;
			   memcpy(new_path.value, &(path[bMatch+2]), new_path.len);
			   /* final step: select file */
			   return es_ep2k3_select_file(card, &new_path, file_out);
		  }
		  else /* if (bMatch - pathlen == 0) */
		  {
			   /* done: we are already in the
				* requested directory */
			   sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
				"cache hit\n");
			   /* copy file info (if necessary) */
			   if (file_out) {
					sc_file_t *file = sc_file_new();
					if (!file)
						 SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_OUT_OF_MEMORY);
					file->id = (path[pathlen-2] << 8) +
						 path[pathlen-1];
					file->path = card->cache.current_path;
					file->type = SC_FILE_TYPE_DF;
					file->ef_structure = SC_FILE_EF_UNKNOWN;
					file->size = 0;
					file->namelen = 0;
					file->magic = SC_FILE_MAGIC;
					*file_out = file;
			   }
			   /* nothing left to do */
			   return SC_SUCCESS;
		  }
	 }
	 else
	 {
		  /* no usable cache */
		  for ( i=0; i<pathlen-2; i+=2 )
		  {
			   r = es_ep2k3_select_fid(card, path[i], path[i+1], NULL);
			   SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "SELECT FILE (DF-ID) failed");
		  }
		  return es_ep2k3_select_fid(card, path[pathlen-2], path[pathlen-1], file_out);
	 }
}

static int es_ep2k3_select_file(sc_card_t *card,
								 const sc_path_t *in_path,
								 sc_file_t **file_out)
{
	 int r;
	 char pbuf[SC_MAX_PATH_STRING_SIZE];
	 assert(card);
	 assert(in_path);
	 SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);


	  r = sc_path_print(pbuf, sizeof(pbuf), &card->cache.current_path);
	  if (r != SC_SUCCESS)
		 pbuf[0] = '\0';
		
	  sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
		"current path (%s, %s): %s (len: %u)\n",
		   (card->cache.current_path.type==SC_PATH_TYPE_DF_NAME?"aid":"path"),
		   (card->cache.valid?"valid":"invalid"), pbuf,
		   card->cache.current_path.len);
	 
	 switch(in_path->type)
	 {
	 case SC_PATH_TYPE_FILE_ID:
		  if (in_path->len != 2)
			   SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,SC_ERROR_INVALID_ARGUMENTS);
		  return es_ep2k3_select_fid(card,in_path->value[0],in_path->value[1], file_out);
	 case SC_PATH_TYPE_DF_NAME:
		  return es_ep2k3_select_aid(card,in_path,file_out);
	 case SC_PATH_TYPE_PATH:
		  return es_ep2k3_select_path(card,in_path->value,in_path->len,file_out);
	 default:
		  SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_ARGUMENTS);
	 }
}

static int es_ep2k3_set_security_env(sc_card_t *card,
				    const sc_security_env_t *env,
				    int se_num)
{
	sc_apdu_t apdu;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE] = {0};
	u8 *p;
	unsigned short fid = 0;
	int r, locked = 0;

	assert(card != NULL && env != NULL);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, 0);
	switch (env->operation) {
	case SC_SEC_OPERATION_DECIPHER:
		apdu.p2 = 0xB8;
		break;
	case SC_SEC_OPERATION_SIGN:
		apdu.p2 = 0xB8;
		break;
	default:
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	p = sbuf;
		*p++ = 0x80;	/* algorithm reference */
		*p++ = 0x01;
		*p++ = 0x84;

		*p++ = 0x81;
		*p++ = 0x02;
		
		fid = 0x2900;
		fid += (unsigned short)(0x20 * (env->key_ref[0] & 0xff));
		*p++ = fid >> 8;
		*p++ = fid & 0xff;
	r = p - sbuf;
	apdu.lc = r;
	apdu.datalen = r;
	apdu.data = sbuf;
	if (se_num > 0) {
		r = sc_lock(card);
		SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "sc_lock() failed");
		locked = 1;
	}
	if (apdu.datalen != 0) {
		r = sc_transmit_apdu(card, &apdu);
		if (r) {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
				"%s: APDU transmit failed", sc_strerror(r));
			goto err;
		}
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		if (r) {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
				"%s: Card returned error", sc_strerror(r));
			goto err;
		}
	}
	if (se_num <= 0)
		return 0;
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0xF2, se_num);
	r = sc_transmit_apdu(card, &apdu);
	sc_unlock(card);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	return sc_check_sw(card, apdu.sw1, apdu.sw2);
err:
	if (locked)
		sc_unlock(card);
	return r;
}

static int es_ep2k3_restore_security_env(sc_card_t *card, int se_num)
{
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_NORMAL);
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_SUCCESS);
}

static int es_ep2k3_compute_signature(sc_card_t *card,
				     const u8 * data, size_t datalen,
				     u8 * out, size_t outlen)
{
	int r;
	sc_apdu_t apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE] = {0};
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE] = {0};

	assert(card != NULL && data != NULL && out != NULL);
	if (datalen > 255)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_ARGUMENTS);

	/* INS: 0x2A  PERFORM SECURITY OPERATION
	 * P1:  0x9E  Resp: Digital Signature
	 * P2:  0x9A  Cmd: Input for Digital Signature */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, 0x80,
		       0x86);
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf); /* FIXME */
	apdu.le = 256;

	memcpy(sbuf, data, datalen);
	apdu.data = sbuf;
	apdu.lc = datalen;
	apdu.datalen = datalen;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
		size_t len = apdu.resplen > outlen ? outlen : apdu.resplen;

		memcpy(out, apdu.resp, len);
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, len);
	}
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, sc_check_sw(card, apdu.sw1, apdu.sw2));
}

static int es_ep2k3_decipher(sc_card_t *card,
			    const u8 * crgram, size_t crgram_len,
			    u8 * out, size_t outlen)
{
	int       r;
	sc_apdu_t apdu;
	u8        *sbuf = NULL;

	assert(card != NULL && crgram != NULL && out != NULL);
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_NORMAL);

	sbuf = malloc(crgram_len + 1);
	if (sbuf == NULL)
		return SC_ERROR_OUT_OF_MEMORY;

	/* INS: 0x2A  PERFORM SECURITY OPERATION
	 * P1:  0x80  Resp: Plain value
	 * P2:  0x86  Cmd: Padding indicator byte followed by cryptogram */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4, 0x2A, 0x80, 0x86);
	apdu.resp    = out;
	apdu.resplen = outlen;
	/* if less than 256 bytes are expected than set Le to 0x00
	 * to tell the card the we want everything available (note: we
	 * always have Le <= crgram_len) */
	apdu.le      = (outlen >= 256 && crgram_len < 256) ? 256 : outlen;
	/* Use APDU chaining with 2048bit RSA keys if the card does not do extended APDU-s */
	if ((crgram_len+1 > 255) && !(card->caps & SC_CARD_CAP_APDU_EXT))
		apdu.flags |= SC_APDU_FLAGS_CHAINING;
	
	sbuf[0] = 0; /* padding indicator byte, 0x00 = No further indication */
	memcpy(sbuf + 1, crgram, crgram_len);
	apdu.data = sbuf;
	apdu.lc = crgram_len + 1;
	apdu.datalen = crgram_len + 1;
	r = sc_transmit_apdu(card, &apdu);
	sc_mem_clear(sbuf, crgram_len + 1);
	free(sbuf);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, apdu.resplen);
	else
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, sc_check_sw(card, apdu.sw1, apdu.sw2));
}
static int 
acl_to_ac_byte(struct sc_card *card, const struct sc_acl_entry *e)
{
	unsigned key_ref;

	if (e == NULL)
		return SC_ERROR_OBJECT_NOT_FOUND;
	
	switch (e->method) {
	case SC_AC_NONE:
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, ES_AC_MAC_NOLESS|ES_AC_EVERYONE);
	case SC_AC_NEVER:
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, ES_AC_MAC_NOLESS|ES_AC_NOONE);
	default:
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, ES_AC_MAC_NOLESS|ES_AC_USER);
	}
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INCORRECT_PARAMETERS);
}
static int es_ep2k3_process_fci(sc_card_t *card, sc_file_t *file,
		       const u8 *buf, size_t buflen)
{
	sc_context_t *ctx = card->ctx;
	size_t taglen, len = buflen;
	const u8 *tag = NULL, *p = buf;

	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "processing FCI bytes");
	tag = sc_asn1_find_tag(ctx, p, len, 0x83, &taglen);
	if (tag != NULL && taglen == 2) {
		file->id = (tag[0] << 8) | tag[1];
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL,
			"  file identifier: 0x%02X%02X", tag[0], tag[1]);
	}
	tag = sc_asn1_find_tag(ctx, p, len, 0x80, &taglen);
	if (tag != NULL && taglen > 0 && taglen < 3) {
		file->size = tag[0];
		if (taglen == 2)
			file->size = (file->size << 8) + tag[1];
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "  bytes in file: %d", file->size);
	}
	if (tag == NULL) {
		tag = sc_asn1_find_tag(ctx, p, len, 0x81, &taglen);
		if (tag != NULL && taglen >= 2) {
			int bytes = (tag[0] << 8) + tag[1];
			sc_debug(ctx, SC_LOG_DEBUG_NORMAL,
				"  bytes in file: %d", bytes);
			file->size = bytes;
		}
	}
	tag = sc_asn1_find_tag(ctx, p, len, 0x82, &taglen);
	if (tag != NULL) {
		if (taglen > 0) {
			unsigned char byte = tag[0];
			const char *type;

			if( byte == 0x38 ) {
				type = "DF";
				file->type = SC_FILE_TYPE_DF;
			}
			else if( 0x01 <= byte && byte <= 0x07) {
				type = "working EF";
				file->type = SC_FILE_TYPE_WORKING_EF;
				switch(byte) {
					case 0x01:
						file->ef_structure = SC_FILE_EF_TRANSPARENT;
						break;
					case 0x02:
						file->ef_structure = SC_FILE_EF_LINEAR_FIXED;
						break;
					case 0x03:
						break;
					case 0x04:
						file->ef_structure = SC_FILE_EF_LINEAR_FIXED;
						break;
					case 0x05:
						break;
					case 0x06:
						break;
					case 0x07:
						break;
					default:
						break;
				}

			}
			else if( 0x10 == byte) {
				type = "BSO";
				file->type = SC_FILE_TYPE_BSO;
			}
			else if( 0x11 <= byte) {
				type = "internal EF";
				file->type = SC_FILE_TYPE_INTERNAL_EF;
				switch (byte) {
					case 0x11:
						break;
					case 0x12:
						break;
					default:
						break;
				}
			}
			else {
				type = "unknown";
				file->type = SC_FILE_TYPE_INTERNAL_EF;

			}
			sc_debug(ctx, SC_LOG_DEBUG_NORMAL,
				"  type: %s", type);
			sc_debug(ctx, SC_LOG_DEBUG_NORMAL,
				"  EF structure: %d", byte);
		}
	}
	tag = sc_asn1_find_tag(ctx, p, len, 0x84, &taglen);
	if (tag != NULL && taglen > 0 && taglen <= 16) {
		char tbuf[128];
		memcpy(file->name, tag, taglen);
		file->namelen = taglen;

		sc_hex_dump(ctx, SC_LOG_DEBUG_NORMAL,
			file->name, file->namelen, tbuf, sizeof(tbuf));
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "  File name: %s", tbuf);
		if (!file->type)
			file->type = SC_FILE_TYPE_DF;
	}
	tag = sc_asn1_find_tag(ctx, p, len, 0x85, &taglen);
	if (tag != NULL && taglen) {
		sc_file_set_prop_attr(file, tag, taglen); 
	} else
		file->prop_attr_len = 0;
	tag = sc_asn1_find_tag(ctx, p, len, 0xA5, &taglen);
	if (tag != NULL && taglen) {
		sc_file_set_prop_attr(file, tag, taglen); 
	}
	tag = sc_asn1_find_tag(ctx, p, len, 0x86, &taglen);
	if (tag != NULL && taglen) {
		sc_file_set_sec_attr(file, tag, taglen); 
	}
	tag = sc_asn1_find_tag(ctx, p, len, 0x8A, &taglen);
	if (tag != NULL && taglen==1) {
		if (tag[0] == 0x01)
			file->status = SC_FILE_STATUS_CREATION;
		else if (tag[0] == 0x07 || tag[0] == 0x05)
			file->status = SC_FILE_STATUS_ACTIVATED;
		else if (tag[0] == 0x06 || tag[0] == 0x04)
			file->status = SC_FILE_STATUS_INVALIDATED;
	}
	file->magic = SC_FILE_MAGIC;

	return 0;
}
static int es_ep2k3_construct_fci(sc_card_t *card, const sc_file_t *file,
	u8 *out, size_t *outlen)
{
	u8 *p = out;
	u8 buf[64];
	unsigned char  ops[8] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	int ii, rv;

	if (*outlen < 2)
		return SC_ERROR_BUFFER_TOO_SMALL;
	*p++ = 0x62;
	p++;
	if (file->type == SC_FILE_TYPE_WORKING_EF) {
		if( file->ef_structure == SC_FILE_EF_TRANSPARENT ) {
		buf[0] = (file->size >> 8) & 0xFF;
		buf[1] = file->size & 0xFF;
		sc_asn1_put_tag(0x80, buf, 2, p, *outlen - (p - out), &p);
		}
	}
	if (file->type == SC_FILE_TYPE_DF) {
		buf[0] = 0x38;
		buf[1] = 0x00;
		sc_asn1_put_tag(0x82, buf, 2, p, *outlen - (p - out), &p);
	}
	else if( file->type == SC_FILE_TYPE_WORKING_EF )
	{
		buf[0] = file->ef_structure & 7;
		if( file->ef_structure == SC_FILE_EF_TRANSPARENT)
		{
			buf[1] = 0x00;
			sc_asn1_put_tag(0x82, buf, 2, p, *outlen - (p - out), &p);
		}
		else if ( file->ef_structure == SC_FILE_EF_LINEAR_FIXED ||
				file->ef_structure == SC_FILE_EF_LINEAR_VARIABLE) {
			buf[1] = 0x00;
			buf[2] = 0x00;
			buf[3] = 0x40;	/* record length */
			buf[4] = 0x00;	/* record count */
			sc_asn1_put_tag(0x82, buf, 5, p, *outlen - (p - out), &p);
		}
		else {
			return SC_ERROR_NOT_SUPPORTED;
		}

	} 
	else if( file->type == SC_FILE_TYPE_INTERNAL_EF ) {
		if( file->ef_structure == SC_CARDCTL_OBERTHUR_KEY_RSA_CRT )
		{
			buf[0] = 0x11;
			buf[1] = 0x00;
		}
		else if( file->ef_structure == SC_CARDCTL_OBERTHUR_KEY_RSA_PUBLIC )
		{
			buf[0] = 0x12;
			buf[1] = 0x00;
		}
		else {
			return SC_ERROR_NOT_SUPPORTED;
		}
		sc_asn1_put_tag(0x82, buf, 2, p, *outlen - (p - out), &p);
	}
	else if( file->type == SC_FILE_TYPE_BSO ) {
		buf[0] = 0x10;
		buf[1] = 0x00;
		sc_asn1_put_tag(0x82, buf, 2, p, *outlen - (p - out), &p);
	}

	buf[0] = (file->id >> 8) & 0xFF;
	buf[1] = file->id & 0xFF;
	sc_asn1_put_tag(0x83, buf, 2, p, *outlen - (p - out), &p);
	if (file->type == SC_FILE_TYPE_DF) {
		if(file->namelen != 0) {
		sc_asn1_put_tag(0x84, file->name, file->namelen, p, *outlen - (p - out), &p);
		}
		else {
			return SC_ERROR_INVALID_ARGUMENTS;
		}
	}
	if (file->type == SC_FILE_TYPE_DF) {
		//127 files at most
		sc_asn1_put_tag(0x85, "\x00\x7f", 2, p, *outlen - (p - out), &p);
	}
	else if (file->type == SC_FILE_TYPE_BSO) {
		buf[0] = file->size & 0xff;
		sc_asn1_put_tag(0x85, buf, 1, p, *outlen - (p - out), &p);
	}
	else if (file->type == SC_FILE_TYPE_INTERNAL_EF ){
		if( file->ef_structure == SC_CARDCTL_OBERTHUR_KEY_RSA_CRT ||
				file->ef_structure == SC_CARDCTL_OBERTHUR_KEY_RSA_PUBLIC )
		{
		buf[0] = (file->size >> 8) & 0xFF;
		buf[1] = file->size & 0xFF;
		sc_asn1_put_tag(0x85, buf, 2, p, *outlen - (p - out), &p);
		}
	}
	if (file->sec_attr_len) {
		assert(sizeof(buf) >= file->prop_attr_len);
		memcpy(buf, file->sec_attr, file->sec_attr_len);
		sc_asn1_put_tag(0x86, buf, file->sec_attr_len,
				p, *outlen - (p - out), &p);
	}
	else
	{
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "SC_FILE_ACL\n");
		if (file->type == SC_FILE_TYPE_DF) {
			ops[0] = SC_AC_OP_LIST_FILES;
			ops[1] = SC_AC_OP_CREATE;
			ops[3] = SC_AC_OP_DELETE;
		}
		else if (file->type == SC_FILE_TYPE_WORKING_EF) {
			if (file->ef_structure == SC_FILE_EF_TRANSPARENT) {
				ops[0] = SC_AC_OP_READ;
				ops[1] = SC_AC_OP_UPDATE;
				ops[3] = SC_AC_OP_DELETE;
			}
			else if (file->ef_structure == SC_FILE_EF_LINEAR_FIXED ||
					file->ef_structure == SC_FILE_EF_LINEAR_VARIABLE) {
				ops[0] = SC_AC_OP_READ;
				ops[1] = SC_AC_OP_UPDATE;
				ops[2] = SC_AC_OP_WRITE;
				ops[3] = SC_AC_OP_DELETE;
			}
			else {
				return SC_ERROR_NOT_SUPPORTED;
			}
		}
		else if (file->type == SC_FILE_TYPE_BSO) {
			ops[0] = SC_AC_OP_UPDATE;
			ops[3] = SC_AC_OP_DELETE;
		}
		else if (file->type == SC_FILE_TYPE_INTERNAL_EF) {
			if (file->ef_structure == SC_CARDCTL_OBERTHUR_KEY_RSA_CRT) {
				ops[1] = SC_AC_OP_UPDATE;
				ops[2] = SC_AC_OP_CRYPTO;
				ops[3] = SC_AC_OP_DELETE;
			}
			else if (file->ef_structure == SC_CARDCTL_OBERTHUR_KEY_RSA_PUBLIC) {
				ops[0] = SC_AC_OP_READ;
				ops[1] = SC_AC_OP_UPDATE;
				ops[2] = SC_AC_OP_CRYPTO;
				ops[3] = SC_AC_OP_DELETE;
			}
		}
		else
		{
			return SC_ERROR_NOT_SUPPORTED;
		}
		for (ii = 0; ii < sizeof(ops); ii++) {
			const struct sc_acl_entry *entry;

			buf[ii] = 0xFF;
			if (ops[ii]==0xFF)
				continue;
			entry = sc_file_get_acl_entry(file, ops[ii]);
			rv = acl_to_ac_byte(card,entry);
			SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, rv, "Invalid ACL");
			buf[ii] = rv;
		}
		sc_asn1_put_tag(0x86, buf, sizeof(ops),
				p, *outlen - (p - out), &p);

	}

	if (file->ef_structure == SC_CARDCTL_OBERTHUR_KEY_RSA_PUBLIC ) {
		sc_asn1_put_tag(0x87, "\x00\x66", 2,
				p, *outlen - (p - out), &p);
	}

	out[1] = p - out - 2;

	*outlen = p - out;
	return 0;
}


static int es_ep2k3_create_file(sc_card_t *card, sc_file_t *file)
{
	int r;
	size_t len;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE] = {0};
	sc_apdu_t apdu;

	len = SC_MAX_APDU_BUFFER_SIZE;

	es_ep2k3_hook_file(file, 1);

	if (card->ops->construct_fci == NULL)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_NOT_SUPPORTED);
	r = es_ep2k3_construct_fci(card, file, sbuf, &len);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "construct_fci() failed");
	
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xE0, 0x00, 0x00);
	apdu.lc = len;
	apdu.datalen = len;
	apdu.data = sbuf;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU sw1/2 wrong");
	es_ep2k3_hook_file(file, 0);
	return r;
}
static int es_ep2k3_delete_file(sc_card_t *card, const sc_path_t *path)
{
	int r;
	u8 sbuf[2];
	sc_apdu_t apdu;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	r = sc_select_file(card, path, NULL);
	es_ep2k3_hook_path(path, 1);
	if (r == SC_SUCCESS) {
		sbuf[0] = path->value[path->len-2];
		sbuf[1] = path->value[path->len-1];
		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xE4, 0x00, 0x00);
		apdu.lc = 2;
		apdu.datalen = 2;
		apdu.data = sbuf;
	}
	else 
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_ARGUMENTS);
	
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	return sc_check_sw(card, apdu.sw1, apdu.sw2);
}
//borrowed from card-oberthur.c, modified
	static int 
es_ep2k3_list_files(struct sc_card *card, unsigned char *buf, size_t buflen)
{
	struct sc_apdu apdu;
	unsigned char rbuf[SC_MAX_APDU_BUFFER_SIZE] = {0};
	int rv;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0x34, 0x00, 0x00);
	apdu.cla = 0x80;
	apdu.le = 0x40;
	apdu.resplen = sizeof(rbuf);
	apdu.resp = rbuf;

	rv = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, rv, "APDU transmit failed");

	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, rv, "Card returned error");

	if (apdu.resplen == 0x100 && rbuf[0]==0 && rbuf[1]==0)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, 0);

	buflen = buflen < apdu.resplen ? buflen : apdu.resplen;
	memcpy(buf, rbuf, buflen);

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, buflen);
}
static int internal_write_rsa_key_factor(sc_card_t *card,
		unsigned short fid, u8 factor,
		sc_pkcs15_bignum_t data)
{
	int r;
	sc_apdu_t apdu;
	u8 sbuff[SC_MAX_EXT_APDU_BUFFER_SIZE] = {0};

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	sbuff[0] = ((fid & 0xff00) >> 8);
	sbuff[1] = (fid & 0x00ff);
	memcpy(&sbuff[2],data.data,data.len);
	es_ep2k3_reverse_buffer(&sbuff[2],data.len);

	sc_format_apdu(card,&apdu,SC_APDU_CASE_3,0xe7,factor,0x00);
	apdu.cla = 0x80;
	apdu.lc=apdu.datalen=2+data.len;
	apdu.data=sbuff;

	r = sc_transmit_apdu(card,&apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r,"Write prkey factor failed");
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_SUCCESS);
}

static int internal_write_rsa_key(sc_card_t *card, unsigned short fid, struct sc_pkcs15_prkey_rsa *rsa)
{
	int r;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	r = internal_write_rsa_key_factor(card,fid,0x02,rsa->modulus);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "write n failed");
	r = internal_write_rsa_key_factor(card,fid,0x03,rsa->d);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "write d failed");

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,SC_SUCCESS);
}

static int hash_data(unsigned char *data, size_t datalen, unsigned char *hash)
{
	unsigned char data_hash[24] = {0};
	size_t len = 0;
	if((NULL == data) || (NULL == hash))
	{
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	sha1_digest(data, datalen, data_hash);

	len = REVERSE_ORDER4(datalen);
	memcpy(&data_hash[20], &len, 4);
	memcpy(hash, data_hash, 24);
	return SC_SUCCESS;
}
static int cmdInstallSecretKey(sc_card_t *card, unsigned char ktype, unsigned char kid, unsigned char useac, unsigned char modifyac, unsigned char* data, unsigned long dataLen)
{
	int r;
	sc_apdu_t apdu;
	unsigned char isapp = 0x00; /* appendable */
	unsigned char tmp_data[256] = {0};
	tmp_data[0] = ktype;
	tmp_data[1] = kid;
	tmp_data[2] = useac;
	tmp_data[3] = modifyac;	
	tmp_data[8] = 0xFF;
	if (0x04==ktype || 0x06==ktype)
	{
		tmp_data[4] = ES_AC_MAC_NOLESS|ES_AC_SO;
		tmp_data[5] = ES_AC_MAC_NOLESS|ES_AC_SO;
		tmp_data[7] = (kid==PIN_ID[0]?ES_AC_USER:ES_AC_SO);
		tmp_data[9] = (MAX_PIN_COUNTER<<4)|MAX_PIN_COUNTER;
	}
	memcpy(&tmp_data[10], data, dataLen);
	//	APDU apdu(0x80, 0xE3, isapp, 0x00, 10+dataLen, tmp_data);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xe3, isapp, 0x00);
	apdu.cla = 0x80;
	apdu.lc = apdu.datalen = 10 + dataLen;
	apdu.data = tmp_data;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU InstallSecretKey failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "InstallSecretKey failed");
	return r;
}

static int internal_install_pre(sc_card_t *card)
{
	int r, i, j;
	unsigned char data[32] = {0};
	/* Kenc */
	r = cmdInstallSecretKey(card, 0x01, 0x00, ES_AC_MAC_NOLESS|ES_AC_EVERYONE, ES_AC_MAC_NOLESS|ES_AC_EVERYONE, INIT_KEYenc, 16);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Install failed");
	/* Kmac */
	r = cmdInstallSecretKey(card, 0x02, 0x00, ES_AC_MAC_NOLESS|ES_AC_EVERYONE, ES_AC_MAC_NOLESS|ES_AC_EVERYONE, INIT_KEYmac, 16);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Install failed");
	//	/* aes_256 key */
	//	for (i=0; i<sizeof(AES_KeyID); i++)
	//	{
	//		r = cmdInstallSecretKey(card, 0x05, AES_KeyID[i], ES_AC_MAC_EQUAL|ES_AC_USER, ES_AC_MAC_EQUAL|ES_AC_USER, data, 32);
	//		SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Install failed");
	//	}
	//	/* 3des key */
	//	for (j=0; j<sizeof(DES_KeyID); j++)
	//	{
	//		r = cmdInstallSecretKey(card, 0x05, DES_KeyID[j], ES_AC_MAC_EQUAL|ES_AC_USER, ES_AC_MAC_EQUAL|ES_AC_USER, data, 24);
	//		SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Install failed");
	//	}
	return r;
}

static int internal_install_pin(sc_card_t *card, sc_es_ep2k3_wkey_data *pin)
	/* use external auth secret as pin */
{
	int r, i, j;
	unsigned char data[32] = {0};
	unsigned char hash[HASH_LEN] = {0};
	r = hash_data(pin->key_data.es_secret.key_val, pin->key_data.es_secret.key_len, hash);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "hash data failed");
	r = cmdInstallSecretKey(card, 0x04, pin->key_data.es_secret.kid, 
			pin->key_data.es_secret.ac[0], pin->key_data.es_secret.ac[1], 
			hash, HASH_LEN);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Install failed");
	return r;
}

static int es_ep2k3_write_key(sc_card_t *card, sc_es_ep2k3_wkey_data *data)
{
	SC_FUNC_CALLED(card->ctx, 1);

	if (data->type & SC_ES_KEY)
	{
		if( data->type == SC_ES_KEY_RSA )
		{
			return internal_write_rsa_key(card, data->key_data.es_key.fid, 
					data->key_data.es_key.rsa);
		}
		else
		{
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_NOT_SUPPORTED);
		}
	}
	else if(data->type & SC_ES_SECRET)
	{
		if( data->type == SC_ES_SECRET_PRE )
		{
			return internal_install_pre(card);
		}
		else if( data->type == SC_ES_SECRET_PIN)
		{
			return internal_install_pin(card, data);
		}
		else
		{
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_NOT_SUPPORTED);
		}
	}
	else
	{
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_NOT_SUPPORTED);
	}
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_SUCCESS);
}

static int es_ep2k3_gen_key(sc_card_t *card, sc_es_ep2k3_gen_key_data *data)
{
	int	r;
	size_t len = data->key_length;
	sc_apdu_t apdu;
	u8 rbuf[SC_MAX_EXT_APDU_BUFFER_SIZE] = {0};
	u8 sbuf[SC_MAX_EXT_APDU_BUFFER_SIZE] = {0},*p;
	struct sc_path tmp_path;

	SC_FUNC_CALLED(card->ctx, 1);

	sbuf[0] = 0x01;
	sbuf[1] = (u8)((len >> 8) & 0xff);
	sbuf[2] = (u8)(len & 0xff);
	sbuf[3] = (u8)((data->prkey_id >> 8)&0xFF);
	sbuf[4] = (u8)((data->prkey_id)&0xFF);
	sbuf[5] = (u8)((data->pukey_id >> 8)&0xFF);
	sbuf[6] = (u8)((data->pukey_id)&0xFF);

	/* generate key */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x46,  0x00, 0x00);
	apdu.lc = apdu.datalen = 7;
	apdu.data = sbuf;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	r = sc_check_sw(card,apdu.sw1,apdu.sw2);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r,"generate keypair failed");

	/* read public key via READ PUBLIC KEY */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xb4,  0x02, 0x00);
	apdu.cla = 0x80;
	apdu.lc = apdu.datalen = 2;
	apdu.data = &sbuf[5];
	apdu.resp=rbuf;
	apdu.resplen=sizeof(rbuf);
	apdu.le = 0x00;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	r = sc_check_sw(card,apdu.sw1,apdu.sw2);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r,"get pukey failed");

	if( len < apdu.resplen )
	{
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_ARGUMENTS);
	}
	data->modulus = (u8 *) malloc(len);
	if (!data->modulus)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_OUT_OF_MEMORY);

	memcpy(data->modulus,rbuf,len);
//	tmp_path.type = SC_PATH_TYPE_FILE_ID;
//	tmp_path.len = 2;
//	memcpy(tmp_path.value, &sbuf[5], 2);
//	r = sc_select_file(card, &tmp_path, NULL);
//	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "cannot select public key file");


	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_SUCCESS);
}

static int es_ep2k3_erase_card(sc_card_t *card)
{
	int r;
	u8  sbuf[2];
	sc_apdu_t apdu;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	/* invalidate cache */
	card->cache.valid = 0;
	r = sc_delete_file(card, sc_get_mf_path());

	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "delete MF failed");
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
}

static int es_ep2k3_get_serialnr(sc_card_t *card, sc_serial_number_t *serial)
{
	int	r;
	sc_apdu_t apdu;
	u8 rbuf[8];
	size_t rbuf_len = sizeof(rbuf);

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	assert(serial);

	ES_VERIFY(SC_SUCCESS == cmdGetData(card, 0x80, rbuf, rbuf_len), SC_ERROR_CARD_CMD_FAILED);

	card->serialnr.len = serial->len = 8;
	memcpy(card->serialnr.value,rbuf,8);
	memcpy(serial->value,rbuf,8);

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,SC_SUCCESS);
}

static int es_ep2k3_card_ctl(sc_card_t *card, unsigned long cmd, void *ptr)
{
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	switch (cmd)
	{
		case SC_CARDCTL_ENTERSAFE_WRITE_KEY:
			return es_ep2k3_write_key(card, (sc_es_ep2k3_wkey_data *)ptr);
		case SC_CARDCTL_ENTERSAFE_GENERATE_KEY:
			return es_ep2k3_gen_key(card, (sc_es_ep2k3_gen_key_data *)ptr);
		case SC_CARDCTL_ERASE_CARD:
			return es_ep2k3_erase_card(card);
		case SC_CARDCTL_GET_SERIALNR:
			return es_ep2k3_get_serialnr(card, (sc_serial_number_t *)ptr);
		default:
			return SC_ERROR_NOT_SUPPORTED;
	}
}

static void internal_sanitize_pin_info(struct sc_pin_cmd_pin *pin, unsigned int num)
{
	pin->encoding = SC_PIN_ENCODING_ASCII;
	pin->min_length = 4;
	pin->max_length = 16;
	pin->pad_length = 16;
	pin->offset = 5 + num * 16;
	pin->pad_char = 0x00;
}

static int cmdGetExternalKeyRetries(sc_card_t *card, unsigned char kid, unsigned char* retries)
{
	int r;
	sc_apdu_t apdu;
	unsigned char random[16] = {0};
	unsigned char resp[SC_MAX_APDU_BUFFER_SIZE] = {0};
	size_t resplen = SC_MAX_APDU_BUFFER_SIZE;
	r = sc_get_challenge(card, random, 8);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "get challenge GetExternalKeyRetries failed");

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0x82, 0x01, 0x80|kid); 
	apdu.resp = resp;
	apdu.resplen = resplen;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU GetExternalKeyRetries failed");
	if (retries && ((0x63 == (apdu.sw1 & 0xff)) && (0xC0 == (apdu.sw2 & 0xf0))))
	{
		*retries = (apdu.sw2 & 0x0f);
		r = SC_SUCCESS;
	}
	else
	{
		SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "GetExternalKeyRetries failed");
	}
	return r;
}

static int cmdExternalKeyAuth(sc_card_t *card, unsigned char kid, unsigned char* data, size_t datalen)
{
	int r;
	sc_apdu_t apdu;
	unsigned char random[16] = {0};
	unsigned char tmp_data[16] = {0};
	unsigned char hash[HASH_LEN] = {0};
	unsigned char iv[16] = {0};
	r = sc_get_challenge(card, random, 8);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "get challenge ExternalKeyAuth failed");
	r = hash_data(data, datalen, hash);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "hash data failed");
	des3_encrypt_cbc(hash, HASH_LEN, iv, random, 8, tmp_data);
	//	APDU apdu(0x00, 0x82, 0x01, kid, 8, data);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x82, 0x01, 0x80|kid);
	apdu.lc = apdu.datalen = 8;
	apdu.data = tmp_data;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU ExternalKeyAuth failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "ExternalKeyAuth failed");
	return r;
}

static int cmdUpdateSecretKey(sc_card_t *card, unsigned char ktype, unsigned char kid, unsigned char* data, unsigned long datalen)
{
	int r;
	sc_apdu_t apdu;
	unsigned char hash[HASH_LEN] = {0};
	unsigned char tmp_data[256] = {0};
	r = hash_data(data, datalen, hash);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "hash data failed");
	tmp_data[0] = (MAX_PIN_COUNTER<<4) | MAX_PIN_COUNTER;
	memcpy(&tmp_data[1], hash, HASH_LEN);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xe5, ktype, kid);
	apdu.cla = 0x80;
	apdu.lc = apdu.datalen = 1 + HASH_LEN;
	apdu.data = tmp_data;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU UpdateSecretKey failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "UpdateSecretKey failed");
	return r;
}

static int es_ep2k3_pin_cmd(sc_card_t *card, struct sc_pin_cmd_data *data, 
		int *tries_left)
/* use external auth secret as pin */
{
	int r;
	u8 kid;
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	internal_sanitize_pin_info(&data->pin1, 0);
	internal_sanitize_pin_info(&data->pin2, 1);
	data->flags |= SC_PIN_CMD_NEED_PADDING;
	kid = data->pin_reference;
	/* get pin retries */
	if( data->cmd == SC_PIN_CMD_GET_INFO )
	{
		u8 retries = 0;
		r = cmdGetExternalKeyRetries(card, 0x80|kid, &retries);
		if( r == SC_SUCCESS )
		{
			data->pin1.max_tries = MAX_PIN_COUNTER;
			data->pin1.tries_left = retries;
		}
		return r;
	}
	/* verify */
	if( data->cmd == SC_PIN_CMD_UNBLOCK ) {
	r = cmdExternalKeyAuth(card, (kid+1), data->pin1.data, data->pin1.len);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "verify pin failed");
	}
	else {
	r = cmdExternalKeyAuth(card, kid, data->pin1.data, data->pin1.len);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "verify pin failed");

	}

	if( data->cmd == SC_PIN_CMD_CHANGE ||
			data->cmd == SC_PIN_CMD_UNBLOCK )
		/* change */
	{
		r = cmdUpdateSecretKey(card, 0x04, kid, data->pin2.data, data->pin2.len);
		SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "verify pin failed");
	}
	return r;
}
static struct sc_card_driver * sc_get_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	if (iso_ops == NULL)
		iso_ops = iso_drv->ops;

	es_ep2k3_ops = *iso_ops;

	es_ep2k3_ops.match_card = es_ep2k3_match_card;
	es_ep2k3_ops.init = es_ep2k3_init;
	es_ep2k3_ops.sm_wrap_apdu = es_ep2k3_sm_wrap_apdu;
	es_ep2k3_ops.sm_unwrap_apdu = es_ep2k3_sm_unwrap_apdu;
	es_ep2k3_ops.read_binary = es_ep2k3_read_binary;
	es_ep2k3_ops.write_binary = NULL;
//	es_ep2k3_ops.update_binary = es_ep2k3_update_binary;
	es_ep2k3_ops.write_record = NULL;
	es_ep2k3_ops.select_file = es_ep2k3_select_file;
	es_ep2k3_ops.get_response = NULL;
	es_ep2k3_ops.restore_security_env = es_ep2k3_restore_security_env;
	es_ep2k3_ops.set_security_env = es_ep2k3_set_security_env;
//	es_ep2k3_ops.decipher = es_ep2k3_decipher;
	es_ep2k3_ops.decipher = es_ep2k3_compute_signature;
	es_ep2k3_ops.compute_signature = es_ep2k3_compute_signature;
	es_ep2k3_ops.create_file = es_ep2k3_create_file;
	es_ep2k3_ops.delete_file = es_ep2k3_delete_file;
	es_ep2k3_ops.list_files = es_ep2k3_list_files;
	es_ep2k3_ops.card_ctl = es_ep2k3_card_ctl;
	es_ep2k3_ops.process_fci = es_ep2k3_process_fci;
	es_ep2k3_ops.construct_fci = es_ep2k3_construct_fci;
//	es_ep2k3_ops.= es_ep2k3_;
	es_ep2k3_ops.pin_cmd = es_ep2k3_pin_cmd;
	return &es_ep2k3_drv;
}

struct sc_card_driver * sc_get_es_ep2k3_driver(void)
{
	return sc_get_driver();
}
#endif
