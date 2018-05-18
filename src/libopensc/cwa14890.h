/**
 * cwa14890.h: Defines, Typedefs and prototype functions for SM Messaging according CWA-14890 standard.
 *
 * Copyright (C) 2010 Juan Antonio Martinez <jonsito@terra.es>
 *
 * This work is derived from many sources at OpenSC Project site,
 * (see references), and the information made public for Spanish 
 * Direccion General de la Policia y de la Guardia Civil
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

#ifndef __CWA14890_H__
#define __CWA14890_H__

#if defined(ENABLE_OPENSSL) && defined(ENABLE_SM)

/* Flags for setting SM status */
#define CWA_SM_OFF        0x00	/** Disable SM channel */
#define CWA_SM_ON         0x01	/** Enable SM channel */

/* TAGS for encoded APDU's */
#define CWA_SM_PLAIN_TAG  0x81	/** Plain value (to be protected by CC) */
#define CWA_SM_CRYPTO_TAG 0x87	/** Padding-content + cryptogram */
#define CWA_SM_MAC_TAG    0x8E	/** Cryptographic checksum (MAC) */
#define CWA_SM_LE_TAG     0x97	/** Le (to be protected by CC ) */
#define CWA_SM_STATUS_TAG 0x99	/** Processing status (SW1-SW2 mac protected ) */

/*************** data structures for CWA14890 SM handling **************/

#include "libopensc/types.h"

#include <openssl/x509.h>
#include <openssl/des.h>

/**
 * Data and function pointers to provide information to create and handle
 * Secure Channel.
 */
typedef struct cwa_provider_st {

    /************ operations related with secure channel creation *********/

	/* pre and post operations */

	/** 
 	* CWA-14890 SM stablisment pre-operations.
	*
	* This code is called before any operation required in
	* standard cwa14890 SM stablisment process. It's usually
	* used for acquiring/initialize data to be used in the
	* process (i.e: retrieve card serial number), to make sure
	* that no extra apdu is sent during the SM establishment procedure
	*
	* @param card pointer to card driver structure
	* @param provider pointer to SM data provider for DNIe
	* @return SC_SUCCESS if OK. else error code
	*/
	int (*cwa_create_pre_ops) (sc_card_t * card,
				   struct cwa_provider_st * provider);

	/** 
 	* CWA-14890 SM stablisment post-operations.
	*
	* This code is called after successful SM channel establishment
	* procedure, and before returning from create_sm_channel() function
	* May be use for store data, trace, logs and so
	*
	* @param card pointer to card driver structure
	* @param provider pointer to SM data provider for DNIe
	* @return SC_SUCCESS if OK. else error code
	*/
	int (*cwa_create_post_ops) (sc_card_t * card,
				    struct cwa_provider_st * provider);

	/**
	* Get ICC (card) intermediate CA Certificate.
	*
	* @param card Pointer to card driver structure
	* @param cert where to store resulting certificate
	* @return SC_SUCCESS if ok; else error code
	*/
	int (*cwa_get_icc_intermediate_ca_cert) (sc_card_t * card,
						 X509 ** cert);

	/**
	* Get ICC (card) certificate.
	*
	* @param card Pointer to card driver structure
	* @param cert where to store resulting certificate
	* @return SC_SUCCESS if ok; else error code
	*/
	int (*cwa_get_icc_cert) (sc_card_t * card, X509 ** cert);

	/** 
	* Obtain RSA public key from RootCA.
	*
	* @param root_ca_key pointer to resulting returned key
	* @return SC_SUCCESS if ok; else error code
	*/
	int (*cwa_get_root_ca_pubkey) (sc_card_t * card, EVP_PKEY ** key);

	/**
	* Get RSA IFD (Terminal) private key data.
	* 
	* Notice that resulting data should be kept in memory as little
	* as possible Erasing them once used
	*
	* @param card pointer to card driver structure
	* @param ifd_privkey where to store IFD private key
	* @return SC_SUCCESS if ok; else error code
	*/
	int (*cwa_get_ifd_privkey) (sc_card_t * card, EVP_PKEY ** key);

	/* TODO:
	 * CVC handling routines should be grouped in just retrieve CVC
	 * certificate. The key reference, as stated by CWA should be
	 * extracted from CVC...
	 *
	 * But to do this, an special OpenSSL with PACE extensions is
	 * needed. In the meantime, let's use binary buffers to get
	 * CVC and key references, until an CV_CERT handling API
	 * become available in standard OpenSSL
	 *
	 *@see http://openpace.sourceforge.net
	 */

	/**
 	* Retrieve IFD (application) CVC intermediate CA certificate and length.
	*
	* Returns a byte array with the intermediate CA certificate
	* (in CardVerifiable Certificate format) to be sent to the
	* card in External Authentication process
	*
	* @param card Pointer to card driver Certificate
	* @param cert Where to store resulting byte array
	* @param length len of returned byte array
	* @return SC_SUCCESS if ok; else error code
	*/
	int (*cwa_get_cvc_ca_cert) (sc_card_t * card, u8 ** cert,
				    size_t * length);

	/**
	* Retrieve IFD (application) CVC certificate and length.
	*
	* Returns a byte array with the application's certificate
	* (in CardVerifiable Certificate format) to be sent to the
	* card in External Authentication process
	*
	* @param card Pointer to card driver Certificate
	* @param cert Where to store resulting byte array
	* @param length len of returned byte array
	* @return SC_SUCCESS if ok; else error code
	*/
	int (*cwa_get_cvc_ifd_cert) (sc_card_t * card, u8 ** cert,
				     size_t * length);

	/**
	* Retrieve public key reference for Root CA to validate CVC intermediate CA certs.
	*
	* This is required in the process of On card external authenticate
	* @param card Pointer to card driver structure
	* @param buf where to store resulting key reference
	* @param len where to store buffer length
	* @return SC_SUCCESS if ok; else error code
	*/
	int (*cwa_get_root_ca_pubkey_ref) (sc_card_t * card, u8 ** buf,
					   size_t * len);

	/**
	* Get public key reference for intermediate CA to validate IFD cert.
	*
	* This is required in the process of On card external authenticate
	*
	* @param card Pointer to card driver structure
	* @param buf where to store resulting key reference
	* @param len where to store buffer length
	* @return SC_SUCCESS if ok; else error code
	*/
	int (*cwa_get_intermediate_ca_pubkey_ref) (sc_card_t * card, u8 ** buf,
						   size_t * len);

	/**
	*  Retrieve public key reference for IFD certificate.
	*
	* This tells the card with in memory key reference is to be used
	* when CVC cert is sent for external auth procedure
	*
	* @param card pointer to card driver structure
	* @param buf where to store data to be sent
	* @param len where to store data length
	* @return SC_SUCCESS if ok; else error code
	*/
	int (*cwa_get_ifd_pubkey_ref) (sc_card_t * card, u8 ** buf,
				       size_t * len);

	/**
	* Retrieve key reference for ICC private key.
	* 
	* @param card pointer to card driver structure
	* @param buf where to store data
	* @param len where to store data length
	* @return SC_SUCCESS if ok; else error
	*/
	int (*cwa_get_icc_privkey_ref) (sc_card_t * card, u8 ** buf,
					size_t * len);

	/**
	* Retrieve SN.IFD - Terminal Serial Number.
	*
	* Result SN is 8 bytes long left padded with zeroes if required.
	* The result should stored in card->sm_ctx.info.session.cwa.ifd.sn
	*
	* @param card pointer to card structure
	* @return SC_SUCCESS if ok; else error
	*/
	int (*cwa_get_sn_ifd) (sc_card_t * card);

	/**
	* Get SN.ICC - Card Serial Number.
	*  
	* Result value is 8 bytes long left padded with zeroes if needed)
	* The result should stored in card->sm_ctx.info.session.cwa.icc.sn
	*
	* @param card pointer to card structure
	* @return SC_SUCCESS if ok; else error
	*/
	int (*cwa_get_sn_icc) (sc_card_t * card);

 
} cwa_provider_t;

/************************** external function prototypes ******************/

/**
 * Create Secure channel.
 *
 * Based on Several documents:
 * - "Understanding the DNIe"
 * - "Manual de comandos del DNIe"
 * - ISO7816-4 and CWA14890-{1,2}
 *
 * @param card card info structure
 * @param provider pointer to cwa provider
 * @param flag Requested SM final state (OFF,COLD,WARM)
 * @return SC_SUCCESS if OK; else error code
 */
extern int cwa_create_secure_channel(sc_card_t * card,
				     cwa_provider_t * provider, int flag);

/**
 * Decode an APDU response.
 *
 * Calling this functions means that It's has been verified
 * That apdu response comes in TLV encoded format and needs decoding
 * Based on section 9 of CWA-14890 and Sect 6 of iso7816-4 standards
 * And DNIe's manual
 *
 * @param card card info structure
 * @param provider cwa provider data to handle SM channel
 * @param apdu apdu to be decoded
 * @return SC_SUCCESS if ok; else error code
 */
extern int cwa_decode_response(sc_card_t * card,
			       cwa_provider_t * provider,
			       sc_apdu_t * apdu);

/**
 * Encode an APDU.
 *
 * Calling this functions means that It's has been verified
 * That source apdu needs encoding
 * Based on section 9 of CWA-14890 and Sect 6 of iso7816-4 standards
 * And DNIe's manual
 *
 * @param card card info structure
 * @param provider cwa provider data to handle SM channel
 * @param from apdu to be encoded
 * @param to Where to store encoded apdu
 * @return SC_SUCCESS if ok; else error code
 */
extern int cwa_encode_apdu(sc_card_t * card,
			   cwa_provider_t * provider,
			   sc_apdu_t * from, sc_apdu_t * to);

/**
 * Gets a default cwa_provider structure.
 *
 * @param card Pointer to card driver information
 * @return default cwa_provider data, or null on error
 */
extern cwa_provider_t *cwa_get_default_provider(sc_card_t * card);

#endif				/* ENABLE_OPENSSL */

#endif
