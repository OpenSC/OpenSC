/**
 * card-dnie.c: Support for Spanish DNI electronico (DNIe card).
 *
 * Copyright (C) 2010 Juan Antonio Martinez <jonsito@terra.es>
 *
 * This work is derived from many sources at OpenSC Project site,
 * (see references) and the information made public for Spanish 
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

#define __CARD_DNIE_C__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef ENABLE_OPENSSL		/* empty file without openssl */

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/stat.h>

#include "opensc.h"
#include "cardctl.h"
#include "internal.h"
#include "compression.h"
#include "cwa14890.h"
#include "cwa-dnie.h"
#include "user-interface.h"

extern cwa_provider_t *dnie_get_cwa_provider(sc_card_t * card);
extern int dnie_read_file(
	sc_card_t * card, 
	const sc_path_t * path, 
	sc_file_t ** file, 
	u8 ** buffer, size_t * length);

#define DNIE_CHIP_NAME "DNIe: Spanish eID card"
#define DNIE_CHIP_SHORTNAME "dnie"
#define DNIE_MF_NAME "Master.File"

/* default user consent program (if required) */
#define USER_CONSENT_CMD "/usr/bin/pinentry"

/**
 * SW internal apdu response table.
 *
 * Override APDU response error codes from iso7816.c to allow 
 * handling of SM specific error
 */
static struct sc_card_error dnie_errors[] = {
	{0x6688, SC_ERROR_SM, "Cryptographic checksum invalid"},
	{0x6987, SC_ERROR_SM, "Expected SM Data Object missing"},
	{0x6988, SC_ERROR_SM, "SM Data Object incorrect"},
	{0, 0, NULL}
};

/* 
 * DNIe ATR info from DGP web page
 *
Tag Value Meaning
TS  0x3B  Direct Convention
T0  0x7F  Y1=0x07=0111; TA1,TB1 y TC1 present.
          K=0x0F=1111; 15 historical bytes
TA1 0x38  FI (Factor de conversión de la tasa de reloj) = 744
          DI (Factor de ajuste de la tasa de bits) = 12
          Máximo 8 Mhz.
TB1 0x00  Vpp (voltaje de programación) no requerido.
TC1 0x00  No se requiere tiempo de espera adicional.
H1  0x00  No usado
H2  0x6A  Datos de preexpedición. Diez bytes con identificación del expedidor.
H3  0x44  'D'
H4  0x4E  'N'
H5  0x49  'I'
H6  0x65  'e'
H7  Fabricante de la tecnología Match-on-Card incorporada.
    0x10  SAGEM
    0x20  SIEMENS
H8  0x02  Fabricante del CI: STMicroelectronics.
H9  0x4C
H10 0x34  Tipo de CI: 19WL34
H11 0x01  MSB de la version del SO: 1
H12 0x1v  LSB de la version del SO: 1v
H13 Fase del ciclo de vida .
    0x00  prepersonalización.
    0x01  personalización.
    0x03  usuario.
    0x0F  final.
H14 0xss
H15 0xss  Bytes de estado

H13-H15: 0x03 0x90 0x00 user phase: tarjeta operativa
H13-H15: 0x0F 0x65 0x81 final phase: tarjeta no operativa
*/

/**
 * ATR Table list.
 * OpenDNIe defines two ATR's for user and finalized card state
 */
static struct sc_atr_table dnie_atrs[] = {
	/* TODO: get ATR for uninitalized DNIe */
	{		/** card activated; normal operation state */
	 "3B:7F:00:00:00:00:6A:44:4E:49:65:00:00:00:00:00:00:03:90:00",
	 "FF:FF:00:FF:FF:FF:FF:FF:FF:FF:FF:00:00:00:00:00:00:FF:FF:FF",
	 DNIE_CHIP_SHORTNAME,
	 SC_CARD_TYPE_DNIE_USER,
	 0,
	 NULL},
	{		/** card finalized, unusable */
	 "3B:7F:00:00:00:00:6A:44:4E:49:65:00:00:00:00:00:00:0F:65:81",
	 "FF:FF:00:FF:FF:FF:FF:FF:FF:FF:FF:00:00:00:00:00:00:FF:FF:FF",
	 DNIE_CHIP_SHORTNAME,
	 SC_CARD_TYPE_DNIE_TERMINATED,
	 0,
	 NULL},
	{NULL, NULL, NULL, 0, 0, NULL}
};

/**
 * Messages used on user consent procedures
 */
const char *user_consent_title="Signature Requested";

#ifdef linux
const char *user_consent_message="Está a punto de realizar una firma electrónica con su clave de FIRMA del DNI electrónico. ¿Desea permitir esta operación?";
#else
const char *user_consent_message="Esta a punto de realizar una firma digital\ncon su clave de FIRMA del DNI electronico.\nDesea permitir esta operacion?";
#endif

/**
 * DNIe specific card driver operations
 */
static struct sc_card_operations dnie_ops;

/**
 * Local copy of iso7816 card driver operations
 */
static struct sc_card_operations *iso_ops = NULL;

/**
 * Module definition for OpenDNIe card driver
 */
static sc_card_driver_t dnie_driver = {
	DNIE_CHIP_NAME, /**< Full name for DNIe card driver */
	DNIE_CHIP_SHORTNAME, /**< Short name for DNIe card driver */
	&dnie_ops,	/**< pointer to dnie_ops (DNIe card driver operations) */
	dnie_atrs,	/**< List of card ATR's handled by this driver */
	0,		/**< (natrs) number of atr's to check for this driver */
	NULL		/**< (dll) Card driver module (on DNIe is null) */
};

/************************** card-dnie.c internal functions ****************/

/**
 * Parse configuration file for dnie parameters.
 *
 * DNIe card driver has two main paramaters:
 * - The name of the user consent Application to be used in Linux. This application shoud be any of pinentry-xxx family
 * - A flag to indicate if user consent is to be used in this driver. If false, the user won't be prompted for confirmation on signature operations
 *
 * @See ../../etc/opensc.conf for details
 * @param card Pointer to card structure
 * @param ui_context Pointer to ui_context structure to store data into
 * @return SC_SUCCESS (should return no errors)
 *
 * TODO: Code should be revised in order to store user consent info
 * in a card-independent way at configuration file
 */
#ifdef ENABLE_DNIE_UI
static int dnie_get_environment(
	sc_card_t * card, 
	ui_context_t * ui_context)
{
	int i;
	scconf_block **blocks, *blk;
	sc_context_t *ctx;
	/* set default values */
	ui_context->user_consent_app = USER_CONSENT_CMD;
	ui_context->user_consent_enabled = 1;
	/* look for sc block in opensc.conf */
	ctx = card->ctx;
	for (i = 0; ctx->conf_blocks[i]; i++) {
		blocks =
		    scconf_find_blocks(ctx->conf, ctx->conf_blocks[i],
				       "card_driver", "dnie");
		if (!blocks)
			continue;
		blk = blocks[0];
		free(blocks);
		if (blk == NULL)
			continue;
		/* fill private data with configuration parameters */
		ui_context->user_consent_app =	/* def user consent app is "pinentry" */
		    (char *)scconf_get_str(blk, "user_consent_app",
					   USER_CONSENT_CMD);
		ui_context->user_consent_enabled =	/* user consent is enabled by default */
		    scconf_get_bool(blk, "user_consent_enabled", 1);
	}
	return SC_SUCCESS;
}
#endif

/************************** cardctl defined operations *******************/

/** 
 * Generate a public/private key pair.
 *
 * Manual says that generate_keys() is a reserved operation; that is: 
 * only can be done at DGP offices. But several authors talk about 
 * this operation is available also outside. So need to test :-)
 * Notice that write operations are not supported, so we can't use 
 * created keys to generate and store new certificates into the card.
 * TODO: copy code from card-jcop.c::jcop_generate_keys()
 * @param card pointer to card info data
 * @param data where to store function results
 * @return SC_SUCCESS if ok, else error code
 */
static int dnie_generate_key(sc_card_t * card, void *data)
{
	int result = SC_ERROR_NOT_SUPPORTED;
	if ((card == NULL) || (data == NULL))
		return SC_ERROR_INVALID_ARGUMENTS;
	LOG_FUNC_CALLED(card->ctx);
	/* TODO: write dnie_generate_key() */
	LOG_FUNC_RETURN(card->ctx, result);
}

/**
 * Analyze a buffer looking for provided data pattern.
 *
 * Comodity function for dnie_get_info() that searches a byte array
 * in provided buffer
 *
 * @param card pointer to card info data
 * @param pat data pattern to find in buffer
 * @param buf where to look for pattern
 * @param len buffer length
 * @return retrieved value or NULL if pattern not found
 * @see dnie_get_info()
 */
static char *findPattern(u8 *pat, u8 *buf, size_t len)
{
	char *res = NULL;
	u8 *from = buf;
	int size = 0;
	/* Locate pattern. Assume pattern length=6 */
	for ( from = buf; from < buf+len-6; from++) {
		if (memcmp(from,pat,6) == 0 ) goto data_found;
	}
	/* arriving here means pattern not found */
	return NULL;

data_found:
	/* assume length is less than 128 bytes, so is coded in 1 byte */
	size = 0x000000ff & (int) *(from+6);
	if ( size == 0 ) return NULL; /* empty data */
	res = calloc( size+1, sizeof(char) );
	if ( res == NULL) return NULL; /* calloc() error */
	memcpy(res,from+7,size);
	return res;
}

/**
 * Retrieve name, surname, and DNIe number.
 *
 * This is done by mean of reading and parsing CDF file
 * at address 3F0050156004
 * No need to enter pin nor use Secure Channel
 *
 * Notice that this is done by mean of a dirty trick: instead
 * of parsing ASN1 data on EF(CDF), 
 * we look for desired OID patterns in binary array
 *
 * @param card pointer to card info data 
 * @param data where to store function results (number,name,surname,idesp,version)
 * @return SC_SUCCESS if ok, else error code
 */
static int dnie_get_info(sc_card_t * card, char *data[])
{
	sc_file_t *file = NULL;
        sc_path_t *path = NULL;
        u8 *buffer = NULL;
	size_t bufferlen = 0;
	char *msg = NULL;
	u8 SerialNumber [] = { 0x06, 0x03, 0x55, 0x04, 0x05, 0x13 };
	u8 Name [] = { 0x06, 0x03, 0x55, 0x04, 0x04, 0x0C };
	u8 GivenName [] = { 0x06, 0x03, 0x55, 0x04, 0x2A, 0x0C };
	int res = SC_ERROR_NOT_SUPPORTED;

        if ((card == NULL) || (data == NULL))
                return SC_ERROR_INVALID_ARGUMENTS;
        LOG_FUNC_CALLED(card->ctx);

	/* phase 1: get DNIe number, Name and GivenName */

	/* read EF(CDF) at 3F0050156004 */
	path = (sc_path_t *) calloc(1, sizeof(sc_path_t));
	if (!path) {
		msg = "Cannot allocate path data for EF(CDF) read";
		res = SC_ERROR_OUT_OF_MEMORY;
		goto get_info_end;
	}
	sc_format_path("3F0050156004", path);
	res = dnie_read_file(card, path, &file, &buffer, &bufferlen);
	if (res != SC_SUCCESS) {
		msg = "Cannot read EF(CDF)";
		goto get_info_end;
	}
	/* locate OID 2.5.4.5 (SerialNumber) - DNIe number*/
	data[0]= findPattern(SerialNumber,buffer,bufferlen);
	/* locate OID 2.5.4.4 (Name)         - Apellidos */
	data[1]= findPattern(Name,buffer,bufferlen);
	/* locate OID 2.5.4.42 (GivenName)   - Nombre */
	data[2]= findPattern(GivenName,buffer,bufferlen);
	if ( ! data[0] || !data[1] || !data[2] ) {
		res = SC_ERROR_INVALID_DATA;
		msg = "Cannot retrieve info from EF(CDF)";
		goto get_info_end;
        }

	/* phase 2: get IDESP */
	sc_format_path("3F000006", path);
	if (file) {
		sc_file_free(file);
		file = NULL;
	}
	if (buffer) {
		free(buffer); 
		buffer=NULL; 
		bufferlen=0;
	}
	res = dnie_read_file(card, path, &file, &buffer, &bufferlen);
	if (res != SC_SUCCESS) {
		msg = "Cannot read IDESP EF";
		data[3]=NULL;
		goto get_info_ph3;
	}
	data[3]=calloc(bufferlen+1,sizeof(char));
	if ( !data[3] ) {
		msg = "Cannot allocate memory for IDESP data";
		res = SC_ERROR_OUT_OF_MEMORY;
		goto get_info_end;
	}
	memcpy(data[3],buffer,bufferlen);

get_info_ph3:
	/* phase 3: get DNIe software version */
	sc_format_path("3F002F03", path);
	if (file) {
		sc_file_free(file);
		file = NULL;
	}
	if (buffer) {
		free(buffer); 
		buffer=NULL; 
		bufferlen=0;
	}
	/* 
	* Some old DNIe cards seems not to include SW version file,
 	* so let this code fail without notice
 	*/
	res = dnie_read_file(card, path, &file, &buffer, &bufferlen);
	if (res != SC_SUCCESS) {
		msg = "Cannot read DNIe Version EF";
		data[4]=NULL;
		res = SC_SUCCESS; /* let function return successfully */
		goto get_info_end;
	}
	data[4]=calloc(bufferlen+1,sizeof(char));
	if ( !data[4] ) {
		msg = "Cannot allocate memory for DNIe Version data";
		res = SC_ERROR_OUT_OF_MEMORY;
		goto get_info_end;
	}
	memcpy(data[4],buffer,bufferlen);

	/* arriving here means ok */
	res = SC_SUCCESS;
	msg = NULL;

get_info_end:
	if (file) {
		sc_file_free(file);
		free(buffer);
		file = NULL;
		buffer = NULL;
		bufferlen = 0;
	}
	if (msg)
		sc_log(card->ctx,msg);
        LOG_FUNC_RETURN(card->ctx, res);
}

/**
 * Retrieve serial number (7 bytes) from card.
 *
 * This is done by mean of an special APDU command described
 * in the DNIe Reference Manual
 *
 * @param card pointer to card description
 * @param serial where to store data retrieved
 * @return SC_SUCCESS if ok; else error code
 */
static int dnie_get_serialnr(sc_card_t * card, sc_serial_number_t * serial)
{
	int result;
	sc_apdu_t apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	if ((card == NULL) || (card->ctx == NULL) || (serial == NULL))
		return SC_ERROR_INVALID_ARGUMENTS;

	LOG_FUNC_CALLED(card->ctx);
	if (card->type != SC_CARD_TYPE_DNIE_USER)
		return SC_ERROR_NOT_SUPPORTED;
	/* if serial number is cached, use it */
	if (card->serialnr.len) {
		memcpy(serial, &card->serialnr, sizeof(*serial));
		sc_log(card->ctx, "Serial Number (cached): '%s'",
		       sc_dump_hex(serial->value, serial->len));
		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
	}
	/* not cached, retrieve it by mean of an APDU */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xb8, 0x00, 0x00);
	apdu.cla = 0x90;	/* propietary cmd */
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	/* official driver read 0x11 bytes, but only uses 7. Manual says just 7 */
	apdu.le = 0x07;
	apdu.lc = 0;
	apdu.datalen = 0;
	/* send apdu */
	result = dnie_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, result, "APDU transmit failed");
	if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
		return SC_ERROR_INTERNAL;
	/* cache serial number */
	memcpy(card->serialnr.value, apdu.resp, 7 * sizeof(u8));
	card->serialnr.len = 7 * sizeof(u8);
	/* TODO: fill Issuer Identification Number data with proper (ATR?) info */
	/*
	   card->serialnr.iin.mii=;
	   card->serialnr.iin.country=;
	   card->serialnr.iin.issuer_id=;
	 */
	/* copy and return serial number */
	memcpy(serial, &card->serialnr, sizeof(*serial));
	sc_log(card->ctx, "Serial Number (apdu): '%s'",
	       sc_dump_hex(serial->value, serial->len));
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

/**
 * Remove the binary data in the cache.
 *
 * It frees memory if allocated and resets pointer and length.
 * It only touches the private binary cache variables, not the sc_card information.
 *
 * @param data pointer to dnie private data
 */
static void dnie_clear_cache(dnie_private_data_t * data)
{
	if (data == NULL) return;
	if (data->cache != NULL)
		free(data->cache);
	data->cache = NULL;
	data->cachelen = 0;
}

/**
 * Set sc_card flags according to DNIe requirements.
 *
 * Used in card initialization.
 *
 * @param card pointer to card data
 */
static inline void init_flags(struct sc_card *card)
{
	unsigned long algoflags;
	/* set up flags according documentation */
	card->name = DNIE_CHIP_SHORTNAME;
	card->cla = 0x00;	/* default APDU class (interindustry) */
	card->caps |= SC_CARD_CAP_RNG;	/* we have a random number generator */
	card->max_send_size = (255 - 12);	/* manual says 255, but we need 12 extra bytes when encoding */
	card->max_recv_size = 255;

	algoflags = SC_ALGORITHM_RSA_RAW;	/* RSA support */
	algoflags |= SC_ALGORITHM_RSA_HASH_NONE;
	_sc_card_add_rsa_alg(card, 1024, algoflags, 0);
	_sc_card_add_rsa_alg(card, 2048, algoflags, 0);
}

/**************************** sc_card_operations **********************/

/* Generic operations */

/**
 * Check if provided card can be handled by OpenDNIe.
 *
 * Called in sc_connect_card().  Must return 1, if the current
 * card can be handled with this driver, or 0 otherwise.  ATR
 * field of the sc_card struct is filled in before calling
 * this function.
 * do not declare static, as used by pkcs15-dnie module
 *
 * @param card Pointer to card structure
 * @return on card matching 0 if not match; negative return means error
 */
int dnie_match_card(struct sc_card *card)
{
	int result = 0;
	int matched = -1;
	LOG_FUNC_CALLED(card->ctx);
	matched = _sc_match_atr(card, dnie_atrs, &card->type);
	result = (matched >= 0) ? 1 : 0;
	LOG_FUNC_RETURN(card->ctx, result);
}

/**
 * OpenDNIe card structures initialization.
 *
 * Called when ATR of the inserted card matches an entry in ATR
 * table.  May return SC_ERROR_INVALID_CARD to indicate that
 * the card cannot be handled with this driver.
 *
 * @param card Pointer to card structure
 * @return SC_SUCCES if ok; else error code
 */
static int dnie_init(struct sc_card *card)
{
	int res = SC_SUCCESS;
	sc_context_t *ctx = card->ctx;
	cwa_provider_t *provider = NULL;

	LOG_FUNC_CALLED(ctx);

	/* if recognized as terminated DNIe card, return error */
	if (card->type == SC_CARD_TYPE_DNIE_TERMINATED)
	    LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_CARD, "DNIe card is terminated.");

	/* create and initialize cwa-dnie provider*/
	provider = dnie_get_cwa_provider(card);
	if (!provider) 
	    LOG_TEST_RET(card->ctx, SC_ERROR_INTERNAL, "Error initializing cwa-dnie provider");

#ifdef ENABLE_SM
	/** Secure messaging initialization section **/
	memset(&(card->sm_ctx), 0, sizeof(sm_context_t));
	card->sm_ctx.ops.get_sm_apdu = NULL;
	card->sm_ctx.ops.free_sm_apdu = NULL;
#endif

	init_flags(card);

#ifdef ENABLE_SM
	res=cwa_create_secure_channel(card,provider,CWA_SM_OFF);
	LOG_TEST_RET(card->ctx, res, "Failure creating CWA secure channel.");
#endif

	/* initialize private data */
	card->drv_data = calloc(1, sizeof(dnie_private_data_t));
	if (card->drv_data == NULL)
	    LOG_TEST_RET(card->ctx, SC_ERROR_OUT_OF_MEMORY, "Could not allocate DNIe private data.");

#ifdef ENABLE_DNIE_UI
	/* read environment from configuration file */
	res = dnie_get_environment(card, &(GET_DNIE_UI_CTX(card)));
	if (res != SC_SUCCESS) {
		free(card->drv_data);
		LOG_TEST_RET(card->ctx, res, "Failure reading DNIe environment.");
	}
#endif

	GET_DNIE_PRIV_DATA(card)->cwa_provider = provider;

	LOG_FUNC_RETURN(card->ctx, res);
}

/**
 * De-initialization routine.
 *
 * Called when the card object is being freed.  finish() has to
 * deallocate all possible private data. 
 *
 * @param card Pointer to card driver data structure
 * @return SC_SUCCESS if ok; else error code
 */
static int dnie_finish(struct sc_card *card)
{
	int result = SC_SUCCESS;
	LOG_FUNC_CALLED(card->ctx);
	dnie_clear_cache(GET_DNIE_PRIV_DATA(card));
#ifdef ENABLE_SM
	/* disable sm channel if established */
	result = cwa_create_secure_channel(card, GET_DNIE_PRIV_DATA(card)->cwa_provider, CWA_SM_OFF);
#endif
	if (card->drv_data != NULL)
		free(card->drv_data);
	LOG_FUNC_RETURN(card->ctx, result);
}

/* ISO 7816-4 functions */

/**
 * Convert little-endian data into unsigned long.
 *
 * @param pt pointer to little-endian data
 * @return equivalent long
 */
static unsigned long le2ulong(u8 * pt)
{
	unsigned long res = 0L;
	if (pt==NULL) return res;
	res = (0xff & *(pt + 0)) +
	    ((0xff & *(pt + 1)) << 8) +
	    ((0xff & *(pt + 2)) << 16) + ((0xff & *(pt + 3)) << 24);
	return res;
}

/**
 * Uncompress data if in compressed format.
 *
 * @param card poiner to sc_card_t structure
 * @param from buffer to get data from
 * @param len pointer to buffer length
 * @return uncompresed or original buffer; len points to new buffer length
 *        on error return null
 */
static u8 *dnie_uncompress(sc_card_t * card, u8 * from, size_t *len)
{
	int res = SC_SUCCESS;
	u8 *upt = from;
	size_t uncompressed = 0L;
	size_t compressed = 0L;

#ifdef ENABLE_ZLIB
	if (!card || !card->ctx || !from || !len)
		return NULL;
	LOG_FUNC_CALLED(card->ctx);

	/* if data size not enought for compression header assume uncompressed */
	if (*len < 8)
		goto compress_exit;
	/* evaluate compressed an uncompressed sizes (little endian format) */
	uncompressed = le2ulong(from);
	compressed = le2ulong(from + 4);
	/* if compressed size doesn't match data length assume not compressed */
	if (compressed != (*len) - 8)
		goto compress_exit;
	/* if compressed size greater than uncompressed, assume uncompressed data */
	if (uncompressed < compressed)
		goto compress_exit;

	sc_log(card->ctx, "Data seems to be compressed. calling uncompress");
	/* ok: data seems to be compressed */
	upt = calloc(uncompressed, sizeof(u8));
	if (!upt) {
		sc_log(card->ctx, "alloc() for uncompressed buffer failed");
		return NULL;
	}
	res = sc_decompress(upt,	/* try to uncompress by calling sc_xx routine */
			    (size_t *) & uncompressed,
			    from + 8, (size_t) compressed, COMPRESSION_ZLIB);
	/* TODO: check that returned uncompressed size matches expected */
	if (res != SC_SUCCESS) {
		sc_log(card->ctx, "Uncompress() failed or data not compressed");
		goto compress_exit;	/* assume not need uncompression */
	}
	/* Done; update buffer len and return pt to uncompressed data */
	*len = uncompressed;
	sc_log(card->ctx, "Compressed data:\n%s\n",
	       sc_dump_hex(from + 8, compressed));
	sc_log(card->ctx, "Uncompress() done. Before:'%lu' After: '%lu'",
	       compressed, uncompressed);
	sc_log(card->ctx, "Uncompressed data:\n%s\n",
	       sc_dump_hex(upt, uncompressed));
 compress_exit:

#endif

	sc_log(card->ctx, "uncompress: returning with%s de-compression ",
	       (upt == from) ? "out" : "");
	return upt;
}

/**
 * Fill file cache for read_binary() operation.
 *
 * Fill a temporary buffer by mean of consecutive calls to read_binary()
 * until card sends eof
 *
 * DNIe card stores user certificates in compressed format. so we need
 * some way to detect and uncompress on-the-fly compressed files, to
 * let read_binary() work transparently. 
 * This is the main goal of this routine: create an in-memory buffer 
 * for read_binary operation, filling this buffer on first read_binary() 
 * call, and uncompress data if compression detected. Further 
 * read_binary() calls then make use of cached data, instead
 * of accessing the card
 *
 * @param card Pointer to card structure
 * @return SC_SUCCESS if OK; else error code
 */
static int dnie_fill_cache(sc_card_t * card)
{
	u8 tmp[SC_MAX_APDU_BUFFER_SIZE];
	sc_apdu_t apdu;
	size_t count = 0;
	size_t len = 0;
	u8 *buffer = NULL;
	u8 *pt = NULL;
	sc_context_t *ctx = NULL;

	if (!card || !card->ctx)
		return SC_ERROR_INVALID_ARGUMENTS;
	ctx = card->ctx;

	LOG_FUNC_CALLED(ctx);

	/* mark cache empty */
	dnie_clear_cache(GET_DNIE_PRIV_DATA(card));

	/* initialize apdu */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xB0, 0x00, 0x00);

	/* try to read_binary while data available but never long than 32767 */
	count = card->max_recv_size;
	for (len = 0; len < 0x7fff;) {
		int r = SC_SUCCESS;
		/* fill apdu */
		apdu.p1 = 0xff & (len >> 8);
		apdu.p2 = 0xff & len;
		apdu.le = count;
		apdu.resplen = count;
		apdu.resp = tmp;
		/* transmit apdu */
		r = dnie_transmit_apdu(card, &apdu);
		if (r != SC_SUCCESS) {
			if (buffer)
				free(buffer);
			sc_log(ctx, "read_binary() APDU transmit failed");
			LOG_FUNC_RETURN(ctx, r);
		}
		if (apdu.resplen == 0) {
			/* on no data received, check if requested len is longer than
			   available data in card. If so, ask just for remaining data */
			r = sc_check_sw(card, apdu.sw1, apdu.sw2);
			if (r == SC_ERROR_WRONG_LENGTH) {
				count = 0xff & apdu.sw2;
				if (count != 0)
					continue;	/* read again with correct size */
				goto read_done;	/* no more data to read */
			}
			if (r == SC_ERROR_INCORRECT_PARAMETERS)
				goto read_done;
			LOG_FUNC_RETURN(ctx, r);	/* arriving here means response error */
		}
		/* copy received data into buffer. realloc() if not enought space */
		count = apdu.resplen;
		buffer = realloc(buffer, len + count);
		if (!buffer)
			LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
		memcpy(buffer + len, apdu.resp, count);
		len += count;
		if (count != card->max_recv_size)
			goto read_done;
	}

 read_done:
	/* no more data to read: check if data is compressed */
	pt = dnie_uncompress(card, buffer, &len);
	if (pt == NULL) {
		sc_log(ctx, "Uncompress proccess failed");
		if (buffer)
			free(buffer);
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	}
	if (pt != buffer)
		if (buffer)
			free(buffer);

	/* ok: as final step, set correct cache data into dnie_priv structures */
	GET_DNIE_PRIV_DATA(card)->cache = pt;
	GET_DNIE_PRIV_DATA(card)->cachelen = len;
	sc_log(ctx, "fill_cache() done. length '%d' bytes", len);
	LOG_FUNC_RETURN(ctx,len);
}

/**
 * OpenDNIe implementation of read_binary().
 *
 * Reads a binary stream from card by mean of READ BINARY iso command
 * Creates and handle a cache to allow data uncompression
 *
 * @param card pointer to sc_card_t structure
 * @param idx offset from card file to ask data for
 * @param buf where to store readed data. must be non null
 * @param count number of bytes to read
 * @param flags. not used
 * @return number of bytes readed, 0 on EOF, error code on error
 */
static int dnie_read_binary(struct sc_card *card,
			    unsigned int idx,
			    u8 * buf, size_t count, unsigned long flags)
{
	int res = 0;
	sc_context_t *ctx = NULL;
	/* preliminary checks */
	if (!card || !card->ctx || !buf || (count <= 0))
		return SC_ERROR_INVALID_ARGUMENTS;
	ctx = card->ctx;

	LOG_FUNC_CALLED(ctx);
	if (idx == 0 || GET_DNIE_PRIV_DATA(card)->cache == NULL) {
		/* on first block or no cache, try to fill */
		res = dnie_fill_cache(card);
		if (res < 0) {
			sc_log(ctx, "Cannot fill cache. using iso_read_binary()");
			return iso_ops->read_binary(card, idx, buf, count, flags);
		}
	}
	if (idx >= GET_DNIE_PRIV_DATA(card)->cachelen)
		return 0;	/* at eof */
	res = MIN(count, GET_DNIE_PRIV_DATA(card)->cachelen - idx);	/* eval how many bytes to read */
	memcpy(buf, GET_DNIE_PRIV_DATA(card)->cache + idx, res);	/* copy data from buffer */
	sc_log(ctx, "dnie_read_binary() '%d' bytes", res);
	LOG_FUNC_RETURN(ctx, res);
}

/**
 * Send apdu to the card
 *
 * @param card pointer to sc_card_t structure
 * @param path
 * @param pathlen
 * @param p1
 * @param file_out
 * @return result
 */
static int dnie_compose_and_send_apdu(sc_card_t *card, const u8 *path, size_t pathlen,
					u8 p1, sc_file_t **file_out)
{
	int res = 0;
	sc_apdu_t apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	sc_file_t *file = NULL;

	sc_context_t *ctx = NULL;

	if (!card || !card->ctx)
		return SC_ERROR_INVALID_ARGUMENTS;
	ctx = card->ctx;

	LOG_FUNC_CALLED(ctx);

        sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "called, p1=%u, path=%s\n", p1, sc_dump_hex(path, pathlen));

	/* Arriving here means need to compose and send apdu */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, p1, 0);
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.lc = pathlen;
	apdu.data = path;
	apdu.datalen = pathlen;
	apdu.le = card->max_recv_size > 0 ? card->max_recv_size : 256;
	if (p1 == 3)
		apdu.cse= SC_APDU_CASE_1;

	if (file_out == NULL) {
		apdu.cse = (apdu.lc == 0) ? SC_APDU_CASE_1 : SC_APDU_CASE_3_SHORT;
		apdu.le = 0;
	}
	res = dnie_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, res, "SelectFile() APDU transmit failed");
	if (file_out == NULL) {
		if (apdu.sw1 == 0x61)
			SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_VERBOSE, 0);
		SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_VERBOSE,
			       sc_check_sw(card, apdu.sw1, apdu.sw2));
	}

	/* analyze response. if FCI, try to parse */
	res = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, res, "SelectFile() check_sw failed");
	if (apdu.resplen < 2)
		LOG_FUNC_RETURN(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	if (apdu.resp[0] == 0x00)	/* proprietary coding */
		LOG_FUNC_RETURN(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);

	/* finally process FCI response */
	file = sc_file_new();
	if (file == NULL)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	res = card->ops->process_fci(card, file, apdu.resp + 2, apdu.resp[1]);
	*file_out = file;
	LOG_FUNC_RETURN(ctx, res);
}

/**
 * OpenDNIe implementation of Select_File().
 *
 * Select_file: Does the equivalent of SELECT FILE command specified
 *   in ISO7816-4. Stores information about the selected file to
 *   <file>, if not NULL.
 *
 * SELECT file in DNIe is a bit tricky: 
 * - only handles some types: 
 * -- <strong>SC_PATH_TYPE_FILE_ID</strong> 2-byte long file ID
 * -- <strong>SC_PATH_TYPE_DF_NAME</strong> named DF's
 * -- <strong>SC_PATH_TYPE_PARENT</strong>  jump to parent DF of current EF/DF - undocummented in DNIe manual
 * -- other file types are marked as unssupported
 *
 * - Also MF must be addressed by their Name, not their ID
 * So some magic is needed:
 * - split <strong>SC_PATH_TYPE_PATH</strong> into several calls to each 2-byte data file ID
 * - Translate initial file id 3F00 to be DF name 'Master.File'
 *
 * Also, Response always handle a proprietary FCI info, so
 * need to handle it manually via dnie_process_fci()
 *
 * @param card Pointer to Card Structure
 * @param in_path Path ID to be selected
 * @param file_out where to store fci information
 * @return SC_SUCCESS if ok; else error code
 */
static int dnie_select_file(struct sc_card *card,
			    const struct sc_path *in_path,
			    struct sc_file **file_out)
{
	int res = SC_SUCCESS;
	sc_context_t *ctx = NULL;
	unsigned char tmp_path[sizeof(DNIE_MF_NAME)];
	int reminder = 0;

	if (!card || !card->ctx || !in_path)
		return SC_ERROR_INVALID_ARGUMENTS;
	ctx = card->ctx;

	LOG_FUNC_CALLED(ctx);

	switch (in_path->type) {
	case SC_PATH_TYPE_FILE_ID:
		/* pathlen must be of len=2 */
		/* 
		 * gscriptor shows that DNIe also handles 
		 * Select child DF (p1=1) and Select EF (p1=2),
		 * but we'll use P1=0 as general solution for all cases
		 *
		 * According iso7816-4 sect 7.1.1  pathlen==0 implies
		 * select MF, but this case is not supported by DNIe
		 */
		if (in_path->len != 2)
			LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
		sc_log(ctx, "select_file(ID): %s", sc_dump_hex(in_path->value, in_path->len));
		res = dnie_compose_and_send_apdu(card, in_path->value, in_path->len, 0, file_out);
		break;
	case SC_PATH_TYPE_DF_NAME:
		sc_log(ctx, "select_file(NAME): %s", sc_dump_hex(in_path->value, in_path->len));
		res = dnie_compose_and_send_apdu(card, in_path->value, in_path->len, 4, file_out);
		break;
	case SC_PATH_TYPE_PATH:
		if ((in_path->len == 0) || ((in_path->len & 1) != 0)) /* not divisible by 2 */
			LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

		sc_log(ctx, "select_file(PATH): requested:%s ", sc_dump_hex(in_path->value, in_path->len));


		/* convert to SC_PATH_TYPE_FILE_ID */
		res = sc_lock(card); /* lock to ensure path traversal */
		LOG_TEST_RET(ctx, res, "sc_lock() failed");
		if (memcmp(in_path->value, "\x3F\x00", 2) == 0) {
			/* if MF, use the name as path */
			strcpy((char *)tmp_path, DNIE_MF_NAME);
			sc_log(ctx, "select_file(NAME): requested:%s ", sc_dump_hex(tmp_path, sizeof(DNIE_MF_NAME) - 1));
			res = dnie_compose_and_send_apdu(card, tmp_path, sizeof(DNIE_MF_NAME) - 1, 4, file_out);
			if (res != SC_SUCCESS) {
				sc_unlock(card);
				LOG_TEST_RET(ctx, res, "select_file(NAME) failed");
			}
			tmp_path[2] = 0;
			reminder = in_path->len - 2;
		} else {
			tmp_path[2] = 0;
			reminder = in_path->len;
		}
		while (reminder > 0) {
			tmp_path[0] = in_path->value[in_path->len - reminder];
			tmp_path[1] = in_path->value[1 + in_path->len - reminder];
			sc_log(ctx, "select_file(PATH): requested:%s ", sc_dump_hex(tmp_path, 2));
			res = dnie_compose_and_send_apdu(card, tmp_path, 2, 0, file_out);
			if (res != SC_SUCCESS) {
				sc_unlock(card);
				LOG_TEST_RET(ctx, res, "select_file(PATH) failed");
			}
			reminder -= 2;
		}
		sc_unlock(card);
		break;
	case SC_PATH_TYPE_FROM_CURRENT:
		LOG_FUNC_RETURN(ctx, SC_ERROR_NO_CARD_SUPPORT);
		break;
	case SC_PATH_TYPE_PARENT:
		/* Hey!! Manual doesn't says anything on this, but
		 * gscriptor shows that this type is supported
		 */
		sc_log(ctx, "select_file(PARENT)");
		/* according iso7816-4 sect 7.1.1 shouldn't have any parameters */
		if (in_path->len != 0)
			LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
		res = dnie_compose_and_send_apdu(card, NULL, 0, 3, file_out);
		break;
	default:
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
		break;
	}

	/* as last step clear data cache and return */
	dnie_clear_cache(GET_DNIE_PRIV_DATA(card));
	LOG_FUNC_RETURN(ctx, res);
}

/**
 * OpenDNIe implementation of Get_Challenge() command.
 *
 * Get challenge: retrieve 8 random bytes for any further use
 * (eg perform an external authenticate command)
 *
 * NOTE:
 * Official driver redundantly sets SM before execute this command
 * No reason to do it, as is needed to do SM handshake...
 * Also: official driver reads in blocks of 20 bytes. 
 * Why? Manual and iso-7816-4 states that only 8 bytes 
 * are required... so we will obbey Manual
 *
 * @param card Pointer to card Structure
 * @param rnd Where to store challenge
 * @param len requested challenge length
 * @return SC_SUCCESS if OK; else error code
 */
static int dnie_get_challenge(struct sc_card *card, u8 * rnd, size_t len)
{
	sc_apdu_t apdu;
	u8 buf[10];
	int result = SC_SUCCESS;
	if ((card == NULL) || (card->ctx == NULL))
		return SC_ERROR_INVALID_ARGUMENTS;
	LOG_FUNC_CALLED(card->ctx);
	/* just a copy of iso7816::get_challenge() but call dnie_check_sw to
	 * look for extra error codes */
	if ( (rnd==NULL) || (len==0) ) {
		/* no valid buffer provided */
		result = SC_ERROR_INVALID_ARGUMENTS;
		goto dnie_get_challenge_error;
	}
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0x84, 0x00, 0x00);
	apdu.le = 8;
	apdu.resp = buf;
	apdu.resplen = 8;	/* include SW's */

	/* 
	* As DNIe cannot handle other data length than 0x08 and 0x14, 
	* perform consecutive reads of 8 bytes until retrieve requested length
	*/
	while (len > 0) {
		size_t n = len > 8 ? 8 : len;
		result = dnie_transmit_apdu(card, &apdu);
		LOG_TEST_RET(card->ctx, result, "APDU transmit failed");
		if (apdu.resplen != 8) {
			result = sc_check_sw(card, apdu.sw1, apdu.sw2);
			goto dnie_get_challenge_error;
		}
		memcpy(rnd, apdu.resp, n);
		len -= n;
		rnd += n;
	}
	result = SC_SUCCESS;
 dnie_get_challenge_error:
	LOG_FUNC_RETURN(card->ctx, result);
}

/*
 * ISO 7816-8 functions
 */

/**
 * OpenDNIe implementation of Logout() card_driver function.
 *
 *  Resets all access rights that were gained. Disable SM
 *
 * @param card Pointer to Card Structure
 * @return SC_SUCCESS if OK; else error code
 */
static int dnie_logout(struct sc_card *card)
{
	int result = SC_SUCCESS;

	if ((card == NULL) || (card->ctx == NULL))
		return SC_ERROR_INVALID_ARGUMENTS;
	LOG_FUNC_CALLED(card->ctx);
#ifdef ENABLE_SM
	/* disable and free any sm channel related data */
	result =
	    cwa_create_secure_channel(card, GET_DNIE_PRIV_DATA(card)->cwa_provider, CWA_SM_OFF);
#endif
	/* TODO: _logout() see comments.txt on what to do here */
	LOG_FUNC_RETURN(card->ctx, result);
}

/**
 * Implementation of Set_Security_Environment card driver command.
 *
 * Initializes the security environment on card
 *   according to <env>, and stores the environment as <se_num> on the
 *   card. If se_num <= 0, the environment will not be stored. 
 *   Notice that OpenDNIe SM handling requires a buffer longer than 
 *   provided for this command; so special apdu is used in cwa code
 *
 * @param card Pointer to card driver Structure
 * @param env Pointer to security environment data
 * @param num: which Card Security environment to use (ignored in OpenDNIe)
 * @return SC_SUCCESS if OK; else error code
 *
 * TODO: mix these code with SM set_security_env operations
 *
 */
static int dnie_set_security_env(struct sc_card *card,
				 const struct sc_security_env *env, int se_num)
{
	sc_apdu_t apdu;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];	/* buffer to compose apdu data */
	u8 *p = sbuf;
	int result = SC_SUCCESS;
	if ((card == NULL) || (card->ctx == NULL) || (env == NULL))
		return SC_ERROR_INVALID_ARGUMENTS;
	LOG_FUNC_CALLED(card->ctx);
	if (se_num!=0) {
		sc_log(card->ctx,"DNIe cannot handle several security envs");
		LOG_FUNC_RETURN(card->ctx,SC_ERROR_INVALID_ARGUMENTS);
	}

	/* Secure Channel should be on here, if not means an error */
	/*
	result =
	    cwa_create_secure_channel(card, dnie_priv.provider, CWA_SM_WARM);
	LOG_TEST_RET(card->ctx, result,
		     "set_security_env(); Cannot establish SM");
	*/

	/* check for algorithms */
	if (env->flags & SC_SEC_ENV_ALG_REF_PRESENT) {
		sc_log(card->ctx, "checking algorithms");
		switch (env->algorithm) {
		case SC_ALGORITHM_RSA:
			result = SC_SUCCESS;
			break;
		case SC_ALGORITHM_DSA:
		case SC_ALGORITHM_EC:
		case SC_ALGORITHM_GOSTR3410:
		default:
			result = SC_ERROR_NOT_SUPPORTED;
			break;
		}
		LOG_TEST_RET(card->ctx, result, "Unsupported algorithm");
		if ((env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA1) == 0) {
			result = SC_ERROR_NOT_SUPPORTED;
			/* TODO: 
			 * Manual says that only RSA with SHA1 is supported, but found
			 * some docs where states that SHA256 is also handled
			 */
		}
		LOG_TEST_RET(card->ctx, result,
			     "Only RSA with SHA1 is supported");
		/* ok: insert algorithm reference into buffer */
		*p++ = 0x80;	/* algorithm reference tag */
		*p++ = 0x01;	/* len */
		*p++ = env->algorithm_ref & 0xff;	/* val */
	}

	/* check for key references */
	if (env->flags & SC_SEC_ENV_KEY_REF_PRESENT) {
		sc_log(card->ctx, "checking key references");
		if (env->key_ref_len != 1) {
			sc_log(card->ctx, "Null or invalid key ID reference");
			result = SC_ERROR_INVALID_ARGUMENTS;
		}
		sc_log(card->ctx, "Using key reference '%s'",
		       sc_dump_hex(env->key_ref, env->key_ref_len));
		/* ok: insert key reference into buffer */
		/* notice that DNIe uses same key reference for pubk and privk */

		/* see cwa14890-2 sect B.1 about Control Reference Template Tags */
		*p++ = 0x84;	/* TODO: make proper detection of 0x83 /0x84 tag usage */
		*p++ = 0x02;	/* len  */
		*p++ = 0x01;	/* key ID prefix (MSB byte of keyFile ID) */
		memcpy(p, env->key_ref, env->key_ref_len);	/* in DNIe key_ref_len=1 */
		p += env->key_ref_len;
		/* store key reference into private data */
		GET_DNIE_PRIV_DATA(card)->rsa_key_ref = 0xff & env->key_ref[0];
	}

	/* create and format apdu */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x00, 0x00);

	/* check and perform operation */
	switch (env->operation) {
	case SC_SEC_OPERATION_DECIPHER:
		/* TODO: Manual is unsure about if (de)cipher() is supported */
		apdu.p1 = 0xC1;
		apdu.p2 = 0xB8;
		break;
	case SC_SEC_OPERATION_SIGN:
		apdu.p1 = 0x41;	/* SET; internal operation */
		apdu.p2 = 0xB6;	/* Template for Digital Signature */
		break;
	case SC_SEC_OPERATION_AUTHENTICATE:
		/* TODO: _set_security_env() study diffs on internal/external auth */
		apdu.p1 = 0x41;	/* SET; internal operation */
		apdu.p2 = 0xA4;	/* Template for Authenticate */
		break;
	default:
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	}

	/* complete apdu contents with buffer data */
	apdu.data = sbuf;
	apdu.datalen = p - sbuf;
	apdu.lc = p - sbuf;
	apdu.resplen = 0;

	/* Notice that Manual states that DNIE only allows handle of 
	 * current security environment, so se_num is ignored, and
	 * store sec env apdu (00 22 F2 se_num) command will not be issued */

	/* send composed apdu and parse result */
	result = dnie_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, result, "Set Security Environment failed");
	result = sc_check_sw(card, apdu.sw1, apdu.sw2);

	LOG_FUNC_RETURN(card->ctx, result);
}

/**
 * OpenDNIe implementation of Decipher() card driver operation.
 *
 * Engages the deciphering operation.  Card will use the
 * security environment set in a call to set_security_env or
 * restore_security_env.
 *
 * Notice that DNIe manual doesn't say anything about crypt/decrypt
 * operations. So this code is based on ISO standards and still needs
 * to be checked
 *
 * ADD: seems that DNIe supports a minimal cipher/decipher operation
 * but restricted to 1024 data chunks . Need more info and tests
 *
 * @param card Pointer to Card Driver Structure 
 * @param crgram cryptogram to be (de)ciphered
 * @param crgram_len cryptogram length
 * @param out where to store result
 * @param outlen length of result buffer
 * @return SC_SUCCESS if OK; else error code
 */
static int dnie_decipher(struct sc_card *card,
			 const u8 * crgram, size_t crgram_len,
			 u8 * out, size_t outlen)
{
	struct sc_apdu apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	size_t len;
	int result = SC_SUCCESS;
	if ((card == NULL) || (card->ctx == NULL))
		return SC_ERROR_INVALID_ARGUMENTS;
	LOG_FUNC_CALLED(card->ctx);
	if ((crgram == NULL) || (out == NULL) || (crgram_len > 255)) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	}
	/* Secure Channel should be on. Elsewhere an error will be thrown */
	/*
	result =
	    cwa_create_secure_channel(card, dnie_priv.provider, CWA_SM_WARM);
	LOG_TEST_RET(card->ctx, result, "decipher(); Cannot establish SM");
	*/

	/* Official driver uses an undocumented proprietary APDU
	 * (90 74 40 keyID). This code uses standard 00 2A 80 8x one)
	 * as shown in card-atrust-acos.c and card-jcop.c
	 */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A,	/* INS: 0x2A  perform security operation */
		       0x80,	/* P1: Response is plain value */
		       0x86	/* P2: 8x: Padding indicator byte followed by cryptogram */
	    );
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);

	sbuf[0] = 0;		/* padding indicator byte, 0x00 = No further indication */
	memcpy(sbuf + 1, crgram, crgram_len);
	apdu.data = sbuf;
	apdu.lc = crgram_len + 1;
	apdu.datalen = crgram_len + 1;
	apdu.le = 256;
	/* send apdu */
	result = dnie_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, result, "APDU transmit failed");
	/* check response */
	result = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, result, "decipher returned error");
	/* responde ok: fill result data and return */
	len = apdu.resplen > outlen ? outlen : apdu.resplen;
	memcpy(out, apdu.resp, len);
	LOG_FUNC_RETURN(card->ctx, result);
}

/**
 * OpenDNIe implementation of Compute_Signature() card driver operation.
 *
 * Generates a digital signature on the card.  
 * This function handles the process of hash + sign 
 * with previously selected keys (by mean of set_security environment
 *
 * AS iso7816 and DNIe Manual states there are 3 ways to perform 
 * this operation:
 *
 * - (plaintext) Hash on plaintext + sign
 * - (partial hash) Send a externally evaluated pkcs1 hash + sign
 * - (hash) directly sign a given sha1 hash
 *
 * So the code analyze incoming data, decide which method to be used
 * and applies
 *
 * @param card pointer to sc_card_t structure
 * @param data data to be hased/signed
 * @param datalen length of provided data
 * @param out buffer to store results into
 * @param outlen available space in result buffer
 * @return
 *  - Positive value: Size of data stored in out buffer when no error
 *  - Negative value: error code
 */
static int dnie_compute_signature(struct sc_card *card,
				  const u8 * data, size_t datalen,
				  u8 * out, size_t outlen)
{
	int result = SC_SUCCESS;
	struct sc_apdu apdu;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];	/* to compose digest+hash data */
	size_t sbuflen = 0;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];	/* to receive sign response */

	/* some preliminar checks */
	if ((card == NULL) || (card->ctx == NULL))
		return SC_ERROR_INVALID_ARGUMENTS;
	/* OK: start working */
	LOG_FUNC_CALLED(card->ctx);
	/* more checks */
	if ((data == NULL) || (out == NULL))
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	if (datalen > SC_MAX_APDU_BUFFER_SIZE)	/* should be 256 */
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	if (outlen<256) /* enought space to store 2048 bit response */
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

#ifdef ENABLE_DNIE_UI
	/* (Requested by DGP): on signature operation, ask user consent */
	if (GET_DNIE_PRIV_DATA(card)->rsa_key_ref == 0x02) {	/* TODO: revise key ID handling */
		result = sc_ask_user_consent(card,user_consent_title,user_consent_message);
		LOG_TEST_RET(card->ctx, result, "User consent denied");
	}
#endif    

	/*
	   Seems that OpenSC already provides pkcs#1 v1.5 DigestInfo structure 
	   with pre-calculated hash. So no need to to any Hash calculation, 

	   So just extract 15+20 DigestInfo+Hash info from ASN.1 provided
	   data and feed them into sign() command
	 */
	sc_log(card->ctx,
	       "Compute signature len: '%d' bytes:\n%s\n============================================================",
	       datalen, sc_dump_hex(data, datalen));
	if (datalen != 256) {
		sc_log(card->ctx, "Expected pkcs#1 v1.5 DigestInfo data");
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_WRONG_LENGTH);
	}

	/* try to strip pkcs1 padding */
	sbuflen = sizeof(sbuf);
	memset(sbuf, 0, sbuflen);
	result = sc_pkcs1_strip_01_padding(card->ctx, data, datalen, sbuf, &sbuflen);
	if (result != SC_SUCCESS) {
		sc_log(card->ctx, "Provided data is not pkcs#1 padded");
		/* TODO: study what to do on plain data */
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_WRONG_PADDING);
	}

	/*INS: 0x2A  PERFORM SECURITY OPERATION
	 * P1:  0x9E  Resp: Digital Signature
	 * P2:  0x9A  Cmd: Input for Digital Signature */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, 0x9E, 0x9A);
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = 256;		/* signature response size */
	apdu.data = sbuf;
	apdu.lc = sbuflen;	/* 15 SHA1 DigestInfo + 20 SHA1 computed Hash */
	apdu.datalen = sizeof(sbuf);
	/* tell card to compute signature */
	result = dnie_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, result, "compute_signature() failed");
	/* check response */
	result = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, result, "compute_signature() response error");

	/* ok: copy result from buffer */
	memcpy(out, apdu.resp, apdu.resplen);
	/* and return response length */
	LOG_FUNC_RETURN(card->ctx, apdu.resplen);
}

/*
 * ISO 7816-9 functions
 */

/**
 * OpenDNIe implementation of List_Files() card driver operation.
 *
 * List available files in current DF
 * This is a dirty and trick implementation:
 * Just try every ID in current dir
 *
 * @param card Pointer to Card Driver structure
 * @param buff buffer to store result into
 * @param bufflen size of provided buffer
 * @return SC_SUCCESS if OK; else error code
 *
 * TODO: check for presence of every file ids on a DF is not
 * practical. Locate a better way to handle, or remove code
 */
static int dnie_list_files(sc_card_t * card, u8 * buf, size_t buflen)
{
	int res = SC_SUCCESS;
	int id1 = 0;
	int id2 = 0;
	size_t count = 0;
	u8 data[2];
	sc_apdu_t apdu;
	sc_apdu_t back;
	if (!card || !card->ctx)
		return SC_ERROR_INVALID_ARGUMENTS;

	LOG_FUNC_CALLED(card->ctx);
	if (!buf || (buflen < 2))
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

	/* compose select_file(ID) command */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xA4, 0x00, 0x00);
	apdu.le = 0;
	apdu.lc = 2;
	apdu.data = data;
	apdu.resp = NULL;
	apdu.datalen = 2;
	apdu.resplen = 0;
	/* compose select_file(PARENT) command */
	sc_format_apdu(card, &back, SC_APDU_CASE_1, 0xA4, 0x03, 0x00);
	back.le = 0;
	back.lc = 0;
	back.data = NULL;
	back.resp = NULL;
	back.datalen = 0;
	back.resplen = 0;
	/* iterate on every possible ids */
	for (id1 = 0; id1 < 256; id1++) {
		for (id2 = 0; id2 < 256; id2++) {
			if (count >= (buflen - 2)) {
				sc_log(card->ctx,
				       "list_files: end of buffer. Listing stopped");
				LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
			}
			/* according iso several ids are not allowed, so check for it */
			if ((id1 == 0x3F) && (id2 == 0xFF))
				continue;	/* generic parent "." DF */
			if ((id1 == 0x2F) && (id2 == 0x00))
				continue;	/* RFU see iso 8.2.1.1 */
			if ((id1 == 0x2F) && (id2 == 0x01))
				continue;	/* RFU */
			/* compose and transmit select_file() cmd */
			data[0] = (u8) (0xff & id1);
			data[1] = (u8) (0xff & id2);
			res = dnie_transmit_apdu(card, &apdu);
			if (res != SC_SUCCESS) {
				sc_log(card->ctx, "List file '%02X%02X' failed",
				       id1, id2);
				/* if file not found, continue; else abort */
				if (res != SC_ERROR_FILE_NOT_FOUND) 
					LOG_FUNC_RETURN(card->ctx, res);
				continue;
			}
			/* if file found, process fci to get file type */
			sc_log(card->ctx, "Found File ID '%02X%02X'", id1, id2);
			/* store id into buffer */
			*(buf + count++) = data[0];
			*(buf + count++) = data[1];
			/* TODO: 
			* if found file is a DF go back to parent DF 
			* to continue search */
		}
	}
	/* arriving here means all done */
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

/**
 * Parse APDU results to generate proper error code.
 *
 * Traps standard check_sw function to take care on special error codes
 * for OpenDNIe (mostly related to SM status and operations)
 *
 * @param card Pointer to Card driver Structure
 * @param sw1 SW1 APDU response byte
 * @param sw2 SW2 APDU response byte
 * @return SC_SUCCESS if no error; else proper error code
 */
static int dnie_check_sw(struct sc_card *card,
			 unsigned int sw1, unsigned int sw2)
{
	int res = SC_SUCCESS;
	int n = 0;
	if (!card || !card->ctx)
		return SC_ERROR_INVALID_ARGUMENTS;
	LOG_FUNC_CALLED(card->ctx);

	/* check specific dnie errors */
	for (n = 0; dnie_errors[n].SWs != 0; n++) {
		if (dnie_errors[n].SWs == ((sw1 << 8) | sw2)) {
			sc_log(card->ctx, "%s", dnie_errors[n].errorstr);
			return dnie_errors[n].errorno;
		}
	}

	/* arriving here means check for supported iso error codes */
	res = iso_ops->check_sw(card, sw1, sw2);
	LOG_FUNC_RETURN(card->ctx, res);
}

/**
 * OpenDNIe implementation for Card_Ctl() card driver operation.
 *
 * This command provides access to non standard functions provided by
 * this card driver, as defined in cardctl.h
 *
 * @param card Pointer to card driver structure
 * @param request Operation requested
 * @param data where to get data/store response
 * @return SC_SUCCESS if ok; else error code
 * @see cardctl.h
 *
 * TODO: wait for GET_CARD_INFO generic cardctl to be implemented
 * in opensc and rewrite code according it
 */
static int dnie_card_ctl(struct sc_card *card,
			 unsigned long request, void *data)
{
	int result = SC_SUCCESS;
	if ((card == NULL) || (card->ctx == NULL))
		return SC_ERROR_INVALID_ARGUMENTS;
	LOG_FUNC_CALLED(card->ctx);
	if (data == NULL) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	}
	switch (request) {
		/* obtain lifecycle status by reading card->type */
	case SC_CARDCTL_LIFECYCLE_GET:
		switch (card->type) {
		case SC_CARD_TYPE_DNIE_ADMIN:
			result = SC_CARDCTRL_LIFECYCLE_ADMIN;
			break;
		case SC_CARD_TYPE_DNIE_USER:
			result = SC_CARDCTRL_LIFECYCLE_USER;
			break;
		case SC_CARD_TYPE_DNIE_BLANK:
		case SC_CARD_TYPE_DNIE_TERMINATED:
			result = SC_CARDCTRL_LIFECYCLE_OTHER;
			break;
		}
		*(int *)data = result;
		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
		/* call card to obtain serial number */
	case SC_CARDCTL_GET_SERIALNR:
		result = dnie_get_serialnr(card, (sc_serial_number_t *) data);
		LOG_FUNC_RETURN(card->ctx, result);
	case SC_CARDCTL_DNIE_GENERATE_KEY:
		/* some reports says that this card supports genkey */
		result = dnie_generate_key(card, data);
		LOG_FUNC_RETURN(card->ctx, result);
	case SC_CARDCTL_DNIE_GET_INFO:
		/* retrieve name, surname and eid number */
		result = dnie_get_info(card, data);
		LOG_FUNC_RETURN(card->ctx, result);
	default:
		/* default: unsupported function */
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	}
}

/**
 * Read first bytes of an EF to check for compression data.
 *
 * FCI info on compressed files provides the length of the compressed
 * data. When fci returns filetype = 0x24, needs to check if the
 * file is compressed, and set up properly correct file length, to let
 * the read_binary() file cache work
 *
 * Extract real file length from compressed file is done by mean of
 * reading 8 first bytes for uncompressed/compressed lenght. 
 * Lengths are provided as two 4-byte little endian numbers
 *
 * Implemented just like a direct read binary apdu bypassing dnie file cache
 *
 * @param card sc_card_t structure pointer
 * @return <0: error code - ==0 not compressed - >0 file size
 */
static int dnie_read_header(struct sc_card *card)
{
	sc_apdu_t apdu;
	int r;
	u8 buf[SC_MAX_APDU_BUFFER_SIZE];
	unsigned long uncompressed = 0L;
	unsigned long compressed = 0L;
	sc_context_t *ctx = NULL;

	if (!card || !card->ctx)
		return SC_ERROR_INVALID_ARGUMENTS;
	ctx = card->ctx;
	LOG_FUNC_CALLED(ctx);

	/* initialize apdu */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xB0, 0x00, 0x00);
	apdu.p1 = 0x00;
	apdu.p2 = 0x00;
	apdu.le = 8;		/* read 8 bytes at begining of file */
	apdu.resplen = SC_MAX_APDU_BUFFER_SIZE;
	apdu.resp = buf;
	/* transmit apdu */
	r = dnie_transmit_apdu(card, &apdu);
	if (r != SC_SUCCESS) {
		sc_log(ctx, "read_header() APDU transmit failed");
		LOG_FUNC_RETURN(ctx, r);
	}
	/* check response */
	if (apdu.resplen != 8)
		goto header_notcompressed;
	uncompressed = le2ulong(apdu.resp);
	compressed = le2ulong(apdu.resp + 4);
	if (uncompressed < compressed)
		goto header_notcompressed;
	if (uncompressed > 32767)
		goto header_notcompressed;
	/* ok: assume data is correct */
	sc_log(ctx, "read_header: uncompressed file size is %lu", uncompressed);
	return (int)(0x7FFF & uncompressed);

 header_notcompressed:
	sc_log(ctx, "response doesn't match compressed file header");
	return 0;
}

/** 
 *  Access control list bytes for propietary DNIe FCI response for DF's.
 *  based in information from official DNIe Driver
 *  Parsing code based on itacns card driver
 */
static int df_acl[] = {		/* to handle DF's */
	SC_AC_OP_CREATE, SC_AC_OP_DELETE,
	SC_AC_OP_REHABILITATE, SC_AC_OP_INVALIDATE,
	-1			/* !hey!, what about 5th byte of FCI info? */
};

/** 
 *  Access control list bytes for propietary DNIe FCI response for EF's.
 *  based in information from official DNIe Driver
 *  Parsing code based on itacns card driver
 */
static int ef_acl[] = {		/* to handle EF's */
	SC_AC_OP_READ, SC_AC_OP_UPDATE,
	SC_AC_OP_REHABILITATE, SC_AC_OP_INVALIDATE,
	-1			/* !hey!, what about 5th byte of FCI info? */
};

/**
 * OpenDNIe implementation of Process_FCI() card driver command.
 *
 * Parse SelectFile's File Control information.
 * - First, std iso_parse_fci is called to parse std fci tags
 * - Then analyze propietary tag according DNIe Manual
 *
 * @param card OpenSC card structure pointer
 * @param file currently selected EF or DF
 * @param buf received FCI data
 * @param buflen FCI length
 * @return SC_SUCCESS if OK; else error code 
 */
static int dnie_process_fci(struct sc_card *card,
			    struct sc_file *file, const u8 * buf, size_t buflen)
{
	int res = SC_SUCCESS;
	int *op = df_acl;
	int n = 0;
	sc_context_t *ctx = NULL;
	if ((card == NULL) || (card->ctx == NULL) || (file == NULL))
		return SC_ERROR_INVALID_ARGUMENTS;
	ctx = card->ctx;
	LOG_FUNC_CALLED(ctx);
	/* first of all, let iso do the hard work */
	res = iso_ops->process_fci(card, file, buf, buflen);
	LOG_TEST_RET(ctx, res, "iso7816_process_fci() failed");
	/* if tag 0x85 is received, then file->prop_attr_len should be filled
	 * by sc_file_set_prop_attr() code. So check and set data according manual 
	 * Note errata at pg 35 of Manual  about DF identifier (should be 0x38) */
	if (file->prop_attr_len == 0) {	/* no proprietary tag (0x85) received */
		res = SC_SUCCESS;
		goto dnie_process_fci_end;
	}
	/* at least 10 bytes should be received */
	if (file->prop_attr_len < 10) {
		res = SC_ERROR_WRONG_LENGTH;
		goto dnie_process_fci_end;
	}
	/* byte 0 denotes file type */
	switch (file->prop_attr[0]) {
	case 0x01:		/* EF for plain files */
		file->type = SC_FILE_TYPE_WORKING_EF;
		file->ef_structure = SC_FILE_EF_TRANSPARENT;
		break;
	case 0x15:		/* EF for keys: linear variable simple TLV */
		file->type = SC_FILE_TYPE_WORKING_EF;
		/* pin file 3F000000 has also this EF type */
		if ( ( file->prop_attr[3] == 0x00 ) && (file->prop_attr[3] == 0x00 ) ) {
			sc_log(ctx,"Processing pin EF");
			break;
		}
		/* FCI response for Keys EF returns 3 additional bytes */
		if (file->prop_attr_len < 13) {
			sc_log(ctx, "FCI response len for Keys EF should be 13 bytes");
			res = SC_ERROR_WRONG_LENGTH;
			goto dnie_process_fci_end;
		}
		break;
	case 0x24:		/* EF for compressed certificates */
		file->type = SC_FILE_TYPE_WORKING_EF;
		file->ef_structure = SC_FILE_EF_TRANSPARENT;
		/* evaluate real length by reading first 8 bytes from file */
		res = dnie_read_header(card);
		/* Hey!, we need pin to read certificates... */
		if (res == SC_ERROR_SECURITY_STATUS_NOT_SATISFIED)
			goto dnie_process_fci_end;
		if (res <= 0) {
			sc_log(ctx,
			       "Cannot evaluate uncompressed size. use fci length");
		} else {
			sc_log(ctx, "Storing uncompressed size '%d' into fci",
			       res);
			file->prop_attr[3] = (u8) ((res >> 8) & 0xff);
			file->prop_attr[4] = (u8) (res & 0xff);
		}
		break;
	case 0x38:		/* Errata: manual page 35 says wrong 0x34 */
		file->type = SC_FILE_TYPE_DF;
		break;
	default:
		res = SC_ERROR_UNKNOWN_DATA_RECEIVED;
		goto dnie_process_fci_end;
	}

	/* bytes 1 and 2 stores file ID */
	file->id = ( ( 0xff & (int)file->prop_attr[1] ) << 8 ) | 
			( 0xff & (int)file->prop_attr[2] ) ;

	/* bytes 3 and 4 states file length */
	file->size = ( ( 0xff & (int)file->prop_attr[3] ) << 8 ) | 
			( 0xff & (int)file->prop_attr[4] ) ;

	/* bytes 5 to 9 states security attributes */
	/* NOTE: 
	 * seems that these 5 bytes are handled according iso7816-9 sect 8.
	 * but sadly that each card uses their own bits :-(
	 * Moreover: Manual talks on 5 bytes, but official driver only uses 4
	 * No info available (yet), so copy code from card-jcos.c / card-flex.c
	 * card drivers and pray... */
	op = (file->type == SC_FILE_TYPE_DF) ? df_acl : ef_acl;
	for (n = 0; n < 5; n++) {
		int key_ref = 0;
		if (*(op + n) == -1)
			continue;	/* unused entry: skip */
		key_ref = file->prop_attr[5 + n] & 0x0F;
		switch (0xF0 & file->prop_attr[5 + n]) {
		case 0x00:
			sc_file_add_acl_entry(file, *(op + n), SC_AC_NONE,
					      SC_AC_KEY_REF_NONE);
			break;
		case 0x10:
			/* this tag is omitted in official code 
			   case 0x20: 
			 */
		case 0x30:
			sc_file_add_acl_entry(file, *(op + n), SC_AC_CHV,
					      key_ref);
			break;
		case 0x40:
			sc_file_add_acl_entry(file, *(op + n), SC_AC_TERM,
					      key_ref);
			break;
		case 0xF0:
			sc_file_add_acl_entry(file, *(op + n), SC_AC_NEVER,
					      SC_AC_KEY_REF_NONE);
			break;
		default:
			sc_file_add_acl_entry(file, *(op + n), SC_AC_UNKNOWN,
					      SC_AC_KEY_REF_NONE);
			break;
		}
	}
	/* NOTE: Following bytes are described at DNIe manual pg 36, but No 
	   documentation about what to do with following data is provided... 
	   logs suggest that they are neither generated nor handled.

	   UPDATE: these additional bytes are received when FileDescriptor tag
	   is 0x15 (EF for keys)
	 */
	if (file->prop_attr[0] == 0x15) {
		sc_log(card->ctx,
		       "Processing flags for Cryptographic key files");
		/* byte 10 (if present) shows Control Flags for security files */
		/* bytes 11 and 12 (if present) states Control bytes for 
		   RSA crypto files */
		/* TODO: write when know what to do */
	}
	res = SC_SUCCESS;	/* arriving here means success */
 dnie_process_fci_end:
	LOG_FUNC_RETURN(card->ctx, res);
}

/*
 * PIN related functions
 * NOTE:
 * DNIe manual says only about CHV1 PIN verify, but several sources talks
 * about the ability to also handle CHV1 PIN change
 * So prepare code to eventually support
 *
 * Anyway pin unlock is not available: no way to get PUK as these code is
 * obtained by mean of user fingerprint, only available at police station
 */

/**
 * Change PIN.
 *
 * Not implemented yet, as current availability for DNIe user driver 
 * is unknown
 *
 * @param card Pointer to Card Driver data structrure
 * @param data Pointer to Pin data structure
 * @return SC_SUCCESS if ok; else error code
 */
static int dnie_pin_change(struct sc_card *card, struct sc_pin_cmd_data * data)
{
	int res=SC_SUCCESS;
	LOG_FUNC_CALLED(card->ctx);
#ifdef ENABLE_SM
    /* Ensure that secure channel is established from reset */
    res = cwa_create_secure_channel(card, GET_DNIE_PRIV_DATA(card)->cwa_provider, CWA_SM_COLD);
    LOG_TEST_RET(card->ctx, res, "Establish SM failed");
#endif
	LOG_FUNC_RETURN(card->ctx,SC_ERROR_NOT_SUPPORTED);
}

/** 
 * Verify PIN.
 *
 * Initialize SM and send pin verify CHV1 command to DNIe
 *
 * @param card Pointer to Card Driver data structure
 * @param data Pointer to Pin data structure
 * @param tries_left; on fail stores the number of tries left before car lock
 * @return SC_SUCCESS if ok, else error code; on pin incorrect also sets tries_left
 */
static int dnie_pin_verify(struct sc_card *card,
                        struct sc_pin_cmd_data *data, int *tries_left)
{
#ifdef ENABLE_SM
	int res=SC_SUCCESS;
	sc_apdu_t apdu;

	u8 pinbuffer[SC_MAX_APDU_BUFFER_SIZE];
	int pinlen = 0;
	int padding = 0;

	LOG_FUNC_CALLED(card->ctx);
	/* ensure that secure channel is established from reset */
	res = cwa_create_secure_channel(card, GET_DNIE_PRIV_DATA(card)->cwa_provider, CWA_SM_COLD);
	LOG_TEST_RET(card->ctx, res, "Establish SM failed");

	data->apdu = &apdu;	/* prepare apdu struct */
	/* compose pin data to be inserted in apdu */
	if (data->flags & SC_PIN_CMD_NEED_PADDING)
		padding = 1;
	data->pin1.offset = 0;
	res = sc_build_pin(pinbuffer, sizeof(pinbuffer), &data->pin1, padding);
	if (res < 0)
		LOG_FUNC_RETURN(card->ctx, res);
	pinlen = res;

	/* compose apdu */
	memset(&apdu, 0, sizeof(apdu));	/* clear buffer */
	apdu.cla = 0x00;
	apdu.cse = SC_APDU_CASE_3_SHORT;
	apdu.ins = (u8) 0x20;	/* Verify cmd */
	apdu.p1 = (u8) 0x00;
	apdu.p2 = (u8) 0x00;
	apdu.lc = pinlen;
	apdu.datalen = pinlen;
	apdu.data = pinbuffer;
	apdu.resplen = 0;
	apdu.le = 0;

	/* and send to card throught virtual channel */
	res = dnie_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, res, "VERIFY APDU Transmit fail");

	/* check response and if requested setup tries_left */
	if (tries_left != NULL) {	/* returning tries_left count is requested */
		if ((apdu.sw1 == 0x63) && ((apdu.sw2 & 0xF0) == 0xC0)) {
			*tries_left = apdu.sw2 & 0x0F;
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_PIN_CODE_INCORRECT);
		}
	}
	res = dnie_check_sw(card, apdu.sw1, apdu.sw2);	/* not a pinerr: parse result */

	/* the end: a bit of Mister Proper and return */
	memset(&apdu, 0, sizeof(apdu));	/* clear buffer */
	data->apdu = NULL;
	LOG_FUNC_RETURN(card->ctx, res);
#else
    LOG_TEST_RET(card->ctx, SC_ERROR_NOT_SUPPORTED, "built without support of SM and External Authentication");
    return SC_ERROR_NOT_SUPPORTED;
#endif
}

/* pin_cmd: verify/change/unblock command; optionally using the
 * card's pin pad if supported.
 */

/**
 * OpenDNIe implementation for Pin_Cmd() card driver command.
 *
 * @param card Pointer to Card Driver data structure
 * @param data Pointer to Pin data structure
 * @param tries_left; if pin_verify() operation, on incorrect pin stores the number of tries left before car lock
 * @return SC_SUCCESS if ok, else error code; on pin incorrect also sets tries_left
 */
static int dnie_pin_cmd(struct sc_card *card,
			struct sc_pin_cmd_data *data, int *tries_left)
{
	int res = SC_SUCCESS;
	int lc = SC_CARDCTRL_LIFECYCLE_USER;

	if ((card == NULL) || (card->ctx == NULL) || (data == NULL))
		return SC_ERROR_INVALID_ARGUMENTS;
	LOG_FUNC_CALLED(card->ctx);

	/* 
	* some flags and settings from documentation 
	* No (easy) way to handle pinpad throught SM, so disable it
	*/
	data->flags &= ~SC_PIN_CMD_NEED_PADDING; /* no pin padding */
	data->flags &= ~SC_PIN_CMD_USE_PINPAD;	 /* cannot handle pinpad */

	/* ensure that card is in USER Lifecycle */
	res = dnie_card_ctl(card, SC_CARDCTL_LIFECYCLE_GET, &lc);
	LOG_TEST_RET(card->ctx, res, "Cannot get card LC status");
	if (lc != SC_CARDCTRL_LIFECYCLE_USER) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_CARD);
	}

	/* only allow changes on CHV pin ) */
	switch (data->pin_type) {
	case SC_AC_CHV:	/* Card Holder Verifier */
		break;
	case SC_AC_TERM:	/* Terminal auth */
	case SC_AC_PRO:	/* SM auth */
	case SC_AC_AUT:	/* Key auth */
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	default:
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	}
	/* This DNIe driver only supports VERIFY operation */
	switch (data->cmd) {
	case SC_PIN_CMD_VERIFY:
		res =  dnie_pin_verify(card,data,tries_left);
		break;
	case SC_PIN_CMD_CHANGE:
		res =  dnie_pin_change(card,data);
		break;
	case SC_PIN_CMD_UNBLOCK:
	case SC_PIN_CMD_GET_INFO:
		res= SC_ERROR_NOT_SUPPORTED;
		break;
	default:
		res= SC_ERROR_INVALID_ARGUMENTS;
		break;
	}
	/* return result */
	LOG_FUNC_RETURN(card->ctx, res);
}

/**********************************************************************/

/**
 * Internal function to initialize card driver function pointers.
 *
 * This is done by getting a copy for iso7816 card operations, 
 * and replace every DNIe specific functions
 *
 * @return DNIe card driver data, or null on failure
 */
static sc_card_driver_t *get_dnie_driver(void)
{
	sc_card_driver_t *iso_drv = sc_get_iso7816_driver();

	/* memcpy() from standard iso7816 declared operations */
	if (iso_ops == NULL)
		iso_ops = iso_drv->ops;
	dnie_ops = *iso_drv->ops;

	/* fill card specific function pointers */
	/* NULL means that function is not supported neither by DNIe nor iso7816.c */
	/* if pointer is omitted, default ISO7816 function will be used */

	/* initialization */
	dnie_ops.match_card	= dnie_match_card;
	dnie_ops.init		= dnie_init;
	dnie_ops.finish		= dnie_finish;

	/* iso7816-4 functions */
	dnie_ops.read_binary	= dnie_read_binary;
	dnie_ops.write_binary	= NULL;
	dnie_ops.update_binary	= NULL;
	dnie_ops.erase_binary	= NULL;
	dnie_ops.read_record	= NULL;
	dnie_ops.write_record	= NULL;
	dnie_ops.append_record	= NULL;
	dnie_ops.update_record	= NULL;
	dnie_ops.select_file	= dnie_select_file;
	dnie_ops.get_challenge	= dnie_get_challenge;

	/* iso7816-8 functions */
	dnie_ops.verify		= NULL;
	dnie_ops.logout		= dnie_logout;
	/* dnie_ops.restore_security_env */
	dnie_ops.set_security_env = dnie_set_security_env;
	dnie_ops.decipher	= dnie_decipher;
	dnie_ops.compute_signature = dnie_compute_signature;
	dnie_ops.change_reference_data = NULL;
	dnie_ops.reset_retry_counter = NULL;

	/* iso7816-9 functions */
	dnie_ops.create_file	= NULL;
	dnie_ops.delete_file	= NULL;
	dnie_ops.list_files	= dnie_list_files;
	dnie_ops.check_sw	= dnie_check_sw;
	dnie_ops.card_ctl	= dnie_card_ctl;
	dnie_ops.process_fci	= dnie_process_fci;
	/* dnie_ops.construct_fci */
	dnie_ops.pin_cmd	= dnie_pin_cmd;
	dnie_ops.get_data	= NULL;
	dnie_ops.put_data	= NULL;
	dnie_ops.delete_record	= NULL;

	return &dnie_driver;
}

/**
 * Entry point for (static) OpenDNIe card driver.
 *
 * This is the only public function on this module
 *
 * @return properly initialized array pointer to card driver operations
 */
sc_card_driver_t *sc_get_dnie_driver(void)
{
	return get_dnie_driver();
}

#undef __CARD_DNIE_C__

#endif				/* ENABLE_OPENSSL */
