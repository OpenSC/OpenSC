/*
 * internal.h: Internal definitions for libopensc
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 *               2005        The OpenSC project
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

#ifndef _SC_INTERNAL_H
#define _SC_INTERNAL_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include <assert.h>
#ifdef _WIN32
#include <windows.h>
#endif

#include "common/simclist.h"
#include "libopensc/opensc.h"
#include "libopensc/log.h"
#include "libopensc/cards.h"

#ifdef ENABLE_OPENSSL
#include "libopensc/sc-ossl-compat.h"
#endif

#define SC_FILE_MAGIC			0x14426950

#ifndef _WIN32
#define msleep(t)	usleep((t) * 1000)
#else
#define msleep(t)	Sleep(t)
#define sleep(t)	Sleep((t) * 1000)
#endif

#ifndef MAX
#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#endif
#ifndef MIN
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#endif

struct sc_atr_table {
	/* The atr fields are required to
	 * be in aa:bb:cc hex format. */
	const char *atr;
	/* The atrmask is logically AND'd with an
	 * card atr prior to comparison with the
	 * atr reference value above. */
	const char *atrmask;
	const char *name;
	int type;
	unsigned long flags;
	/* Reference to card_atr configuration block,
	 * available to user configured card entries. */
	scconf_block *card_atr;
};

/* Internal use only */
int _sc_add_reader(struct sc_context *ctx, struct sc_reader *reader);
int _sc_parse_atr(struct sc_reader *reader);

/* Add an ATR to the card driver's struct sc_atr_table */
int _sc_add_atr(struct sc_context *ctx, struct sc_card_driver *driver, struct sc_atr_table *src);
int _sc_free_atr(struct sc_context *ctx, struct sc_card_driver *driver);

/**
 * Convert an unsigned long into 4 bytes in big endian order
 * @param  buf   the byte array for the result, should be 4 bytes long
 * @param  x     the value to be converted
 * @return       the buffer passed, containing the converted value
 */
u8 *ulong2bebytes(u8 *buf, unsigned long x);
/**
 * Convert an unsigned long into 2 bytes in big endian order
 * @param  buf   the byte array for the result, should be 2 bytes long
 * @param  x     the value to be converted
 * @return       the buffer passed, containing the converted value
 */
u8 *ushort2bebytes(u8 *buf, unsigned short x);
/**
 * Convert 4 bytes in big endian order into an unsigned long
 * @param  buf   the byte array of 4 bytes
 * @return       the converted value
 */
unsigned long bebytes2ulong(const u8 *buf);
/**
 * Convert 2 bytes in big endian order into an unsigned short
 * @param  buf   the byte array of 2 bytes
 * @return       the converted value
 */
unsigned short bebytes2ushort(const u8 *buf);

/**
 * Convert 2 bytes in little endian order into an unsigned short
 * @param  buf   the byte array of 2 bytes
 * @return       the converted value
 */
unsigned short lebytes2ushort(const u8 *buf);
/**
 * Convert 4 bytes in little endian order into an unsigned long
 * @param  buf   the byte array of 4 bytes
 * @return       the converted value
 */
unsigned long lebytes2ulong(const u8 *buf);

#define BYTES4BITS(num)  (((num) + 7) / 8)    /* number of bytes necessary to hold 'num' bits */

/* Returns an scconf_block entry with matching ATR/ATRmask to the ATR specified,
 * NULL otherwise. Additionally, if card driver is not specified, search through
 * all card drivers user configured ATRs. */
scconf_block *_sc_match_atr_block(sc_context_t *ctx, struct sc_card_driver *driver, struct sc_atr *atr);

/* Returns an index number if a match was found, -1 otherwise. table has to
 * be null terminated. */
int _sc_match_atr(struct sc_card *card, const struct sc_atr_table *table, int *type_out);

int _sc_card_add_algorithm(struct sc_card *card, const struct sc_algorithm_info *info);
int _sc_card_add_symmetric_alg(sc_card_t *card, unsigned int algorithm,
			       unsigned int key_length, unsigned long flags);
int _sc_card_add_rsa_alg(struct sc_card *card, unsigned int key_length,
		unsigned long flags, unsigned long exponent);
int _sc_card_add_ec_alg(struct sc_card *card, unsigned int key_length,
		unsigned long flags, unsigned long ext_flags,
		struct sc_object_id *curve_oid);

/********************************************************************/
/*                 pkcs1 padding/encoding functions                 */
/********************************************************************/

int sc_pkcs1_strip_01_padding(struct sc_context *ctx, const u8 *in_dat, size_t in_len,
		u8 *out_dat, size_t *out_len);
int sc_pkcs1_strip_02_padding(struct sc_context *ctx, const u8 *data, size_t len,
		u8 *out_dat, size_t *out_len);
int sc_pkcs1_strip_digest_info_prefix(unsigned int *algorithm,
		const u8 *in_dat, size_t in_len, u8 *out_dat, size_t *out_len);

/**
 * PKCS1 encodes the given data.
 * @param  ctx     IN  sc_context_t object
 * @param  flags   IN  the algorithm to use
 * @param  in      IN  input buffer
 * @param  inlen   IN  length of the input
 * @param  out     OUT output buffer (in == out is allowed)
 * @param  outlen  OUT length of the output buffer
 * @param  mod_bits IN  length of the modulus in bits
 * @return SC_SUCCESS on success and an error code otherwise
 */
int sc_pkcs1_encode(sc_context_t *ctx, unsigned long flags,
		const u8 *in, size_t inlen, u8 *out, size_t *outlen, size_t mod_bits);
/**
 * Get the necessary padding and sec. env. flags.
 * @param  ctx     IN  sc_contex_t object
 * @param  iflags  IN  the desired algorithms flags
 * @param  caps    IN  the card / key capabilities
 * @param  pflags  OUT the padding flags to use
 * @param  salg    OUT the security env. algorithm flag to use
 * @return SC_SUCCESS on success and an error code otherwise
 */
int sc_get_encoding_flags(sc_context_t *ctx,
		unsigned long iflags, unsigned long caps,
		unsigned long *pflags, unsigned long *salg);

/********************************************************************/
/*             mutex functions                                      */
/********************************************************************/

/**
 * Creates a new sc_mutex object. Note: unless sc_mutex_set_mutex_funcs()
 * this function does nothing and always returns SC_SUCCESS.
 * @param  ctx    sc_context_t object with the thread context
 * @param  mutex  pointer for the newly created mutex object
 * @return SC_SUCCESS on success and an error code otherwise
 */
int sc_mutex_create(const sc_context_t *ctx, void **mutex);
/**
 * Tries to acquire a lock for a sc_mutex object. Note: Unless
 * sc_mutex_set_mutex_funcs() has been called before this 
 * function does nothing and always returns SUCCESS.
 * @param  ctx    sc_context_t object with the thread context
 * @param  mutex  mutex object to lock
 * @return SC_SUCCESS on success and an error code otherwise
 */
int sc_mutex_lock(const sc_context_t *ctx, void *mutex);
/**
 * Unlocks a sc_mutex object. Note: Unless sc_mutex_set_mutex_funcs()
 * has been called before this function does nothing and always returns
 * SC_SUCCESS.
 * @param  ctx    sc_context_t object with the thread context
 * @param  mutex  mutex object to unlock
 * @return SC_SUCCESS on success and an error code otherwise
 */
int sc_mutex_unlock(const sc_context_t *ctx, void *mutex);
/**
 * Destroys a sc_mutex object. Note: Unless sc_mutex_set_mutex_funcs()
 * has been called before this function does nothing and always returns
 * SC_SUCCESS.
 * @param  ctx    sc_context_t object with the thread context
 * @param  mutex  mutex object to be destroyed
 * @return SC_SUCCESS on success and an error code otherwise
 */
int sc_mutex_destroy(const sc_context_t *ctx, void *mutex);
/**
 * Returns a unique id for every thread.
 * @param  ctx  sc_context_t object with the thread context
 * @return unsigned long with the unique id or 0 if not supported
 */
unsigned long sc_thread_id(const sc_context_t *ctx);

/********************************************************************/
/*             internal APDU handling functions                     */
/********************************************************************/

/**
 * Returns the encoded APDU in newly created buffer.
 * @param  ctx     sc_context_t object
 * @param  apdu    sc_apdu_t object with the APDU to encode
 * @param  buf     pointer to the newly allocated buffer
 * @param  len     length of the encoded APDU
 * @param  proto   protocol to be used
 * @return SC_SUCCESS on success and an error code otherwise
 */
int sc_apdu_get_octets(sc_context_t *ctx, const sc_apdu_t *apdu, u8 **buf,
		size_t *len, unsigned int proto);
/**
 * Sets the status bytes and return data in the APDU
 * @param  ctx     sc_context_t object
 * @param  apdu    the apdu to which the data should be written
 * @param  buf     returned data
 * @param  len     length of the returned data
 * @return SC_SUCCESS on success and an error code otherwise
 */
int sc_apdu_set_resp(sc_context_t *ctx, sc_apdu_t *apdu, const u8 *buf,
		size_t len);
/**
 * Logs APDU
 * @param  ctx          sc_context_t object
 * @param  buf          buffer with the APDU data
 * @param  len          length of the APDU
 * @param  is_outgoing  != 0 if the data is send to the card
 */
#define sc_apdu_log(ctx, data, len, is_outgoing) \
	sc_debug_hex(ctx, SC_LOG_DEBUG_NORMAL, is_outgoing != 0 ? "Outgoing APDU" : "Incoming APDU", data, len)

extern struct sc_reader_driver *sc_get_pcsc_driver(void);
extern struct sc_reader_driver *sc_get_ctapi_driver(void);
extern struct sc_reader_driver *sc_get_openct_driver(void);
extern struct sc_reader_driver *sc_get_cryptotokenkit_driver(void);

#ifdef __cplusplus
}
#endif

#endif
