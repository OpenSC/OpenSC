/**
 * cwa-dnie.h: Defines dnie_transmit_apdu wrapper for sc_transmit_apdu
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

#ifndef __CWADNIE_H__
#define __CWADNIE_H__

#ifdef ENABLE_OPENSSL

#include "libopensc/opensc.h"

#ifdef ENABLE_DNIE_UI
/**
* To handle user interface routines
*/
typedef struct ui_context {
	int user_consent_enabled;
	char *user_consent_app;
} ui_context_t;
#endif

struct cwa_provider_st;

/**
  * OpenDNIe private data declaration
  *
  * Defines internal data used in OpenDNIe code
  */
 typedef struct dnie_private_data_st {
 /*  sc_serial_number_t *serialnumber; < Cached copy of card serial number NOT USED AT THE MOMENT */
     int rsa_key_ref;    /**< Key id reference being used in sec operation */
     u8 *cache;      /**< Cache buffer for read_binary() operation */
     size_t cachelen;    /**< length of cache buffer */
     struct cwa_provider_st *cwa_provider;
#ifdef ENABLE_DNIE_UI
	 struct ui_context ui_ctx;
#endif
 } dnie_private_data_t;
 
/**
 * DNIe Card Driver private data
 */
#define GET_DNIE_PRIV_DATA(card) ((dnie_private_data_t *) ((card)->drv_data))
#define GET_DNIE_UI_CTX(card) (((dnie_private_data_t *) ((card)->drv_data))->ui_ctx)

int dnie_transmit_apdu(sc_card_t * card, sc_apdu_t * apdu);

void dnie_format_apdu(sc_card_t *card, sc_apdu_t *apdu,
                       int cse, int ins, int p1, int p2, int le, int lc,
                       unsigned char * resp, size_t resplen,
                       const unsigned char * data, size_t datalen);

void dnie_free_apdu_buffers(sc_apdu_t *apdu,
                               unsigned char * resp, size_t resplen);

#endif

#endif
