/*
 * PKCS15 emulation layer for EstEID card.
 *
 * Copyright (C) 2004, Martin Paljak <martin@paljak.pri.ee>
 * Copyright (C) 2004, Bud P. Bruegger <bud@comune.grosseto.it>
 * Copyright (C) 2004, Antonino Iacono <ant_iacono@tin.it>
 * Copyright (C) 2003, Olaf Kirch <okir@suse.de>
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

#include "internal.h"
#include "pkcs15.h"
#include "asn1.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

#include "esteid.h"

static void
set_string (char **strp, const char *value)
{
  if (*strp)
    free (strp);
  *strp = value ? strdup (value) : NULL;
}


int
select_esteid_df (sc_card_t * card)
{
  int r;
  sc_path_t tmppath;
  sc_format_path ("3F00EEEE", &tmppath);
  tmppath.type = SC_PATH_TYPE_PATH;
  r = sc_select_file (card, &tmppath, NULL);
  SC_TEST_RET (card->ctx, r, "esteid select DF failed");
  return r;
}

int
sc_pkcs15emu_esteid_init (sc_pkcs15_card_t * p15card)
{
  sc_card_t *card = p15card->card;
  unsigned char buff[256];
  int r, i, flags;
  sc_path_t tmppath;
  sc_pkcs15_id_t id;

  set_string (&p15card->label, "EstEID isikutunnistus");
  set_string (&p15card->manufacturer_id, "AS Sertifitseerimiskeskus");

  select_esteid_df (card);

  /* read the serial (document number) */
  sc_format_path ("5044", &tmppath);
  tmppath.type = SC_PATH_TYPE_PATH;
  r = sc_select_file (card, &tmppath, NULL);
  SC_TEST_RET (card->ctx, r, "select esteid PD failed");
  r = sc_read_record (card, SC_ESTEID_PD_DOCUMENT_NR, buff, 8,
		      SC_RECORD_BY_REC_NR);
  SC_TEST_RET (card->ctx, r, "read document number failed");
  // null-terminate
  buff[r] = '\0';
  set_string (&p15card->serial_number, buff);

  p15card->flags =
    SC_PKCS15_CARD_FLAG_PRN_GENERATION |
    SC_PKCS15_CARD_FLAG_EID_COMPLIANT | SC_PKCS15_CARD_FLAG_READONLY;

  /* EstEEID uses 1024b RSA */
  card->algorithm_count = 0;
  flags = SC_ALGORITHM_RSA_PAD_PKCS1;
  _sc_card_add_rsa_alg (card, 1024, flags, 0);

  /* add certificates */
  for (i = 0; i < 2; i++)
    {
      static char *esteid_cert_names[2] = {
	"Autentimissertifikaat",
	"Allkirjasertifikaat"
      };
      static char *esteid_cert_paths[2] = {
	"3f00eeeeaace",
	"3f00eeeeddce"
      };
      static int esteid_cert_ids[2] = {
	SC_ESTEID_AUTH,
	SC_ESTEID_SIGN
      };
      sc_path_t path;
      sc_pkcs15_id_t auth_id;

      sc_format_path (esteid_cert_paths[i], &path);
      path.type = SC_PATH_TYPE_PATH;
      auth_id.value[0] = esteid_cert_ids[i];
      auth_id.len = 1;

      r = sc_pkcs15emu_add_cert (p15card,
				 SC_PKCS15_TYPE_CERT_X509, 0,
				 &path, &auth_id, esteid_cert_names[i], 0);
    }

  /* the file with key pin info (tries left) */
  sc_format_path ("3f000016", &tmppath);
  sc_select_file (card, &tmppath, NULL);

  /* add pins */
  for (i = 0; i < 3; i++)
    {
      char tries_left;
      static char *esteid_pin_names[3] = {
	"PIN1 - Autentiseerimine",
	"PIN2 - Allkirjastamine",
	"PUK"
      };

      static int esteid_pin_min[3] = {
	4,
	5,
	8
      };

      static int esteid_pin_ref[3] = {
	1,
	2,
	0
      };

      static int esteid_pin_flags[3] = {
	0,
	0,
	SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN
      };

      r = sc_read_record (card, i + 1, buff, 128, SC_RECORD_BY_REC_NR);
      tries_left = buff[5];

      id.len = 1;
      id.value[0] = i + 1;




      sc_pkcs15emu_add_pin (p15card, &id,
			    esteid_pin_names[i], NULL,
			    esteid_pin_ref[i],
			    SC_PKCS15_PIN_TYPE_ASCII_NUMERIC,
			    esteid_pin_min[i], 12,
			    esteid_pin_flags[i], tries_left, '\0', 0);
    }

  /* add private keys */
  for (i = 0; i < 2; i++)
    {
      static int prkey_pin[2] = { SC_ESTEID_AUTH, SC_ESTEID_SIGN };
      static int prkey_usage[2] = {
	SC_PKCS15_PRKEY_USAGE_ENCRYPT |
	  SC_PKCS15_PRKEY_USAGE_DECRYPT |
	  SC_PKCS15_PRKEY_USAGE_SIGN |
	  SC_PKCS15_PRKEY_USAGE_SIGNRECOVER |
	  SC_PKCS15_PRKEY_USAGE_WRAP | SC_PKCS15_PRKEY_USAGE_UNWRAP,

	SC_PKCS15_PRKEY_USAGE_NONREPUDIATION
      };
      static char *prkey_name[2] = {
	"Autentiseerimise v\365ti",
	"Allkirjastamise v\365ti"
      };
      sc_pkcs15_id_t id, auth_id;

      id.value[0] = prkey_pin[i];
      id.len = 1;
      auth_id.value[0] = prkey_pin[i];
      auth_id.len = 1;

      // NULL may be a path.... ?
      r = sc_pkcs15emu_add_prkey (p15card, &id,
				  prkey_name[i],
				  SC_PKCS15_TYPE_PRKEY_RSA,
				  1024, prkey_usage[i], NULL,
				  i + 1, &auth_id, 0);
    }
  return 0;
}

static const char *atr1 = "3B:FE:94:00:FF:80:B1:FA:45:1F:03:45:73:74:45:49:44:20:76:65:72:20:31:2E:30:43";
static const char *atr2 = "3B:6E:00:FF:45:73:74:45:49:44:20:76:65:72:20:31:2E:30";

static int esteid_detect_card(sc_pkcs15_card_t *p15card)
{
	u8        buf[SC_MAX_ATR_SIZE];
	size_t    len = sizeof(buf);
	sc_card_t *card = p15card->card;

	/* XXX: save type of the micardo card in the card structure */
	if (sc_hex_to_bin(atr1, buf, &len))
		return SC_ERROR_INTERNAL;
	if (len == card->atr_len && !memcmp(card->atr, buf, len))
		return SC_SUCCESS;
	len = sizeof(buf);
	if (sc_hex_to_bin(atr2, buf, &len))
		return SC_ERROR_INTERNAL;
	if (len == card->atr_len && !memcmp(card->atr, buf, len))
		return SC_SUCCESS;

	return SC_ERROR_WRONG_CARD;
}

int sc_pkcs15emu_esteid_init_ex(sc_pkcs15_card_t *p15card,
				sc_pkcs15emu_opt_t *opts)
{

	if (opts && opts->flags & SC_PKCS15EMU_FLAGS_NO_CHECK)
		return sc_pkcs15emu_esteid_init(p15card);
	else {
		int r = esteid_detect_card(p15card);
		if (r)
			return SC_ERROR_WRONG_CARD;
		return sc_pkcs15emu_esteid_init(p15card);
	}
}
