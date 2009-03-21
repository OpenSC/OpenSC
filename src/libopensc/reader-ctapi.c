/*
 * reader-ctapi.c: Reader driver for CT-API
 *
 * Copyright (C) 2002  Juha Yrjölä <juha.yrjola@iki.fi>
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
#include "ctbcs.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <ltdl.h>

#define GET_PRIV_DATA(r) ((struct ctapi_private_data *) (r)->drv_data)
#define GET_SLOT_DATA(r) ((struct ctapi_slot_data *) (r)->drv_data)

#ifdef _WIN32
typedef char pascal CT_INIT_TYPE(unsigned short ctn, unsigned short Pn);
typedef char pascal CT_CLOSE_TYPE(unsigned short ctn);
typedef char pascal CT_DATA_TYPE(unsigned short ctn, unsigned char *dad, \
			 unsigned char *sad, unsigned short lc, \
			 unsigned char *cmd, unsigned short *lr, \
			 unsigned char *rsp);
#else
typedef char CT_INIT_TYPE(unsigned short ctn, unsigned short Pn);
typedef char CT_CLOSE_TYPE(unsigned short ctn);
typedef char CT_DATA_TYPE(unsigned short ctn, unsigned char *dad, \
			 unsigned char *sad, unsigned short lc, \
			 unsigned char *cmd, unsigned short *lr, \
			 unsigned char *rsp);
#endif

struct ctapi_module {
	char *name;
	void *dlhandle;
	int ctn_count;
};

struct ctapi_global_private_data {
	int module_count;
	struct ctapi_module *modules;
};

struct ctapi_functions {
	CT_INIT_TYPE *CT_init;
	CT_CLOSE_TYPE *CT_close;
	CT_DATA_TYPE *CT_data;
};

/* Reader specific private data */
#define CTAPI_FU_KEYBOARD	0x1
#define CTAPI_FU_DISPLAY	0x2
#define CTAPI_FU_BIOMETRIC	0x4
#define CTAPI_FU_PRINTER	0x8

struct ctapi_private_data {
	struct ctapi_functions funcs;
	unsigned short ctn;
	int ctapi_functional_units;
};

struct ctapi_slot_data {
	void *filler;
};

/* Reset slot or reader */
static int ctapi_reset(sc_reader_t *reader, sc_slot_info_t *slot)
{
	struct ctapi_private_data *priv = GET_PRIV_DATA(reader);
	char rv;
	u8 cmd[5], rbuf[256], sad, dad;
	unsigned short lr;

	cmd[0] = CTBCS_CLA;
	cmd[1] = CTBCS_INS_RESET;
	cmd[2] = slot ? CTBCS_P1_INTERFACE1 + slot->id : CTBCS_P1_CT_KERNEL;
	cmd[3] = 0x00; /* No response. We might also use 0x01 (return ATR) or 0x02 (return historical bytes) here */
	cmd[4] = 0x00;
	dad = 1;
	sad = 2;
	lr = 256;

	rv = priv->funcs.CT_data(priv->ctn, &dad, &sad, 5, cmd, &lr, rbuf);
	if (rv || (lr < 2)) {
		sc_error(reader->ctx, "Error getting status of terminal: %d, using defaults\n", rv);
		return SC_ERROR_TRANSMIT_FAILED;
	}
	if (rbuf[lr-2] != 0x90) {
		sc_error(reader->ctx, "SW1/SW2: 0x%x/0x%x\n", rbuf[lr-2], rbuf[lr-1]);
		return SC_ERROR_TRANSMIT_FAILED;
	}
	return 0;
}

static void set_default_fu(sc_reader_t *reader)
{
	if (!reader) return;

	reader->slot_count = 1;
	reader->slot[0].id = 0;
	reader->slot[0].capabilities = 0;
	reader->slot[0].atr_len = 0;
	reader->slot[0].drv_data = NULL;
}

/* Detect functional units of the reader according to CT-BCS spec version 1.0
   (14.04.2004, http://www.teletrust.de/down/mct1-0_t4.zip) */
static void detect_functional_units(sc_reader_t *reader)
{
	struct ctapi_private_data *priv = GET_PRIV_DATA(reader);
	char rv;
	u8 cmd[5], rbuf[256], sad, dad;
	unsigned short lr;
	int NumUnits;
	int i;

	priv->ctapi_functional_units = 0;

	cmd[0] = CTBCS_CLA;
	cmd[1] = CTBCS_INS_STATUS;
	cmd[2] = CTBCS_P1_CT_KERNEL;
	cmd[3] = CTBCS_P2_STATUS_TFU;
	cmd[4] = 0x00;
	dad = 1;
	sad = 2;
	lr = 256;

	rv = priv->funcs.CT_data(priv->ctn, &dad, &sad, 5, cmd, &lr, rbuf);
	if (rv || (lr < 4) || (rbuf[lr-2] != 0x90)) {
		sc_error(reader->ctx, "Error getting status of terminal: %d, using defaults\n", rv);
		set_default_fu(reader);
		return;
	}
	if (rbuf[0] != CTBCS_P2_STATUS_TFU) {
		/* Number of slots might also detected by using CTBCS_P2_STATUS_ICC.
		   If you think that's important please do it... ;) */
		set_default_fu(reader);
		sc_error(reader->ctx, "Invalid data object returnd on CTBCS_P2_STATUS_TFU: 0x%x\n", rbuf[0]);
		return;
	}
	NumUnits = rbuf[1];
	if (NumUnits + 4 > lr) {
		set_default_fu(reader);
		sc_error(reader->ctx, "Invalid data returnd: %d functional units, size %d\n", NumUnits, rv);
		set_default_fu(reader);
		return;
	}
	reader->slot_count = 0;
	for(i = 0; i < NumUnits; i++) {
		switch(rbuf[i+2])
		{
			case CTBCS_P1_INTERFACE1:
			case CTBCS_P1_INTERFACE2:
			case CTBCS_P1_INTERFACE3:
			case CTBCS_P1_INTERFACE4:
			case CTBCS_P1_INTERFACE5:
			case CTBCS_P1_INTERFACE6:
			case CTBCS_P1_INTERFACE7:
			case CTBCS_P1_INTERFACE8:
			case CTBCS_P1_INTERFACE9:
			case CTBCS_P1_INTERFACE10:
			case CTBCS_P1_INTERFACE11:
			case CTBCS_P1_INTERFACE12:
			case CTBCS_P1_INTERFACE13:
			case CTBCS_P1_INTERFACE14:
			/* Maybe a weak point here if multiple interfaces are present and not returned
			   in the "canonical" order. This is not forbidden by the specs, but why should
			   anyone want to do that? */
				if (reader->slot_count >= SC_MAX_SLOTS) {
					sc_debug(reader->ctx, "Ignoring slot id 0x%x, can only handle %d slots\n", rbuf[i+2], SC_MAX_SLOTS);
				} else {
					reader->slot[reader->slot_count].id = reader->slot_count;
					reader->slot[reader->slot_count].capabilities = 0; /* Just to start with */
					reader->slot[reader->slot_count].atr_len = 0;
					reader->slot[reader->slot_count].drv_data = NULL;
					reader->slot_count++;
				}
				break;

			case CTBCS_P1_DISPLAY:
				priv->ctapi_functional_units |= CTAPI_FU_DISPLAY;
				sc_debug(reader->ctx, "Display detected\n");
				break;

			case CTBCS_P1_KEYPAD:
				priv->ctapi_functional_units |= CTAPI_FU_KEYBOARD;
				sc_debug(reader->ctx, "Keypad detected\n");
				break;

			case CTBCS_P1_PRINTER:
				priv->ctapi_functional_units |= CTAPI_FU_PRINTER;
				sc_debug(reader->ctx, "Printer detected\n");
				break;

			case CTBCS_P1_FINGERPRINT:
			case CTBCS_P1_VOICEPRINT:
			case CTBCS_P1_DSV:
			case CTBCS_P1_FACE_RECOGNITION:
			case CTBCS_P1_IRISSCAN:
				priv->ctapi_functional_units |= CTAPI_FU_BIOMETRIC;
				sc_debug(reader->ctx, "Biometric sensor detected\n");
				break;

			default:
				sc_debug(reader->ctx, "Unknown functional unit 0x%x\n", rbuf[i+2]);
		}

	}
	if (reader->slot_count == 0) {
		sc_debug(reader->ctx, "No slots returned, assuming one default slot\n");
		set_default_fu(reader);
	}
	/* CT-BCS does not define Keyboard/Display for each slot, so I assume
	   those additional units can be used for each slot */
	if (priv->ctapi_functional_units) {
		for(i = 0; i < reader->slot_count; i++)	{
			if (priv->ctapi_functional_units & CTAPI_FU_KEYBOARD)
			reader->slot[i].capabilities |= SC_SLOT_CAP_PIN_PAD;
			if (priv->ctapi_functional_units & CTAPI_FU_DISPLAY)
			reader->slot[i].capabilities |= SC_SLOT_CAP_DISPLAY;
		}
	}
}

static int refresh_slot_attributes(sc_reader_t *reader,
				   sc_slot_info_t *slot)
{
	struct ctapi_private_data *priv = GET_PRIV_DATA(reader);
	char rv;
	u8 cmd[5], rbuf[256], sad, dad;
	unsigned short lr;

	cmd[0] = CTBCS_CLA;
	cmd[1] = CTBCS_INS_STATUS;
	cmd[2] = CTBCS_P1_CT_KERNEL;
	cmd[3] = CTBCS_P2_STATUS_ICC;
	cmd[4] = 0x00;
	dad = 1;
	sad = 2;
	lr = 256;

	slot->flags = 0;

	rv = priv->funcs.CT_data(priv->ctn, &dad, &sad, 5, cmd, &lr, rbuf);
	if (rv || (lr < 3) || (rbuf[lr-2] != 0x90)) {
		sc_error(reader->ctx, "Error getting status of terminal: %d/%d/0x%x\n", rv, lr, rbuf[lr-2]);
		return SC_ERROR_TRANSMIT_FAILED;
	}
	if (lr < 4) {
		/* Looks like older readers do not return data tag and length field, so assume one slot only */
		if (slot->id > 0) {
			sc_error(reader->ctx, "Status for slot id %d not returned, have only 1\n", slot->id);
			return SC_ERROR_SLOT_NOT_FOUND;
		}
		if (rbuf[0] & CTBCS_DATA_STATUS_CARD)
			slot->flags = SC_SLOT_CARD_PRESENT;
	} else {
		if (rbuf[0] != CTBCS_P2_STATUS_ICC) {
			/* Should we be more tolerant here? I do not think so... */
			sc_error(reader->ctx, "Invalid data object returnd on CTBCS_P2_STATUS_ICC: 0x%x\n", rbuf[0]);
		return SC_ERROR_TRANSMIT_FAILED;
	}
		if (rbuf[1] <= slot->id) {
			sc_error(reader->ctx, "Status for slot id %d not returned, only %d\n", slot->id, rbuf[1]);
			return SC_ERROR_SLOT_NOT_FOUND;
		}
		if (rbuf[2+slot->id] & CTBCS_DATA_STATUS_CARD)
		slot->flags = SC_SLOT_CARD_PRESENT;
	}

	return 0;
}

static int ctapi_internal_transmit(sc_reader_t *reader, sc_slot_info_t *slot,
			 const u8 *sendbuf, size_t sendsize,
			 u8 *recvbuf, size_t *recvsize,
			 unsigned long control)
{
	struct ctapi_private_data *priv = GET_PRIV_DATA(reader);
	u8 dad, sad;
	unsigned short lr;
	char rv;
	
	if (control)
		dad = 1;
	else if (!slot || slot->id == 0)
		dad = 0;
	else
		dad = slot->id + 1; /* Adressing of multiple slots, according to CT API 1.0 */
	sad = 2;
	lr = *recvsize;
	
	rv = priv->funcs.CT_data(priv->ctn, &dad, &sad, (unsigned short)sendsize, (u8 *) sendbuf, &lr, recvbuf);
	if (rv != 0) {
		sc_error(reader->ctx, "Error transmitting APDU: %d\n", rv);
		return SC_ERROR_TRANSMIT_FAILED;
	}
	*recvsize = lr;
	
	return 0;
}

static int ctapi_transmit(sc_reader_t *reader, sc_slot_info_t *slot,
	sc_apdu_t *apdu)
{
	size_t       ssize, rsize, rbuflen = 0;
	u8           *sbuf = NULL, *rbuf = NULL;
	int          r;

	rsize = rbuflen = apdu->resplen + 2;
	rbuf     = malloc(rbuflen);
	if (rbuf == NULL) {
		r = SC_ERROR_MEMORY_FAILURE;
		goto out;
	}
	/* encode and log the APDU */
	r = sc_apdu_get_octets(reader->ctx, apdu, &sbuf, &ssize, SC_PROTO_RAW);
	if (r != SC_SUCCESS)
		goto out;
	if (reader->ctx->debug >= 6)
		sc_apdu_log(reader->ctx, sbuf, ssize, 1);
	r = ctapi_internal_transmit(reader, slot, sbuf, ssize,
					rbuf, &rsize, apdu->control);
	if (r < 0) {
		/* unable to transmit ... most likely a reader problem */
		sc_error(reader->ctx, "unable to transmit");
		goto out;
	}
	if (reader->ctx->debug >= 6)
		sc_apdu_log(reader->ctx, rbuf, rsize, 0);
	/* set response */
	r = sc_apdu_set_resp(reader->ctx, apdu, rbuf, rsize);
out:
	if (sbuf != NULL) {
		sc_mem_clear(sbuf, ssize);
		free(sbuf);
	}
	if (rbuf != NULL) {
		sc_mem_clear(rbuf, rbuflen);
		free(rbuf);
	}
	
	return r;
}

static int ctapi_detect_card_presence(sc_reader_t *reader, sc_slot_info_t *slot)
{
	int r;
	
	r = refresh_slot_attributes(reader, slot);
	if (r)
		return r;
	return slot->flags;
}

static int ctapi_connect(sc_reader_t *reader, sc_slot_info_t *slot)
{
	struct ctapi_private_data *priv = GET_PRIV_DATA(reader);
	char rv;
	u8 cmd[9], rbuf[256], sad, dad;
	unsigned short lr;
	int r;

	cmd[0] = CTBCS_CLA;
	cmd[1] = CTBCS_INS_REQUEST;
	cmd[2] = CTBCS_P1_INTERFACE1+slot->id;
	cmd[3] = CTBCS_P2_REQUEST_GET_ATR;
	cmd[4] = 0x00;
	dad = 1;
	sad = 2;
	lr = 256;

	rv = priv->funcs.CT_data(priv->ctn, &dad, &sad, 5, cmd, &lr, rbuf);
	if (rv || rbuf[lr-2] != 0x90) {
		sc_error(reader->ctx, "Error activating card: %d\n", rv);
		return SC_ERROR_TRANSMIT_FAILED;
	}
	if (lr < 2)
		SC_FUNC_RETURN(reader->ctx, 0, SC_ERROR_INTERNAL);
	lr -= 2;
	if (lr > SC_MAX_ATR_SIZE)
		lr = SC_MAX_ATR_SIZE;
	memcpy(slot->atr, rbuf, lr);
	slot->atr_len = lr;
	r = _sc_parse_atr(reader->ctx, slot);

#if 0	
	if (slot->atr_info.Fi > 0) {
		/* Perform PPS negotiation */
		cmd[1] = CTBCS_INS_RESET;
		cmd[4] = 0x03;
		cmd[5] = 0xFF;
		cmd[6] = 0x10;
		cmd[7] = (slot->atr_info.FI << 4) | slot->atr_info.DI;
		cmd[8] = 0x00;
		dad = 1;
		sad = 2;
		lr = 256;

		rv = priv->funcs.CT_data(priv->ctn, &dad, &sad, 9, cmd, &lr, rbuf);
		if (rv) {
			sc_error(reader->ctx, "Error negotiating PPS: %d\n", rv);
			return SC_ERROR_TRANSMIT_FAILED;
		}
	}
#endif	
	return 0;
}

static int ctapi_disconnect(sc_reader_t *reader, sc_slot_info_t *slot)
{
	return 0;
}

static int ctapi_lock(sc_reader_t *reader, sc_slot_info_t *slot)
{
	return 0;
}

static int ctapi_unlock(sc_reader_t *reader, sc_slot_info_t *slot)
{
	return 0;
}

static int ctapi_release(sc_reader_t *reader)
{
	struct ctapi_private_data *priv = GET_PRIV_DATA(reader);

	priv->funcs.CT_close(priv->ctn);

	free(priv);
	return 0;
}

static struct sc_reader_operations ctapi_ops;

static struct sc_reader_driver ctapi_drv = {
	"CT-API module",
	"ctapi",
	&ctapi_ops,
	0, 0, NULL
};

static struct ctapi_module * add_module(struct ctapi_global_private_data *gpriv,
		      const char *name, void *dlhandle)
{
	int i;

	i = gpriv->module_count;
	gpriv->modules = (struct ctapi_module *) realloc(gpriv->modules, sizeof(struct ctapi_module) * (i+1));
	gpriv->modules[i].name = strdup(name);
	gpriv->modules[i].dlhandle = dlhandle;
	gpriv->modules[i].ctn_count = 0;
	gpriv->module_count++;
	
	return &gpriv->modules[i];
}

static int ctapi_load_module(sc_context_t *ctx,
			     struct ctapi_global_private_data *gpriv,
			     scconf_block *conf)
{
	const char *val;
	struct ctapi_functions funcs;
	struct ctapi_module *mod;
	const scconf_list *list;
	void *dlh;
	int r, i;
	
	list = scconf_find_list(conf, "ports");
	if (list == NULL) {
		sc_error(ctx, "No ports configured.\n");
		return -1;
	}

	val = conf->name->data;
	dlh = lt_dlopen(val);
	if (!dlh) {
		sc_error(ctx, "Unable to open shared library '%s': %s\n", val, lt_dlerror());
		return -1;
	}

	funcs.CT_init = (CT_INIT_TYPE *) lt_dlsym(dlh, "CT_init");
	if (!funcs.CT_init)
		goto symerr;
	funcs.CT_close = (CT_CLOSE_TYPE *) lt_dlsym(dlh, "CT_close");
	if (!funcs.CT_close)
		goto symerr;
	funcs.CT_data = (CT_DATA_TYPE *) lt_dlsym(dlh, "CT_data");
	if (!funcs.CT_data)
		goto symerr;

	mod = add_module(gpriv, val, dlh);
	for (; list != NULL; list = list->next) {
		int port;
		char namebuf[128];
		char rv;
		sc_reader_t *reader;
		struct ctapi_private_data *priv;
		
		if (sscanf(list->data, "%d", &port) != 1) {
			sc_error(ctx, "Port '%s' is not a number.\n", list->data);
			continue;
		}
		rv = funcs.CT_init((unsigned short)mod->ctn_count, (unsigned short)port);
		if (rv) {
			sc_error(ctx, "CT_init() failed with %d\n", rv);
			continue;
		}
		reader = (sc_reader_t *) calloc(1, sizeof(sc_reader_t));
		priv = (struct ctapi_private_data *) malloc(sizeof(struct ctapi_private_data));
		reader->drv_data = priv;
		reader->ops = &ctapi_ops;
		reader->driver = &ctapi_drv;
		snprintf(namebuf, sizeof(namebuf), "CT-API %s, port %d", mod->name, port);
		reader->name = strdup(namebuf);
		priv->funcs = funcs;
		priv->ctn = mod->ctn_count;
		r = _sc_add_reader(ctx, reader);
		if (r) {
			funcs.CT_close((unsigned short)mod->ctn_count);
			free(priv);
			free(reader->name);
			free(reader);
			break;
		}
		/* slot count and properties are set in detect_functional_units */
		detect_functional_units(reader);
		
		ctapi_reset(reader, NULL);
		for(i = 0; i < reader->slot_count; i++) {
			refresh_slot_attributes(reader, &(reader->slot[i]));
		}
		
		mod->ctn_count++;
	}
	return 0;
symerr:
	sc_error(ctx, "Unable to resolve CT-API symbols.\n");
	lt_dlclose(dlh);
	return -1;
}

static int ctapi_init(sc_context_t *ctx, void **reader_data)
{
	int i;
	struct ctapi_global_private_data *gpriv;
	scconf_block **blocks = NULL, *conf_block = NULL;

	gpriv = (struct ctapi_global_private_data *) calloc(1, sizeof(struct ctapi_global_private_data));
	if (gpriv == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	*reader_data = gpriv;
	
	for (i = 0; ctx->conf_blocks[i] != NULL; i++) {
		blocks = scconf_find_blocks(ctx->conf, ctx->conf_blocks[i],
					    "reader_driver", "ctapi");
		if (blocks && blocks[0])
			conf_block = blocks[0];
		free(blocks);
		if (conf_block != NULL)
			break;
	}
	if (conf_block == NULL)
		return 0;
	blocks = scconf_find_blocks(ctx->conf, conf_block, "module", NULL);
	for (i = 0; blocks != NULL && blocks[i] != NULL; i++)
		ctapi_load_module(ctx, gpriv, blocks[i]);
	free(blocks);
	
	return 0;
}

static int ctapi_finish(sc_context_t *ctx, void *prv_data)
{
	struct ctapi_global_private_data *priv = (struct ctapi_global_private_data *) prv_data;

	if (priv) {
		int i;
		
		for (i = 0; i < priv->module_count; i++) {
			struct ctapi_module *mod = &priv->modules[i];
			
			free(mod->name);
			lt_dlclose(mod->dlhandle);
		}
		if (priv->module_count)
			free(priv->modules);
		free(priv);
	}
	
	return 0;
}

struct sc_reader_driver * sc_get_ctapi_driver(void)
{
	ctapi_ops.init = ctapi_init;
	ctapi_ops.finish = ctapi_finish;
	ctapi_ops.detect_readers = NULL;
	ctapi_ops.transmit = ctapi_transmit;
	ctapi_ops.detect_card_presence = ctapi_detect_card_presence;
	ctapi_ops.lock = ctapi_lock;
	ctapi_ops.unlock = ctapi_unlock;
	ctapi_ops.release = ctapi_release;
	ctapi_ops.connect = ctapi_connect;
	ctapi_ops.disconnect = ctapi_disconnect;
	ctapi_ops.perform_verify = ctbcs_pin_cmd;
	
	return &ctapi_drv;
}
