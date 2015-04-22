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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef ENABLE_CTAPI
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "common/libscdl.h"
#include "internal.h"
#include "ctbcs.h"

#define GET_PRIV_DATA(r) ((struct ctapi_private_data *) (r)->drv_data)

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
	int slot;
};

/* Reset reader */
static int ctapi_reset(sc_reader_t *reader)
{
	struct ctapi_private_data *priv = GET_PRIV_DATA(reader);
	char rv;
	u8 cmd[5], rbuf[256], sad, dad;
	unsigned short lr;

	cmd[0] = CTBCS_CLA;
	cmd[1] = CTBCS_INS_RESET;
	cmd[2] = priv->slot ? CTBCS_P1_INTERFACE1 + priv->slot : CTBCS_P1_CT_KERNEL;
	cmd[3] = 0x00; /* No response. We might also use 0x01 (return ATR) or 0x02 (return historical bytes) here */
	cmd[4] = 0x00;
	dad = 1;
	sad = 2;
	lr = 256;

	rv = priv->funcs.CT_data(priv->ctn, &dad, &sad, 5, cmd, &lr, rbuf);
	if (rv || (lr < 2)) {
		sc_debug(reader->ctx, SC_LOG_DEBUG_NORMAL, "Error getting status of terminal: %d, using defaults\n", rv);
		return SC_ERROR_TRANSMIT_FAILED;
	}
	if (rbuf[lr-2] != 0x90) {
		sc_debug(reader->ctx, SC_LOG_DEBUG_NORMAL, "SW1/SW2: 0x%x/0x%x\n", rbuf[lr-2], rbuf[lr-1]);
		return SC_ERROR_TRANSMIT_FAILED;
	}
	return 0;
}


static int refresh_attributes(sc_reader_t *reader)
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

	reader->flags = 0;

	rv = priv->funcs.CT_data(priv->ctn, &dad, &sad, 5, cmd, &lr, rbuf);
	if (rv || (lr < 3) || (rbuf[lr-2] != 0x90)) {
		sc_debug(reader->ctx, SC_LOG_DEBUG_NORMAL, "Error getting status of terminal: %d/%d/0x%x\n", rv, lr, rbuf[lr-2]);
		return SC_ERROR_TRANSMIT_FAILED;
	}
	if (lr < 4) {
		if (rbuf[0] & CTBCS_DATA_STATUS_CARD)
			reader->flags = SC_READER_CARD_PRESENT;
	} else {
		if (rbuf[0] != CTBCS_P2_STATUS_ICC) {
			/* Should we be more tolerant here? I do not think so... */
			sc_debug(reader->ctx, SC_LOG_DEBUG_NORMAL, "Invalid data object returnd on CTBCS_P2_STATUS_ICC: 0x%x\n", rbuf[0]);
		return SC_ERROR_TRANSMIT_FAILED;
		}
		/* Fixme - should not be reached */
		sc_debug(reader->ctx, SC_LOG_DEBUG_NORMAL, "Returned status for  %d slots\n", rbuf[1]);
		reader->flags = SC_READER_CARD_PRESENT;
	}

	return 0;
}

static int ctapi_internal_transmit(sc_reader_t *reader,
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
	else
		dad = 0;

	sad = 2;
	lr = *recvsize;
	
	rv = priv->funcs.CT_data(priv->ctn, &dad, &sad, (unsigned short)sendsize, (u8 *) sendbuf, &lr, recvbuf);
	if (rv != 0) {
		sc_debug(reader->ctx, SC_LOG_DEBUG_NORMAL, "Error transmitting APDU: %d\n", rv);
		return SC_ERROR_TRANSMIT_FAILED;
	}
	*recvsize = lr;
	
	return 0;
}

static int ctapi_transmit(sc_reader_t *reader, sc_apdu_t *apdu)
{
	size_t       ssize, rsize, rbuflen = 0;
	u8           *sbuf = NULL, *rbuf = NULL;
	int          r;

	rsize = rbuflen = apdu->resplen + 2;
	rbuf     = malloc(rbuflen);
	if (rbuf == NULL) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	/* encode and log the APDU */
	r = sc_apdu_get_octets(reader->ctx, apdu, &sbuf, &ssize, SC_PROTO_RAW);
	if (r != SC_SUCCESS)
		goto out;
	sc_apdu_log(reader->ctx, SC_LOG_DEBUG_NORMAL, sbuf, ssize, 1);
	r = ctapi_internal_transmit(reader, sbuf, ssize,
					rbuf, &rsize, apdu->control);
	if (r < 0) {
		/* unable to transmit ... most likely a reader problem */
		sc_debug(reader->ctx, SC_LOG_DEBUG_NORMAL, "unable to transmit");
		goto out;
	}
	sc_apdu_log(reader->ctx, SC_LOG_DEBUG_NORMAL, rbuf, rsize, 0);
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

static int ctapi_detect_card_presence(sc_reader_t *reader)
{
	int r;
	
	r = refresh_attributes(reader);
	if (r)
		return r;
	return reader->flags;
}

static int ctapi_connect(sc_reader_t *reader)
{
	struct ctapi_private_data *priv = GET_PRIV_DATA(reader);
	char rv;
	u8 cmd[9], rbuf[256], sad, dad;
	unsigned short lr;
	int r;

	cmd[0] = CTBCS_CLA;
	cmd[1] = CTBCS_INS_REQUEST;
	cmd[2] = CTBCS_P1_INTERFACE1;
	cmd[3] = CTBCS_P2_REQUEST_GET_ATR;
	cmd[4] = 0x00;
	dad = 1;
	sad = 2;
	lr = 256;

	rv = priv->funcs.CT_data(priv->ctn, &dad, &sad, 5, cmd, &lr, rbuf);
	if (rv || rbuf[lr-2] != 0x90) {
		sc_debug(reader->ctx, SC_LOG_DEBUG_NORMAL, "Error activating card: %d\n", rv);
		return SC_ERROR_TRANSMIT_FAILED;
	}
	if (lr < 2)
		SC_FUNC_RETURN(reader->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INTERNAL);
	lr -= 2;
	if (lr > SC_MAX_ATR_SIZE)
		return SC_ERROR_INTERNAL;
	reader->atr.len = lr;
	memcpy(reader->atr.value, rbuf, lr);
	r = _sc_parse_atr(reader);

	return 0;
}

static int ctapi_disconnect(sc_reader_t *reader)
{
	return 0;
}

static int ctapi_lock(sc_reader_t *reader)
{
	return 0;
}

static int ctapi_unlock(sc_reader_t *reader)
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
	int r, i, NumUnits;
	u8 cmd[5], rbuf[256], sad, dad;
	unsigned short lr;

	
	
	list = scconf_find_list(conf, "ports");
	if (list == NULL) {
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "No ports configured.\n");
		return -1;
	}

	val = conf->name->data;
	dlh = sc_dlopen(val);
	if (!dlh) {
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "Unable to open shared library '%s': %s\n", val, sc_dlerror());
		return -1;
	}

	funcs.CT_init = (CT_INIT_TYPE *) sc_dlsym(dlh, "CT_init");
	if (!funcs.CT_init)
		goto symerr;
	funcs.CT_close = (CT_CLOSE_TYPE *) sc_dlsym(dlh, "CT_close");
	if (!funcs.CT_close)
		goto symerr;
	funcs.CT_data = (CT_DATA_TYPE *) sc_dlsym(dlh, "CT_data");
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
			sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "Port '%s' is not a number.\n", list->data);
			continue;
		}
		rv = funcs.CT_init((unsigned short)mod->ctn_count, (unsigned short)port);
		if (rv) {
			sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "CT_init() failed with %d\n", rv);
			continue;
		}
		
		reader = calloc(1, sizeof(sc_reader_t));
		priv = calloc(1, sizeof(struct ctapi_private_data));
		if (!priv || !reader) {
			free(reader);
			free(priv);
			return SC_ERROR_OUT_OF_MEMORY;
		}
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
		
		/* Detect functional units of the reader according to CT-BCS spec version 1.0 
		(14.04.2004, http://www.teletrust.de/down/mct1-0_t4.zip) */	
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
			sc_debug(reader->ctx, SC_LOG_DEBUG_NORMAL, "Error getting status of terminal: %d, using defaults\n", rv);
		}
		if (rbuf[0] != CTBCS_P2_STATUS_TFU) {
			/* Number of slots might also detected by using CTBCS_P2_STATUS_ICC.
			   If you think that's important please do it... ;) */
			sc_debug(reader->ctx, SC_LOG_DEBUG_NORMAL, "Invalid data object returnd on CTBCS_P2_STATUS_TFU: 0x%x\n", rbuf[0]);
		}
		NumUnits = rbuf[1];
		if (NumUnits + 4 > lr) {
			sc_debug(reader->ctx, SC_LOG_DEBUG_NORMAL, "Invalid data returnd: %d functional units, size %d\n", NumUnits, rv);
		}
		priv->ctapi_functional_units = 0;
		for(i = 0; i < NumUnits; i++) {
			switch(rbuf[i+2]) {
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
					sc_debug(reader->ctx, SC_LOG_DEBUG_NORMAL, "Found slot id 0x%x\n", rbuf[i+2]);
					break;

				case CTBCS_P1_DISPLAY:
					priv->ctapi_functional_units |= CTAPI_FU_DISPLAY;
					sc_debug(reader->ctx, SC_LOG_DEBUG_NORMAL, "Display detected\n");
					break;

				case CTBCS_P1_KEYPAD:
					priv->ctapi_functional_units |= CTAPI_FU_KEYBOARD;
					sc_debug(reader->ctx, SC_LOG_DEBUG_NORMAL, "Keypad detected\n");
					break;

				case CTBCS_P1_PRINTER:
					priv->ctapi_functional_units |= CTAPI_FU_PRINTER;
					sc_debug(reader->ctx, SC_LOG_DEBUG_NORMAL, "Printer detected\n");
					break;

				case CTBCS_P1_FINGERPRINT:
				case CTBCS_P1_VOICEPRINT:
				case CTBCS_P1_DSV:
				case CTBCS_P1_FACE_RECOGNITION:
				case CTBCS_P1_IRISSCAN:
					priv->ctapi_functional_units |= CTAPI_FU_BIOMETRIC;
					sc_debug(reader->ctx, SC_LOG_DEBUG_NORMAL, "Biometric sensor detected\n");
					break;

				default:
					sc_debug(reader->ctx, SC_LOG_DEBUG_NORMAL, "Unknown functional unit 0x%x\n", rbuf[i+2]);
			}
		}
		/* CT-BCS does not define Keyboard/Display for each slot, so I assume
		those additional units can be used for each slot */
		if (priv->ctapi_functional_units) {
			if (priv->ctapi_functional_units & CTAPI_FU_KEYBOARD)
				reader->capabilities |= SC_READER_CAP_PIN_PAD;
			if (priv->ctapi_functional_units & CTAPI_FU_DISPLAY)
				reader->capabilities |= SC_READER_CAP_DISPLAY;
		}
		
		ctapi_reset(reader);
		refresh_attributes(reader);
		mod->ctn_count++;
	}
	return 0;
symerr:
	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "Unable to resolve CT-API symbols.\n");
	sc_dlclose(dlh);
	return -1;
}

static int ctapi_init(sc_context_t *ctx)
{
	int i;
	struct ctapi_global_private_data *gpriv;
	scconf_block **blocks = NULL, *conf_block = NULL;

	gpriv = calloc(1, sizeof(struct ctapi_global_private_data));
	if (gpriv == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	ctx->reader_drv_data = gpriv;
	
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

static int ctapi_finish(sc_context_t *ctx)
{
	struct ctapi_global_private_data *priv = (struct ctapi_global_private_data *) ctx->reader_drv_data;

	if (priv) {
		int i;
		
		for (i = 0; i < priv->module_count; i++) {
			struct ctapi_module *mod = &priv->modules[i];
			
			free(mod->name);
			sc_dlclose(mod->dlhandle);
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
	ctapi_ops.perform_pace = NULL;
	ctapi_ops.use_reader = NULL;
	
	return &ctapi_drv;
}
#endif
