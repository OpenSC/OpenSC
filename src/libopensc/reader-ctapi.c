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

#define GET_SLOT_PTR(s, i) (&(s)->slot[(i)])
#define GET_PRIV_DATA(r) ((struct ctapi_private_data *) (r)->drv_data)
#define GET_SLOT_DATA(r) ((struct ctapi_slot_data *) (r)->drv_data)

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
	char (* CT_init)(unsigned short ctn, unsigned short Pn);
	char (* CT_close)(unsigned short ctn);
	char (* CT_data)(unsigned short ctn, unsigned char *dad,
			 unsigned char *sad, unsigned short lc,
			 unsigned char *cmd, unsigned short *lr,
			 unsigned char *rsp);
};

/* Reader specific private data */
struct ctapi_private_data {
	struct ctapi_functions funcs;
	unsigned short ctn;
};

struct ctapi_slot_data {
	void *filler;
};

static int refresh_slot_attributes(struct sc_reader *reader,
				   struct sc_slot_info *slot)
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
	if (rv || rbuf[lr-2] != 0x90) {
		sc_error(reader->ctx, "Error getting status of terminal: %d\n", rv);
		return SC_ERROR_TRANSMIT_FAILED;
	}
	if (rbuf[0] == CTBCS_DATA_STATUS_CARD_CONNECT)
		slot->flags = SC_SLOT_CARD_PRESENT;

	return 0;
}

static int ctapi_transmit(struct sc_reader *reader, struct sc_slot_info *slot,
			 const u8 *sendbuf, size_t sendsize,
			 u8 *recvbuf, size_t *recvsize,
			 int control)
{
	struct ctapi_private_data *priv = GET_PRIV_DATA(reader);
	u8 dad, sad;
	unsigned short lr;
	char rv;
	
	dad = control? 1 : 0;
	sad = 2;
	lr = *recvsize;
	
	rv = priv->funcs.CT_data(priv->ctn, &dad, &sad, sendsize, (u8 *) sendbuf, &lr, recvbuf);
	if (rv != 0) {
		sc_error(reader->ctx, "Error transmitting APDU: %d\n", rv);
		return SC_ERROR_TRANSMIT_FAILED;
	}
	*recvsize = lr;
	
	return 0;
}

static int ctapi_detect_card_presence(struct sc_reader *reader, struct sc_slot_info *slot)
{
	int r;
	
	r = refresh_slot_attributes(reader, slot);
	if (r)
		return r;
	return slot->flags;
}

static int ctapi_connect(struct sc_reader *reader, struct sc_slot_info *slot)
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

static int ctapi_disconnect(struct sc_reader *reader, struct sc_slot_info *slot,
			   int action)
{
	return 0;
}
                                          
static int ctapi_lock(struct sc_reader *reader, struct sc_slot_info *slot)
{
	return 0;
}

static int ctapi_unlock(struct sc_reader *reader, struct sc_slot_info *slot)
{
	return 0;
}

static int ctapi_release(struct sc_reader *reader)
{
	struct ctapi_private_data *priv = GET_PRIV_DATA(reader);

	priv->funcs.CT_close(priv->ctn);

	free(priv);
	return 0;
}

static struct sc_reader_operations ctapi_ops;

static const struct sc_reader_driver ctapi_drv = {
	"CT-API module",
	"ctapi",
	&ctapi_ops
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

static int ctapi_load_module(struct sc_context *ctx,
			     struct ctapi_global_private_data *gpriv,
			     scconf_block *conf)
{
	const char *val;
	struct ctapi_functions funcs;
	struct ctapi_module *mod;
	const scconf_list *list;
	void *dlh;
	int r;
	
	list = scconf_find_list(conf, "ports");
	if (list == NULL) {
		sc_error(ctx, "No ports configured.\n");
		return -1;
	}

	val = conf->name->data;
	r = sc_module_open(ctx, &dlh, val);
	if (r != SC_SUCCESS) {
		sc_error(ctx, "Unable to open shared library '%s'\n", val);
		return -1;
	}
	r = sc_module_get_address(ctx, dlh, (void **) &funcs.CT_init, "CT_init");
	if (r != SC_SUCCESS)
		goto symerr;
	r = sc_module_get_address(ctx, dlh, (void **) &funcs.CT_close, "CT_close");
	if (r != SC_SUCCESS)
		goto symerr;
	r = sc_module_get_address(ctx, dlh, (void **) &funcs.CT_data, "CT_data");
	if (r != SC_SUCCESS)
		goto symerr;
	mod = add_module(gpriv, val, dlh);
	for (; list != NULL; list = list->next) {
		int port;
		char namebuf[128];
		char rv;
		struct sc_reader *reader;
		struct ctapi_private_data *priv;
		struct sc_slot_info *slot;
		
		if (sscanf(list->data, "%d", &port) != 1) {
			sc_error(ctx, "Port '%s' is not a number.\n", list->data);
			continue;
		}
		rv = funcs.CT_init(mod->ctn_count, port);
		if (rv) {
			sc_error(ctx, "CT_init() failed with %d\n", rv);
			continue;
		}
		reader = (struct sc_reader *) malloc(sizeof(struct sc_reader));
		priv = (struct ctapi_private_data *) malloc(sizeof(struct ctapi_private_data));
		memset(reader, 0, sizeof(*reader));
		reader->drv_data = priv;
		reader->ops = &ctapi_ops;
		reader->driver = &ctapi_drv;
		reader->slot_count = 1;
		snprintf(namebuf, sizeof(namebuf), "CT-API %s, port %d", mod->name, port);
		reader->name = strdup(namebuf);
		priv->funcs = funcs;
		priv->ctn = mod->ctn_count;
		r = _sc_add_reader(ctx, reader);
		if (r) {
			funcs.CT_close(mod->ctn_count);
			free(priv);
			free(reader->name);
			free(reader);
			break;
		}
		slot = &reader->slot[0];
		slot->id = 0;
		slot->capabilities = 0;
		slot->atr_len = 0;
		slot->drv_data = NULL;
		
		refresh_slot_attributes(reader, slot);
		
		mod->ctn_count++;
	}
	return 0;
symerr:
	sc_error(ctx, "Unable to resolve CT-API symbols.\n");
	sc_module_close(ctx, dlh);
	return -1;
}

static int ctapi_init(struct sc_context *ctx, void **reader_data)
{
	int i;
	struct ctapi_global_private_data *gpriv;
	scconf_block **blocks = NULL, *conf_block = NULL;

	gpriv = (struct ctapi_global_private_data *) malloc(sizeof(struct ctapi_global_private_data));
	if (gpriv == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	memset(gpriv, 0, sizeof(*gpriv));
	*reader_data = gpriv;
	
	for (i = 0; ctx->conf_blocks[i] != NULL; i++) {
		blocks = scconf_find_blocks(ctx->conf, ctx->conf_blocks[i],
					    "reader_driver", "ctapi");
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

static int ctapi_finish(struct sc_context *ctx, void *prv_data)
{
	struct ctapi_global_private_data *priv = (struct ctapi_global_private_data *) prv_data;

	if (priv) {
		int i;
		
		for (i = 0; i < priv->module_count; i++) {
			struct ctapi_module *mod = &priv->modules[i];
			
			free(mod->name);
			sc_module_close(ctx, mod->dlhandle);
		}
		if (priv->module_count)
			free(priv->modules);
		free(priv);
	}
	
	return 0;
}

const struct sc_reader_driver * sc_get_ctapi_driver(void)
{
	ctapi_ops.init = ctapi_init;
	ctapi_ops.finish = ctapi_finish;
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
