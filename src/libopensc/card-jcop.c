/*
 * card-jcop.c
 *
 * Copyright (C) 2003 Chaskiel Grundman <cg2v@andrew.cmu.edu>
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

#include <string.h>
#include <stdlib.h>

#include "internal.h"
#include "cardctl.h"

static struct sc_atr_table jcop_atrs[] = {
	{ "3B:E6:00:FF:81:31:FE:45:4A:43:4F:50:33:31:06", NULL, NULL, SC_CARD_TYPE_JCOP_GENERIC, 0, NULL },
	{ NULL, NULL, NULL, 0, 0, NULL }
};

static struct sc_card_operations jcop_ops;
static struct sc_card_driver jcop_drv = {
	"JCOP cards with BlueZ PKCS#15 applet",
	"jcop",
	&jcop_ops,
	NULL, 0, NULL
};

#define SELECT_MF 0
#define SELECT_EFDIR 1
#define SELECT_APPDF 2
#define SELECT_EF 3
#define SELECT_UNKNOWN 4
#define SELECTING_TARGET 0xf
#define SELECTING_ABS 0x80
#define SELECTING_VIA_APPDF 0x100

struct jcop_private_data 
{
     sc_file_t *virtmf;
     sc_file_t *virtdir;
     sc_path_t aid;
     int selected;
     int invalid_senv;
     int nfiles;
     u8 *filelist;
};
#define DRVDATA(card)   ((struct jcop_private_data *) ((card)->drv_data))

static int jcop_finish(sc_card_t *card)
{
     struct jcop_private_data *drvdata=DRVDATA(card);
     if (drvdata) {
	  sc_file_free(drvdata->virtmf);
	  sc_file_free(drvdata->virtdir);
	  free(drvdata);
	  card->drv_data=NULL;
     }
     
     return 0;
}

static int jcop_match_card(sc_card_t *card)
{
	int i;

	i = _sc_match_atr(card, jcop_atrs, &card->type);
	if (i < 0)
		return 0;
	return 1;
}

static unsigned char ef_dir_contents[128] = {
     0x61, 0x21, 
     0x4f, 0xc, 0xA0, 0x0, 0x0, 0x0, 0x63, 'P', 'K', 'C', 'S', '-', '1', '5',
     0x50, 0xb, 'O', 'p', 'e', 'n', 'S', 'C', ' ', 'C', 'a', 'r', 'd',
     0x51, 0x04, 0x3f, 0x00, 0x50, 0x15
};


static int jcop_init(sc_card_t *card)
{
     struct jcop_private_data *drvdata;
     sc_file_t *f;
     int flags;
     
     drvdata=malloc(sizeof(struct jcop_private_data));
     if (!drvdata)
	  return SC_ERROR_OUT_OF_MEMORY;
     memset(drvdata, 0, sizeof(struct jcop_private_data));
     
     sc_format_path("A000:0000:6350:4B43:532D:3135", &drvdata->aid);
     drvdata->aid.type = SC_PATH_TYPE_DF_NAME;
     drvdata->selected=SELECT_MF;
     drvdata->invalid_senv=1;
     drvdata->nfiles=-1;
     drvdata->filelist=NULL;
     f=sc_file_new();
     if (!f){
	  free(drvdata);
	  return SC_ERROR_OUT_OF_MEMORY;
     }
     
     sc_format_path("3f00", &f->path);
     f->type=SC_FILE_TYPE_DF;
     f->shareable=0;
     f->ef_structure=SC_FILE_EF_UNKNOWN;
     f->size=0;
     f->id=0x3f00;
     f->status=SC_FILE_STATUS_ACTIVATED;
     sc_file_add_acl_entry(f, SC_AC_OP_SELECT, SC_AC_NONE, 0);
     sc_file_add_acl_entry(f, SC_AC_OP_LIST_FILES, SC_AC_NONE, 0);
     sc_file_add_acl_entry(f, SC_AC_OP_LOCK, SC_AC_NEVER, 0);
     sc_file_add_acl_entry(f, SC_AC_OP_DELETE, SC_AC_NEVER, 0);
     sc_file_add_acl_entry(f, SC_AC_OP_CREATE, SC_AC_NEVER, 0);

     drvdata->virtmf=f;

     f=sc_file_new();
     if (!f){
	  sc_file_free(drvdata->virtmf);
	  free(drvdata);
	  return SC_ERROR_OUT_OF_MEMORY;
     }
     
     sc_format_path("3f002f00", &f->path);
     f->type=SC_FILE_TYPE_WORKING_EF;
     f->shareable=0;
     f->ef_structure=SC_FILE_EF_TRANSPARENT;
     f->size=128;
     f->id=0x2f00;
     f->status=SC_FILE_STATUS_ACTIVATED;
     sc_file_add_acl_entry(f, SC_AC_OP_READ, SC_AC_NONE, 0);
     sc_file_add_acl_entry(f, SC_AC_OP_LOCK, SC_AC_NEVER, 0);
     sc_file_add_acl_entry(f, SC_AC_OP_ERASE, SC_AC_NEVER, 0);
     sc_file_add_acl_entry(f, SC_AC_OP_UPDATE, SC_AC_NEVER, 0);
     sc_file_add_acl_entry(f, SC_AC_OP_WRITE, SC_AC_NEVER, 0);
     sc_file_add_acl_entry(f, SC_AC_OP_CRYPTO, SC_AC_NEVER, 0);
     
     drvdata->virtdir=f;
     
     
     card->drv_data = drvdata;
     card->cla = 0x00;

     /* card supports host-side padding, but not raw rsa */
     flags = SC_ALGORITHM_RSA_PAD_PKCS1;
     flags |= SC_ALGORITHM_RSA_HASH_NONE;
     flags |= SC_ALGORITHM_RSA_HASH_SHA1;
     flags |= SC_ALGORITHM_RSA_HASH_MD5;
     /* only supports keygen with 3 and F-4  exponents */
     flags |= SC_ALGORITHM_ONBOARD_KEY_GEN;
     _sc_card_add_rsa_alg(card, 512, flags, 0);
     _sc_card_add_rsa_alg(card, 768, flags, 0);
     _sc_card_add_rsa_alg(card, 1024, flags, 0);
     _sc_card_add_rsa_alg(card, 2048, flags, 0);
     /* State that we have an RNG */
     card->caps |= SC_CARD_CAP_RNG;

     return 0;
}

static int jcop_get_default_key(sc_card_t *card,
                                struct sc_cardctl_default_key *data)
{
	const char *key;

	if (data->method != SC_AC_PRO || data->key_ref > 2)
		return SC_ERROR_NO_DEFAULT_KEY;

	key = "40:41:42:43:44:45:46:47:48:49:4A:4B:4C:4D:4E:4F";
	return sc_hex_to_bin(key, data->key_data, &data->len);
}

/* since the card is actually a javacard, we're expected to use ISO
   7816-4 direct application selection instead of reading the DIR
   ourselves and selecting the AppDF by path. Since opensc doesn' do
   that, I fake an MF containing the AppDF and a fixed DIR pointing at
   the fake AppDF. This has the added advantage of allowing
   opensc-explorer to be used with this driver */
static int jcop_select_file(sc_card_t *card, const sc_path_t *path,
			    sc_file_t **file)
{
     struct jcop_private_data *drvdata=DRVDATA(card);
     int r,selecting;
     struct sc_card_driver *iso_drv = sc_get_iso7816_driver();
     const struct sc_card_operations *iso_ops = iso_drv->ops;
     sc_path_t       shortpath;
     sc_file_t  *tfile, **fileptr;
     
     if (!drvdata)
	  return SC_ERROR_FILE_NOT_FOUND;

     /* Something about the card does not like Case 4 APDU's to be sent as
	Case 3. you must send a length and accept a response. */
	
     if (file) {
	  fileptr=file;
     } else {
	  fileptr=&tfile;
     }

     /* Selecting the MF. return a copy of the constructed MF */
     if (path->len == 2 && memcmp(path->value, "\x3F\x00", 2) == 0) {
	  drvdata->selected=SELECT_MF;
	  if (file) {
		sc_file_dup(file, drvdata->virtmf);
		if (*file == NULL)
			return SC_ERROR_OUT_OF_MEMORY;
	  }
	  return 0;
     }
     /* Selecting the EF(DIR). return a copy of the constructed EF(DIR) */
     if ((path->len == 4 && 
	  memcmp(path->value, "\x3F\x00\x2F\x00", 4) == 0) ||
	 (drvdata->selected == SELECT_MF && path->len == 2 &&
	  memcmp(path->value, "\x2F\x00", 2) == 0)) {
	  drvdata->selected=SELECT_EFDIR;
	  if (file) {
		sc_file_dup(file, drvdata->virtdir);
		if (*file == NULL)
			return SC_ERROR_OUT_OF_MEMORY;
	  }
	  return 0;
     }	  
     /* selecting the PKCS15 AppDF or a file in it. Select the applet, then 
	pass through any remaining path components to the applet's select 
	command
     */
     selecting=SELECT_UNKNOWN;
     
     if (path->len >= 4 && 
	 memcmp(path->value, "\x3F\x00\x50\x15", 4) == 0) {
	  if (path->len == 4)
	       selecting = SELECTING_ABS | SELECT_APPDF;
	  else
	       selecting = SELECTING_ABS | SELECT_EF;
     }
     
     if	 (drvdata->selected==SELECT_MF && 
	  memcmp(path->value, "\x50\x15", 2) == 0) {
	  if (path->len == 2)
	       selecting = SELECTING_VIA_APPDF | SELECT_APPDF;
	  else
	       selecting = SELECTING_VIA_APPDF | SELECT_EF;
     }
    
     if (selecting & (SELECTING_ABS|SELECTING_VIA_APPDF))
     {
	  if (file == NULL && 
	      (selecting & SELECTING_TARGET) == SELECT_APPDF  && 
	      drvdata->selected == SELECT_APPDF) {
	       return 0;
	  }
	  if ((r = iso_ops->select_file(card, &drvdata->aid, fileptr)) < 0)
	       return r;
	  if (fileptr && (selecting & SELECTING_TARGET) == SELECT_APPDF) {
	       (*fileptr)->type = SC_FILE_TYPE_DF;
	       drvdata->selected=SELECT_APPDF;
	       goto select_ok;
	  }
	  sc_file_free(*fileptr);
	  *fileptr=NULL;
	  memset(&shortpath, 0, sizeof(sc_path_t));	  
	  if (selecting & SELECTING_ABS) {
	       memcpy(&shortpath.value, &path->value[4], path->len-4);
	       shortpath.len=path->len-4;
	  } else {
	       memcpy(&shortpath.value, &path->value[2], path->len-2);
	       shortpath.len=path->len-2;
	  }
	  shortpath.type = shortpath.len == 2 ? SC_PATH_TYPE_FILE_ID :
	       path->type;
	  shortpath.index=path->index;
	  shortpath.count=path->count;
	  path=&shortpath;
     } else {
	  /* There seems to be better debugging output if I call sc_check_sw
	   * with appropriate input than if I just return the appropriate 
	   * SC_ERROR_*, so that's what I do for all errors returned by code 
	   * related to the MF/DIR emulation 
	   */
	  if (drvdata->selected == SELECT_MF || 
              drvdata->selected == SELECT_EFDIR)
	       return sc_check_sw(card, 0x6A, 0x82);
     }
	
     r = iso_ops->select_file(card, path, fileptr);
     if (r)
	  return r;
     drvdata->selected=SELECT_EF;
 select_ok:
     if (!file) {
	  sc_file_free(*fileptr);
     }
     return 0;
}

static int jcop_read_binary(sc_card_t *card, unsigned int idx,
			    u8 * buf, size_t count, unsigned long flags) {
     struct jcop_private_data *drvdata=DRVDATA(card);
     struct sc_card_driver *iso_drv = sc_get_iso7816_driver();
     const struct sc_card_operations *iso_ops = iso_drv->ops;
     int r;
     
     if (drvdata->selected == SELECT_MF) {
          return sc_check_sw(card, 0x69, 0x86);
     }
     if (drvdata->selected == SELECT_EFDIR) {
	  if (idx > 127) {
	       return sc_check_sw(card, 0x6A, 0x86);
	  }
	  if (idx + count > 128) {
	       count=128-idx;
	  }
	  r = iso_ops->select_file(card, &drvdata->aid, NULL);
	  if (r < 0) { /* no pkcs15 app, so return empty DIR. */
	       memset(buf, 0, count);
	  } else {
	       memcpy(buf, (u8 *)(ef_dir_contents + idx), count);
	  }
	  return count;
     }
     return iso_ops->read_binary(card, idx, buf, count, flags);
}

static int jcop_list_files(sc_card_t *card, u8 *buf, size_t buflen) {
     struct jcop_private_data *drvdata=DRVDATA(card);
     struct sc_card_driver *iso_drv = sc_get_iso7816_driver();
     const struct sc_card_operations *iso_ops = iso_drv->ops;
     int r;

     if (drvdata->selected == SELECT_MF) {
	  if (buflen < 2)
	       return 0;
	  memcpy(buf, "\x2f\x00", 2);
	  if (buflen < 4)
	       return 2;
	  /* AppDF only exists if applet is selectable */
	  r = iso_ops->select_file(card, &drvdata->aid, NULL);
	  if (r < 0) { 
	       return 2;
	  } else {
	       memcpy(buf+2, "\x50\x15", 2);
	       return 4;
	  }
     }
     
     if (drvdata->nfiles == -1)
	  return SC_ERROR_NOT_ALLOWED;
     if (drvdata->nfiles == 0)
	  return 0;
     if (buflen > 2 * (size_t)drvdata->nfiles)
	  buflen=2*drvdata->nfiles;
     memcpy(buf, drvdata->filelist, buflen);
     return buflen;
}

static int sa_to_acl(sc_file_t *file, unsigned int operation, 
		     int nibble) {
     switch (nibble & 0x7) {
     case 0:
	  sc_file_add_acl_entry(file, operation, SC_AC_NONE, SC_AC_KEY_REF_NONE);
	  break;
     case 1:
	  sc_file_add_acl_entry(file, operation, SC_AC_NEVER, SC_AC_KEY_REF_NONE);
	  break;
     case 2:
	  sc_file_add_acl_entry(file, operation, SC_AC_CHV, 1);
	  break;
     case 3:
	  sc_file_add_acl_entry(file, operation, SC_AC_CHV, 2);
	  break;
     case 4:
	  sc_file_add_acl_entry(file, operation, SC_AC_CHV, 3);
	  break;
     case 5:
	  sc_file_add_acl_entry(file, operation, SC_AC_AUT, SC_AC_KEY_REF_NONE);
	  break;
     case 6:
	  sc_file_add_acl_entry(file, operation, SC_AC_PRO, SC_AC_KEY_REF_NONE);
	  break;
     default:
	  sc_file_add_acl_entry(file, operation, SC_AC_UNKNOWN, SC_AC_KEY_REF_NONE);
     }
     return 0;
}


static int jcop_process_fci(sc_card_t *card, sc_file_t *file,
			    const u8 *buf, size_t buflen) {
     struct jcop_private_data *drvdata=DRVDATA(card);
     struct sc_card_driver *iso_drv = sc_get_iso7816_driver();
     const struct sc_card_operations *iso_ops = iso_drv->ops;
     u8 *sa;
     int r;

     /* the FCI for EF's includes a bogus length for the overall structure!  */
     if (buflen == 19)
       buflen=24;
     r=iso_ops->process_fci(card, file, buf, buflen);
     
     if (r < 0)
	  return r;
     if (file->type != SC_FILE_TYPE_DF) {
	  if (drvdata->nfiles) {
	       drvdata->nfiles=-1;
	       free(drvdata->filelist);
	       drvdata->filelist=NULL;
	  }
	  if(file->sec_attr_len >=3) {
	       /* The security attribute bytes are divided into nibbles and are
		  as follows:
		  READ | MODIFY || SIGN | ENCIPHER || DECIPHER | DELETE 
	       */
	       sa=file->sec_attr;
	       sa_to_acl(file, SC_AC_OP_READ, sa[0] >> 4);
	       sa_to_acl(file, SC_AC_OP_UPDATE, sa[0] & 0xf);
	       /* Files may be locked by anyone who can MODIFY. */
	       /* opensc seems to think LOCK ACs are only on DFs */
	       /* sa_to_acl(file, SC_AC_OP_LOCK, sa[0] & 0xf); */
	       /* there are seperate SIGN, ENCIPHER, and DECIPHER ACs.
		  I use SIGN for SC_AC_OP_CRYPTO unless it is NEVER, in 
		  which case I use DECIPHER */
	       if ((sa[1] & 0xf0) == 0x10)
		    sa_to_acl(file, SC_AC_OP_CRYPTO, sa[1] >> 4);
	       else
		    sa_to_acl(file, SC_AC_OP_CRYPTO, sa[2] >> 4);
	       sa_to_acl(file, SC_AC_OP_ERASE, sa[2] & 0xf);
	  }
     } else {
	  /* No AC information is reported for the AppDF */
	  sc_file_add_acl_entry(file, SC_AC_OP_SELECT, SC_AC_NONE, 0);
	  sc_file_add_acl_entry(file, SC_AC_OP_CREATE, SC_AC_CHV, 3);
	  sc_file_add_acl_entry(file, SC_AC_OP_DELETE, SC_AC_NONE, 0);
	  sc_file_add_acl_entry(file, SC_AC_OP_LIST_FILES, SC_AC_NONE, 0);
	  if (drvdata->nfiles) {
	       drvdata->nfiles=0;
	       free(drvdata->filelist);
	       drvdata->filelist=NULL;
	  }    
	  /* the format of the poprietary attributes is:
	     4 bytes     unique id
	     1 byte      # files in DF
	     2 bytes     1st File ID
	     2 bytes     2nd File ID
	     ...
	  */
	  if (file->prop_attr_len > 4) {
	       int nfiles;
	       u8 *filelist;
	       nfiles=file->prop_attr[4];
	       if (nfiles) {
		    filelist=malloc(2*nfiles);
		    if (!filelist)
			 return SC_ERROR_OUT_OF_MEMORY;
		    memcpy(filelist, &file->prop_attr[5], 2*nfiles);
		    drvdata->nfiles=nfiles;
		    drvdata->filelist=filelist;
	       }
	  }
     }
     
     return r;
}
static int acl_to_ac_nibble(const sc_acl_entry_t *e)
{
        if (e == NULL)
                return -1;
        if (e->next != NULL)    /* FIXME */
                return -1;
        switch (e->method) {
        case SC_AC_NONE:
                return 0x00;
        case SC_AC_NEVER:
                return 0x01;
        case SC_AC_CHV:
                switch (e->key_ref) {
                case 1:
                        return 0x02;
                case 2:
                        return 0x03;
                case 3:
                        return 0x04;
                }
                return -1;
        case SC_AC_AUT:
                return 0x05;
        case SC_AC_PRO:
                return 0x06;
        }
        return -1;
}


static int jcop_create_file(sc_card_t *card, sc_file_t *file) {
     struct jcop_private_data *drvdata=DRVDATA(card);
     unsigned char sec_attr_data[3];
     int ops[6];
     int i, r;
     struct sc_card_driver *iso_drv = sc_get_iso7816_driver();
     const struct sc_card_operations *iso_ops = iso_drv->ops;
     
     if (drvdata->selected == SELECT_MF || drvdata->selected == SELECT_EFDIR )
	  return sc_check_sw(card, 0x69, 0x82);
     
     /* Can't create DFs */
     if (file->type != SC_FILE_TYPE_WORKING_EF)
	  return sc_check_sw(card, 0x6A, 0x80);
     
     ops[0] = SC_AC_OP_READ;      /* read */
     ops[1] = SC_AC_OP_UPDATE;    /* modify */
     ops[2] = SC_AC_OP_CRYPTO;    /* sign */
     ops[3] = -1;                 /* encipher */
     ops[4] = SC_AC_OP_CRYPTO;    /* decipher */
     ops[5] = SC_AC_OP_ERASE;     /* delete */
     memset(sec_attr_data, 0, 3);
     for (i = 0; i < 6; i++) {
	  const sc_acl_entry_t *entry;
	  if (ops[i] == -1) {
	       sec_attr_data[i/2] |= 1 << ((i % 2) ? 0 : 4);
	       continue;
	  }
	  
	  entry = sc_file_get_acl_entry(file, ops[i]);
	  r = acl_to_ac_nibble(entry);
	  sec_attr_data[i/2] |= r << ((i % 2) ? 0 : 4);
     }

     sc_file_set_sec_attr(file, sec_attr_data, 3);
     
     r=iso_ops->create_file(card, file);
     if (r > 0)
          drvdata->selected=SELECT_EF;
     return r;
}


/* We need to trap these functions so that proper errors can be returned
   when one of the virtual files is selected */
static int jcop_write_binary(sc_card_t *card,
			unsigned int idx, const u8 *buf,
			size_t count, unsigned long flags) {
     struct jcop_private_data *drvdata=DRVDATA(card);
     struct sc_card_driver *iso_drv = sc_get_iso7816_driver();
     const struct sc_card_operations *iso_ops = iso_drv->ops;

     if (drvdata->selected == SELECT_MF)
	       return sc_check_sw(card, 0x6A, 0x86);
     if (drvdata->selected == SELECT_EFDIR)
	       return sc_check_sw(card, 0x69, 0x82);

     return iso_ops->write_binary(card, idx, buf, count, flags);
}


static int jcop_update_binary(sc_card_t *card,
			 unsigned int idx, const u8 *buf,
			 size_t count, unsigned long flags) {
     
     struct jcop_private_data *drvdata=DRVDATA(card);
     struct sc_card_driver *iso_drv = sc_get_iso7816_driver();
     const struct sc_card_operations *iso_ops = iso_drv->ops;
     if (drvdata->selected == SELECT_MF)
	       return sc_check_sw(card, 0x69, 0x86);
     if (drvdata->selected == SELECT_EFDIR)
	       return sc_check_sw(card, 0x69, 0x82);

     return iso_ops->update_binary(card, idx, buf, count, flags);
}

static int jcop_delete_file(sc_card_t *card, const sc_path_t *path) {
     struct jcop_private_data *drvdata=DRVDATA(card);
     struct sc_card_driver *iso_drv = sc_get_iso7816_driver();
     const struct sc_card_operations *iso_ops = iso_drv->ops;

     if (drvdata->selected == SELECT_MF || drvdata->selected == SELECT_EFDIR )
          return sc_check_sw(card, 0x69, 0x82);

     return iso_ops->delete_file(card, path);
}


/* BlueZ doesn't support stored security environments. you have
   to construct one with SET every time */
static int jcop_set_security_env(sc_card_t *card,
                                    const sc_security_env_t *env,
                                    int se_num)
{
        sc_apdu_t apdu;
        u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
        u8 *p;
        int r;
	struct jcop_private_data *drvdata=DRVDATA(card);

        assert(card != NULL && env != NULL);
	if (se_num) 
	     SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INVALID_ARGUMENTS);
	if (drvdata->selected == SELECT_MF || 
	    drvdata->selected == SELECT_EFDIR) {
	     drvdata->invalid_senv=1;
	     return 0;
	}
	
        if (env->flags & SC_SEC_ENV_ALG_PRESENT) {
                sc_security_env_t tmp;

                tmp = *env;
                tmp.flags &= ~SC_SEC_ENV_ALG_PRESENT;
                tmp.flags |= SC_SEC_ENV_ALG_REF_PRESENT;
                if (tmp.algorithm != SC_ALGORITHM_RSA) {
                        sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Only RSA algorithm supported.\n");
                        return SC_ERROR_NOT_SUPPORTED;
                }
                if (!(env->algorithm_flags & SC_ALGORITHM_RSA_PAD_PKCS1)){
                        sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Card requires RSA padding\n");
                        return SC_ERROR_NOT_SUPPORTED;
                }
                tmp.algorithm_ref = 0x02;
                /* potential FIXME: return an error, if an unsupported
                 * pad or hash was requested, although this shouldn't happen.
                 */
                if (tmp.algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA1)
                        tmp.algorithm_ref |= 0x10;
                if (tmp.algorithm_flags & SC_ALGORITHM_RSA_HASH_MD5)
                        tmp.algorithm_ref |= 0x20;

		memcpy((sc_security_env_t *) env, &tmp, sizeof(struct sc_security_env));
	}
	
        sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0xC1, 0);
        switch (env->operation) {
        case SC_SEC_OPERATION_DECIPHER:
	     apdu.p2 = 0xB8;
	     break;
        case SC_SEC_OPERATION_SIGN:
	     apdu.p2 = 0xB6;
	     break;
        default:
	     return SC_ERROR_INVALID_ARGUMENTS;
        }
        apdu.le = 0;
        if (!env->flags & SC_SEC_ENV_ALG_REF_PRESENT)
	     return SC_ERROR_INVALID_ARGUMENTS;
        if (!(env->flags & SC_SEC_ENV_FILE_REF_PRESENT))
	     return SC_ERROR_INVALID_ARGUMENTS;
        if (env->flags & SC_SEC_ENV_KEY_REF_PRESENT) {
	     if (env->key_ref_len > 1 || env->key_ref[0] != 0)
		  return SC_ERROR_INVALID_ARGUMENTS;
	}

        p = sbuf;
	*p++ = 0x80;    /* algorithm reference */
	*p++ = 0x01;
	*p++ = env->algorithm_ref & 0xFF;

	*p++ = 0x81;
	*p++ = env->file_ref.len;
	memcpy(p, env->file_ref.value, env->file_ref.len);
	p += env->file_ref.len;

        r = p - sbuf;
        apdu.lc = r;
        apdu.datalen = r;
        apdu.data = sbuf;
        apdu.resplen = 0;
	r = sc_transmit_apdu(card, &apdu);
	if (r) {
	     sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
		"%s: APDU transmit failed", sc_strerror(r));
	     return r;
	}
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r) {
	     sc_debug(card->ctx,  SC_LOG_DEBUG_NORMAL,
		"%s: Card returned error", sc_strerror(r));
	     return r;
	}
	drvdata->invalid_senv=0;
	return 0;
}
static int jcop_compute_signature(sc_card_t *card,
				  const u8 * data, size_t datalen,
				  u8 * out, size_t outlen) {


       int r;
        sc_apdu_t apdu;
        u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
        u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	struct jcop_private_data *drvdata=DRVDATA(card);

        assert(card != NULL && data != NULL && out != NULL);
        if (datalen > 256)
                SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_ARGUMENTS);

	if (drvdata->invalid_senv)
	     return sc_check_sw(card, 0x69, 0x88);

        /* INS: 0x2A  PERFORM SECURITY OPERATION
         * P1:  0x9E  Resp: Digital Signature
         * P2:  0x9A  Cmd: Input for Digital Signature */
        sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, 0x9E,
                       0x9A);
        apdu.resp = rbuf;
        apdu.resplen = sizeof(rbuf); /* FIXME */
        apdu.le = 256;
	if (datalen == 256) {
	     apdu.p2 = data[0];
	     memcpy(sbuf, data+1, datalen-1);
	     apdu.lc = datalen - 1;
	     apdu.datalen = datalen - 1;
	} else {
	     memcpy(sbuf, data, datalen);
	     apdu.lc = datalen;
	     apdu.datalen = datalen;
	}

        apdu.data = sbuf;
        r = sc_transmit_apdu(card, &apdu);
        SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
        if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
                int len = apdu.resplen > outlen ? outlen : apdu.resplen;

                memcpy(out, apdu.resp, len);
                SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, len);
        }
        SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, sc_check_sw(card, apdu.sw1, apdu.sw2));
}
 


static int jcop_decipher(sc_card_t *card,
			 const u8 * crgram, size_t crgram_len,
			 u8 * out, size_t outlen) {

        int r;
        sc_apdu_t apdu;
        u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
        u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	struct jcop_private_data *drvdata=DRVDATA(card);

        assert(card != NULL && crgram != NULL && out != NULL);
        SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_NORMAL);
        if (crgram_len > 256)
                SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_ARGUMENTS);
	if (drvdata->invalid_senv)
	     return sc_check_sw(card, 0x69, 0x88);

        /* INS: 0x2A  PERFORM SECURITY OPERATION
         * P1:  0x80  Resp: Plain value
         * P2:  0x86  Cmd: Padding indicator byte followed by cryptogram */
        sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, 0x80, 0x86);
        apdu.resp = rbuf;
        apdu.resplen = sizeof(rbuf); /* FIXME */
        apdu.le = crgram_len;
        
	if (crgram_len == 256) {
	     apdu.p2 = crgram[0];
	     memcpy(sbuf, crgram+1, crgram_len-1);
	     apdu.lc = crgram_len - 1;
	     apdu.datalen = crgram_len -1;
	} else {
	     sbuf[0] = 0; /* padding indicator byte, 0x00 = No further indication */
	     memcpy(sbuf + 1, crgram, crgram_len);
	     apdu.lc = crgram_len + 1;
	     apdu.datalen = crgram_len + 1;
	}
	
        apdu.data = sbuf;
        r = sc_transmit_apdu(card, &apdu);
        SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
        if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
                int len = apdu.resplen > outlen ? outlen : apdu.resplen;

                memcpy(out, apdu.resp, len);
                SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, len);
        }
        SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, sc_check_sw(card, apdu.sw1, apdu.sw2));
}
 
static int jcop_generate_key(sc_card_t *card, struct sc_cardctl_jcop_genkey *a) {
     int r;
     sc_apdu_t apdu;
     u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
     u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
     u8 *p;
     int is_f4;
     struct jcop_private_data *drvdata=DRVDATA(card);

     if (drvdata->selected == SELECT_MF || drvdata->selected == SELECT_EFDIR )
	  return sc_check_sw(card, 0x6A, 0x82);

     is_f4=0;
     
     if (a->exponent == 0x10001) {
	  is_f4=1;
     } else if (a->exponent != 3) {
	  sc_debug(card->ctx,  SC_LOG_DEBUG_NORMAL,
		"%s: Invalid exponent", sc_strerror(SC_ERROR_NOT_SUPPORTED));
	  return SC_ERROR_NOT_SUPPORTED;
     }
     
     sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0xC1, 0xB6);

     p = sbuf;
     *p++ = 0x80;    /* algorithm reference */
     *p++ = 0x01;
     *p++ = is_f4 ? 0x6E : 0x6D;
     
     *p++ = 0x81;
     *p++ = a->pub_file_ref.len;
     memcpy(p, a->pub_file_ref.value, a->pub_file_ref.len);
     p += a->pub_file_ref.len;
     
     *p++ = 0x81;
     *p++ = a->pri_file_ref.len;
     memcpy(p, a->pri_file_ref.value, a->pri_file_ref.len);
     p += a->pri_file_ref.len;
     
     r = p - sbuf;

     apdu.lc = r;
     apdu.datalen = r;
     apdu.data = sbuf;
     apdu.resplen = 0;
     r = sc_transmit_apdu(card, &apdu);
     if (r) {
	  sc_debug(card->ctx,  SC_LOG_DEBUG_NORMAL,
		"%s: APDU transmit failed", sc_strerror(r));
	  return r;
     }
     r = sc_check_sw(card, apdu.sw1, apdu.sw2);
     if (r) {
	  sc_debug(card->ctx,  SC_LOG_DEBUG_NORMAL,
	  	"%s: Card returned error", sc_strerror(r));
	  return r;
     }

     sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0x46, 0, 0);

     apdu.le = 256;
     apdu.resp=rbuf;
     apdu.resplen = sizeof(rbuf);
     
     r = sc_transmit_apdu(card, &apdu);
     if (r) {
	  sc_debug(card->ctx,  SC_LOG_DEBUG_NORMAL,
		"%s: APDU transmit failed", sc_strerror(r));
	  return r;
     }
     r = sc_check_sw(card, apdu.sw1, apdu.sw2);
     if (r) {
	  sc_debug(card->ctx,  SC_LOG_DEBUG_NORMAL,
		"%s: Card returned error", sc_strerror(r));
	  return r;
     }

     if (rbuf[0] != 0x4) {
	  return SC_ERROR_INVALID_DATA;
     }
     if (a->pubkey_len < rbuf[1])
	  return SC_ERROR_BUFFER_TOO_SMALL;
     a->pubkey_len=rbuf[1] * 4;
     memcpy(a->pubkey, &rbuf[2], a->pubkey_len);
     
     return 0;
}

static int jcop_card_ctl(sc_card_t *card, unsigned long cmd, void *ptr)
{
        switch (cmd) {
        case SC_CARDCTL_GET_DEFAULT_KEY:
                return jcop_get_default_key(card,
                                (struct sc_cardctl_default_key *) ptr);
        case SC_CARDCTL_JCOP_GENERATE_KEY:
                return jcop_generate_key(card,
                                (struct sc_cardctl_jcop_genkey *) ptr);
        }

        return SC_ERROR_NOT_SUPPORTED;
}

static struct sc_card_driver * sc_get_driver(void)
{
     struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

     jcop_ops = *iso_drv->ops;
     jcop_ops.match_card = jcop_match_card;
     jcop_ops.init = jcop_init;
     jcop_ops.finish = jcop_finish;
     /* no record oriented file services */
     jcop_ops.read_record = NULL;
     jcop_ops.write_record = NULL;
     jcop_ops.append_record = NULL;
     jcop_ops.update_record = NULL;
     jcop_ops.read_binary = jcop_read_binary;
     jcop_ops.write_binary = jcop_write_binary;
     jcop_ops.update_binary = jcop_update_binary;
     jcop_ops.select_file = jcop_select_file;
     jcop_ops.create_file = jcop_create_file;
     jcop_ops.delete_file = jcop_delete_file;
     jcop_ops.list_files = jcop_list_files;
     jcop_ops.set_security_env = jcop_set_security_env;
     jcop_ops.compute_signature = jcop_compute_signature;
     jcop_ops.decipher = jcop_decipher;
     jcop_ops.process_fci = jcop_process_fci;
     jcop_ops.card_ctl = jcop_card_ctl;
     
     return &jcop_drv;
}

struct sc_card_driver * sc_get_jcop_driver(void)
{
     return sc_get_driver();
}

