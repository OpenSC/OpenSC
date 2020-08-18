#ifndef PKCS11_DISPLAY_H
#define PKCS11_DISPLAY_H

/*
 * Copyright (C) 2015 Mathias Brossard <mathias@brossard.org>
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307,
 * USA
 */

#include <stdlib.h>
#include <stdio.h>

#include "pkcs11.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (display_func) \
		 (FILE *, CK_LONG, CK_VOID_PTR, CK_ULONG, CK_VOID_PTR);

typedef struct {
  CK_ULONG   type;
  const char *name;
} enum_specs;

typedef struct {
  CK_ULONG type;
  enum_specs *specs;
  CK_ULONG   size;
  const char *name;
} enum_spec;

typedef struct {
  CK_ULONG          type;
  const char *      name;
  display_func*     display;
  void *            arg;
} type_spec;

enum ck_type{
  OBJ_T,
  PROFILE_T,
  KEY_T,
  CRT_T,
  MEC_T,
  MGF_T,
  USR_T,
  STA_T,
  CKD_T,
  RV_T
};

const char *lookup_enum_spec(enum_spec *spec, CK_ULONG value);
const char *lookup_enum(CK_ULONG type, CK_ULONG value);
void print_enum    (FILE *f, CK_LONG type, CK_VOID_PTR value, CK_ULONG size, CK_VOID_PTR arg);
void print_boolean (FILE *f, CK_LONG type, CK_VOID_PTR value, CK_ULONG size, CK_VOID_PTR arg);
void print_generic (FILE *f, CK_LONG type, CK_VOID_PTR value, CK_ULONG size, CK_VOID_PTR arg);
void print_print   (FILE *f, CK_LONG type, CK_VOID_PTR value, CK_ULONG size, CK_VOID_PTR arg);
void show_error    (FILE *f, char *str, CK_RV rc);

void print_ck_info(FILE *f, CK_INFO *info);
void print_slot_list(FILE *f, CK_SLOT_ID_PTR pSlotList, CK_ULONG ulCount);
void print_slot_info(FILE *f, CK_SLOT_INFO *info);
void print_token_info(FILE *f, CK_TOKEN_INFO *info);
void print_mech_list(FILE *f, CK_MECHANISM_TYPE_PTR pMechanismList,
		     CK_ULONG ulMechCount);
void print_mech_info(FILE *f, CK_MECHANISM_TYPE type,
		     CK_MECHANISM_INFO_PTR minfo);
void print_attribute_list(FILE *f, CK_ATTRIBUTE_PTR pTemplate,
			  CK_ULONG  ulCount);
void print_attribute_list_req(FILE *f, CK_ATTRIBUTE_PTR pTemplate,
			      CK_ULONG  ulCount);
void print_session_info(FILE *f, CK_SESSION_INFO *info);
void print_interfaces_list(FILE *f, CK_INTERFACE_PTR pInterfacesList, CK_ULONG ulCount);

extern type_spec ck_attribute_specs[];
extern CK_ULONG ck_attribute_num;
extern enum_spec ck_types[];

#ifdef __cplusplus
};
#endif

#endif
