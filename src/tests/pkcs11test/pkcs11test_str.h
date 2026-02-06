#ifndef PKCS11TEST_STR_H
#define PKCS11TEST_STR_H

#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

#include "pkcs11/pkcs11.h"
#include "pkcs11test_common.h"

typedef void (display_func) \
		 (FILE *, CK_LONG, CK_VOID_PTR, CK_ULONG, CK_VOID_PTR);

typedef struct {
	CK_ULONG type;
	char *name;
} enum_specs;

typedef struct {
	CK_ULONG type;
	enum_specs *specs;
	CK_ULONG size;
	char *name;
} enum_spec;

typedef struct {
	CK_ULONG type;
	char *name;
} type_spec;

enum ck_type {
	INT = -1,
	OBJ_T = 0,
	PROFILE_T,
	KEY_T,
	CRT_T,
	MEC_T,
	MGF_T,
	USR_T,
	STA_T,
	CKD_T,
	RV_T,
	FLG_T,
	ATR_T
};

int lookup_string(CK_ULONG type, const char *value, CK_ULONG_PTR result);
int lookup_enum(CK_ULONG type, CK_ULONG value, char **result);

#endif // PKCS11TEST_STR_H
