/* -*- Mode: C; tab-width: 4; -*- */
/*******************************************************************************
 * Java Runtime Interface
 * Copyright (c) 1996 Netscape Communications Corporation. All rights reserved.
 ******************************************************************************/

#ifndef JRITYPES_H
#define JRITYPES_H

#include "jri_md.h"
#include <stddef.h>
#include <stdlib.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

/*******************************************************************************
 * Types
 ******************************************************************************/

struct JRIEnvInterface;

typedef void*		JRIRef;
typedef void*		JRIGlobalRef;

typedef jint		JRIInterfaceID[4];
typedef jint		JRIFieldID;
typedef jint		JRIMethodID;

/* synonyms: */
typedef JRIGlobalRef	jglobal;
typedef JRIRef			jref;

typedef union JRIValue {
	jbool			z;
	jbyte			b;
	jchar			c;
	jshort			s;
	jint			i;
	jlong			l;
	jfloat			f;
	jdouble			d;
	jref			r;
} JRIValue;

typedef JRIValue		jvalue;

typedef enum JRIBoolean {
    JRIFalse		= 0,
    JRITrue			= 1
} JRIBoolean;

typedef enum JRIConstant {
	JRIUninitialized	= -1
} JRIConstant;

/* convenience types: */
typedef JRIRef		jbooleanArray;
typedef JRIRef		jbyteArray;
typedef JRIRef		jcharArray;
typedef JRIRef		jshortArray;
typedef JRIRef		jintArray;
typedef JRIRef		jlongArray;
typedef JRIRef		jfloatArray;
typedef JRIRef		jdoubleArray;
typedef JRIRef		jobjectArray;
typedef JRIRef		jstringArray;
typedef JRIRef		jarrayArray;

#define JRIConstructorMethodName	"<init>"

/*******************************************************************************
 * Signature Construction Macros
 ******************************************************************************/

/*
** These macros can be used to construct signature strings. Hopefully their names
** are a little easier to remember than the single character they correspond to.
** For example, to specify the signature of the method:
**
**	public int read(byte b[], int off, int len);
**
** you could write something like this in C:
**
**	char* readSig = JRISigMethod(JRISigArray(JRISigByte)
**								 JRISigInt
**								 JRISigInt) JRISigInt;
**
** Of course, don't put commas between the types.
*/
#define JRISigArray(T)		"[" T
#define JRISigByte			"B"
#define JRISigChar			"C"
#define JRISigClass(name)	"L" name ";"
#define JRISigFloat			"F"
#define JRISigDouble		"D"
#define JRISigMethod(args)	"(" args ")"
#define JRISigNoArgs		""
#define JRISigInt			"I"
#define JRISigLong			"J"
#define JRISigShort			"S"
#define JRISigVoid			"V"
#define JRISigBoolean		"Z"

/*******************************************************************************
 * Environments
 ******************************************************************************/

extern JRI_PUBLIC_API(const struct JRIEnvInterface**)
JRI_GetCurrentEnv(void);

/*******************************************************************************
 * Specific Scalar Array Types
 ******************************************************************************/

/*
** The JRI Native Method Interface does not support boolean arrays. This
** is to allow Java runtime implementations to optimize boolean array
** storage. Using the ScalarArray operations on boolean arrays is bound
** to fail, so convert any boolean arrays to byte arrays in Java before
** passing them to a native method.
*/

#define JRI_NewByteArray(env, length, initialValues)	\
	JRI_NewScalarArray(env, length, JRISigByte, (jbyte*)(initialValues))
#define JRI_GetByteArrayLength(env, array)	\
	JRI_GetScalarArrayLength(env, array)
#define JRI_GetByteArrayElements(env, array)	\
	JRI_GetScalarArrayElements(env, array)

#define JRI_NewCharArray(env, length, initialValues)	\
	JRI_NewScalarArray(env, ((length) * sizeof(jchar)), JRISigChar, (jbyte*)(initialValues))
#define JRI_GetCharArrayLength(env, array)	\
	JRI_GetScalarArrayLength(env, array)
#define JRI_GetCharArrayElements(env, array)		   \
	((jchar*)JRI_GetScalarArrayElements(env, array))

#define JRI_NewShortArray(env, length, initialValues)	\
	JRI_NewScalarArray(env, ((length) * sizeof(jshort)), JRISigShort, (jbyte*)(initialValues))
#define JRI_GetShortArrayLength(env, array)	\
	JRI_GetScalarArrayLength(env, array)
#define JRI_GetShortArrayElements(env, array)		   \
	((jshort*)JRI_GetScalarArrayElements(env, array))

#define JRI_NewIntArray(env, length, initialValues)	\
	JRI_NewScalarArray(env, ((length) * sizeof(jint)), JRISigInt, (jbyte*)(initialValues))
#define JRI_GetIntArrayLength(env, array)	\
	JRI_GetScalarArrayLength(env, array)
#define JRI_GetIntArrayElements(env, array)		   \
	((jint*)JRI_GetScalarArrayElements(env, array))

#define JRI_NewLongArray(env, length, initialValues)	\
	JRI_NewScalarArray(env, ((length) * sizeof(jlong)), JRISigLong, (jbyte*)(initialValues))
#define JRI_GetLongArrayLength(env, array)	\
	JRI_GetScalarArrayLength(env, array)
#define JRI_GetLongArrayElements(env, array)		   \
	((jlong*)JRI_GetScalarArrayElements(env, array))

#define JRI_NewFloatArray(env, length, initialValues)	\
	JRI_NewScalarArray(env, ((length) * sizeof(jfloat)), JRISigFloat, (jbyte*)(initialValues))
#define JRI_GetFloatArrayLength(env, array)	\
	JRI_GetScalarArrayLength(env, array)
#define JRI_GetFloatArrayElements(env, array)		   \
	((jfloat*)JRI_GetScalarArrayElements(env, array))

#define JRI_NewDoubleArray(env, length, initialValues)	\
	JRI_NewScalarArray(env, ((length) * sizeof(jdouble)), JRISigDouble, (jbyte*)(initialValues))
#define JRI_GetDoubleArrayLength(env, array)	\
	JRI_GetScalarArrayLength(env, array)
#define JRI_GetDoubleArrayElements(env, array)		   \
	((jdouble*)JRI_GetScalarArrayElements(env, array))

/******************************************************************************/
#ifdef __cplusplus
}
#endif
#endif /* JRITYPES_H */
/******************************************************************************/
