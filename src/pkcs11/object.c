#include "sc-pkcs11.h"

CK_RV C_CreateObject(CK_SESSION_HANDLE hSession,    /* the session's handle */
		     CK_ATTRIBUTE_PTR  pTemplate,   /* the object's template */
		     CK_ULONG          ulCount,     /* attributes in template */
		     CK_OBJECT_HANDLE_PTR phObject) /* receives new object's handle. */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CopyObject(CK_SESSION_HANDLE    hSession,    /* the session's handle */
		   CK_OBJECT_HANDLE     hObject,     /* the object's handle */
		   CK_ATTRIBUTE_PTR     pTemplate,   /* template for new object */
		   CK_ULONG             ulCount,     /* attributes in template */
		   CK_OBJECT_HANDLE_PTR phNewObject) /* receives handle of copy */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession,  /* the session's handle */
		      CK_OBJECT_HANDLE  hObject)   /* the object's handle */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession,  /* the session's handle */
		      CK_OBJECT_HANDLE  hObject,   /* the object's handle */
		      CK_ULONG_PTR      pulSize)   /* receives size of object */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession,   /* the session's handle */
			  CK_OBJECT_HANDLE  hObject,    /* the object's handle */
			  CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes, gets values */
			  CK_ULONG          ulCount)    /* attributes in template */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession,   /* the session's handle */
			  CK_OBJECT_HANDLE  hObject,    /* the object's handle */
			  CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes and values */
			  CK_ULONG          ulCount)    /* attributes in template */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession,   /* the session's handle */
			CK_ATTRIBUTE_PTR  pTemplate,  /* attribute values to match */
			CK_ULONG          ulCount)    /* attributes in search template */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE    hSession,          /* the session's handle */
		    CK_OBJECT_HANDLE_PTR phObject,          /* receives object handle array */
		    CK_ULONG             ulMaxObjectCount,  /* max handles to be returned */
		    CK_ULONG_PTR         pulObjectCount)    /* actual number returned */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession) /* the session's handle */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}


