/* -*- Mode: C; tab-width: 4; -*- */
/******************************************************************************
 * Copyright (c) 1996 Netscape Communications. All rights reserved.
 ******************************************************************************/
/*
 * UnixShell.c
 *
 * Netscape Client Plugin API
 * - Function that need to be implemented by plugin developers
 *
 * This file defines a "Template" plugin that plugin developers can use
 * as the basis for a real plugin.  This shell just provides empty
 * implementations of all functions that the plugin can implement
 * that will be called by Netscape (the NPP_xxx methods defined in 
 * npapi.h). 
 *
 * dp Suresh <dp@netscape.com>
 *
 */

#include <stdio.h>
#include <string.h>
#include "npapi.h"

/***********************************************************************
 * Instance state information about the plugin.
 *
 * PLUGIN DEVELOPERS:
 *	Use this struct to hold per-instance information that you'll
 *	need in the various functions in this file.
 ***********************************************************************/

typedef struct _PluginInstance
{
    int nothing;
    char *postUrl;
    char *dataToSign;
} PluginInstance;


/***********************************************************************
 *
 * Empty implementations of plugin API functions
 *
 * PLUGIN DEVELOPERS:
 *	You will need to implement these functions as required by your
 *	plugin.
 *
 ***********************************************************************/

char*
NPP_GetMIMEDescription(void)
{
	return("text/x-text-to-sign:sample:Text to be signed");
}

NPError
NPP_GetValue(NPP instance, NPPVariable variable, void *value)
{
	NPError err = NPERR_NO_ERROR;
	
	printf("NPP_GetValue()\n");
	switch (variable) {
		case NPPVpluginNameString:
			*((char **)value) = "Template plugin";
			break;
		case NPPVpluginDescriptionString:
			*((char **)value) =
				"This plugins handles nothing. This is only"
				" a template.";
			break;
		default:
			err = NPERR_GENERIC_ERROR;
	}
	return err;
}

NPError
NPP_Initialize(void)
{
    printf("NPP_Initialize()\n");
    return NPERR_NO_ERROR;
}


jref
NPP_GetJavaClass()
{
	printf("NPP_GetJavaClass()\n");
	return NULL;
}

void
NPP_Shutdown(void)
{
	printf("NPP_Shutdown()\n");
}

static NPError
post_data(NPP instance, const char *url, const char *target, uint32 len,
	  const char* buf)
{
	NPError rv;
	char headers[256], *sendbuf;
	int hdrlen;
	
	sprintf(headers, "Content-type: text/plain\r\n"
			 "Content-Length: %u\r\n\r\n", (unsigned int) len);
	hdrlen = strlen(headers);
	sendbuf = NPN_MemAlloc(hdrlen + len + 1);
	if (sendbuf == NULL)
		return NPERR_OUT_OF_MEMORY_ERROR;
	memcpy(sendbuf, headers, hdrlen);
	memcpy(sendbuf + hdrlen, buf, len);
	sendbuf[hdrlen + len] = 0;
	printf("Sending:\n---\n%s---\n", sendbuf);
	printf("Url: '%s', target: '%s', len: %d\n", url, target, hdrlen + len);
	rv = NPN_PostURL(instance, url, target, hdrlen + len, sendbuf, FALSE);
//	NPN_MemFree(sendbuf);

	return rv;
}

NPError 
NPP_New(NPMIMEType pluginType,
	NPP instance,
	uint16 mode,
	int16 argc,
	char* argn[],
	char* argv[],
	NPSavedData* saved)
{
        PluginInstance* This;
	NPError rv;
	int i;
	const char *resp = "Testing...1234567890 And testing, and testing\n";

	printf("NPP_New()\n");
	if (instance == NULL)
		return NPERR_INVALID_INSTANCE_ERROR;
	instance->pdata = NPN_MemAlloc(sizeof(PluginInstance));
	
	This = (PluginInstance*) instance->pdata;

	if (This == NULL)
		return NPERR_OUT_OF_MEMORY_ERROR;

	This->postUrl = This->dataToSign = NULL;
	for (i = 0; i < argc; i++) {
		if (strcmp(argn[i], "wsxaction") == 0) {
			This->postUrl = strdup(argv[i]);
		} else if (strcmp(argn[i], "wsxdatatosign") == 0) {
			This->dataToSign = strdup(argv[i]);
		} else
			printf("'%s' = '%s'\n", argn[i], argv[i]);
	}
	if (This->postUrl == NULL)
		return NPERR_GENERIC_ERROR;
	printf("Posting to '%s'\n", This->postUrl);
	rv = post_data(instance, This->postUrl, "_self", strlen(resp), resp);
	printf("PostURL returned %d\n", rv);
	return NPERR_NO_ERROR;
}


NPError 
NPP_Destroy(NPP instance, NPSavedData** save)
{
	PluginInstance* This;

	printf("NPP_Destroy()\n");
	if (instance == NULL)
		return NPERR_INVALID_INSTANCE_ERROR;

	This = (PluginInstance*) instance->pdata;

	/* PLUGIN DEVELOPERS:
	 *	If desired, call NP_MemAlloc to create a
	 *	NPSavedDate structure containing any state information
	 *	that you want restored if this plugin instance is later
	 *	recreated.
	 */
	if (This == NULL)
		return NPERR_NO_ERROR;
	
	if (This->postUrl)
		NPN_MemFree(This->postUrl);
	if (This->dataToSign)
		NPN_MemFree(This->dataToSign);	
	NPN_MemFree(instance->pdata);
	instance->pdata = NULL;

	return NPERR_NO_ERROR;
}



NPError 
NPP_SetWindow(NPP instance, NPWindow* window)
{
	PluginInstance* This;
	printf("NPP_SetWindow()\n");

	if (instance == NULL)
		return NPERR_INVALID_INSTANCE_ERROR;

	if (window == NULL)
		return NPERR_NO_ERROR;

	This = (PluginInstance*) instance->pdata;

	/*
	 * PLUGIN DEVELOPERS:
	 *	Before setting window to point to the
	 *	new window, you may wish to compare the new window
	 *	info to the previous window (if any) to note window
	 *	size changes, etc.
	 */

	return NPERR_NO_ERROR;
}


NPError 
NPP_NewStream(NPP instance,
			  NPMIMEType type,
			  NPStream *stream, 
			  NPBool seekable,
			  uint16 *stype)
{
	PluginInstance* This;
	printf("NPP_NewStream()\n");

	if (instance == NULL)
		return NPERR_INVALID_INSTANCE_ERROR;

	This = (PluginInstance*) instance->pdata;

	return NPERR_NO_ERROR;
}


/* PLUGIN DEVELOPERS:
 *	These next 2 functions are directly relevant in a plug-in which
 *	handles the data in a streaming manner. If you want zero bytes
 *	because no buffer space is YET available, return 0. As long as
 *	the stream has not been written to the plugin, Navigator will
 *	continue trying to send bytes.  If the plugin doesn't want them,
 *	just return some large number from NPP_WriteReady(), and
 *	ignore them in NPP_Write().  For a NP_ASFILE stream, they are
 *	still called but can safely be ignored using this strategy.
 */

int32 STREAMBUFSIZE = 0X0FFFFFFF; /* If we are reading from a file in NPAsFile
				   * mode so we can take any size stream in our
				   * write call (since we ignore it) */

int32 
NPP_WriteReady(NPP instance, NPStream *stream)
{
	PluginInstance* This;
	if (instance != NULL)
		This = (PluginInstance*) instance->pdata;
	printf("NPP_WriteReady()\n");
	return STREAMBUFSIZE;
}


int32 
NPP_Write(NPP instance, NPStream *stream, int32 offset, int32 len, void *buffer)
{
#if 0
	if (instance != NULL)
	{
		PluginInstance* This = (PluginInstance*) instance->pdata;
	}
#endif
	printf("NPP_Write(offset %d, len %d)\n", (int) offset, (int) len);

	return len;		/* The number of bytes accepted */
}


NPError 
NPP_DestroyStream(NPP instance, NPStream *stream, NPError reason)
{
	PluginInstance* This;

	if (instance == NULL)
		return NPERR_INVALID_INSTANCE_ERROR;
	This = (PluginInstance*) instance->pdata;
	printf("NPP_DestroyStream()\n");

	return NPERR_NO_ERROR;
}


void 
NPP_StreamAsFile(NPP instance, NPStream *stream, const char* fname)
{
	PluginInstance* This;
	
	if (instance != NULL)
		This = (PluginInstance*) instance->pdata;
	printf("NPP_StreamAsFile('%s')\n", fname);
}


void 
NPP_Print(NPP instance, NPPrint* printInfo)
{
#if 0
	if(printInfo == NULL)
		return;

	if (instance != NULL) {
		PluginInstance* This = (PluginInstance*) instance->pdata;
	
		if (printInfo->mode == NP_FULL) {
		    /*
		     * PLUGIN DEVELOPERS:
		     *	If your plugin would like to take over
		     *	printing completely when it is in full-screen mode,
		     *	set printInfo->pluginPrinted to TRUE and print your
		     *	plugin as you see fit.  If your plugin wants Netscape
		     *	to handle printing in this case, set
		     *	printInfo->pluginPrinted to FALSE (the default) and
		     *	do nothing.  If you do want to handle printing
		     *	yourself, printOne is true if the print button
		     *	(as opposed to the print menu) was clicked.
		     *	On the Macintosh, platformPrint is a THPrint; on
		     *	Windows, platformPrint is a structure
		     *	(defined in npapi.h) containing the printer name, port,
		     *	etc.
		     */

			void* platformPrint =
				printInfo->print.fullPrint.platformPrint;
			NPBool printOne =
				printInfo->print.fullPrint.printOne;
			
			/* Do the default*/
			printInfo->print.fullPrint.pluginPrinted = FALSE;
		}
		else {	/* If not fullscreen, we must be embedded */
		    /*
		     * PLUGIN DEVELOPERS:
		     *	If your plugin is embedded, or is full-screen
		     *	but you returned false in pluginPrinted above, NPP_Print
		     *	will be called with mode == NP_EMBED.  The NPWindow
		     *	in the printInfo gives the location and dimensions of
		     *	the embedded plugin on the printed page.  On the
		     *	Macintosh, platformPrint is the printer port; on
		     *	Windows, platformPrint is the handle to the printing
		     *	device context.
		     */

			NPWindow* printWindow =
				&(printInfo->print.embedPrint.window);
			void* platformPrint =
				printInfo->print.embedPrint.platformPrint;
		}
	}
#endif
}
