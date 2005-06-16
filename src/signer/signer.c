#include <stdio.h>
#include <string.h>
#include "npinclude/npapi.h"
#include "signer.h"
#include "opensc-support.h"

char*
NPP_GetMIMEDescription(void)
{
	return (char *) "text/x-text-to-sign:sgn:Text to be signed";
}

NPError
NPP_GetValue(void *inst, NPPVariable variable, void *value)
{
	NPError err = NPERR_NO_ERROR;
	
	printf("NPP_GetValue()\n");
	switch (variable) {
		case NPPVpluginNameString:
			*((char **)value) = (char *) "OpenSC Signer plugin";
			break;
		case NPPVpluginDescriptionString:
			*((char **)value) = (char *) "This plugins handles"
					    " web signatures using OpenSC"
					    " smart card library.";
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
NPP_GetJavaClass(void)
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
	  const char *buf, const char *tag)
{
	NPError rv;
	char headers[256], *sendbuf;
	char *content;
	unsigned int content_len, hdrlen, taglen;
	
	taglen = strlen(tag);
	content_len = taglen + len + 1;
	content = (char *) NPN_MemAlloc(content_len);
	if (content == NULL)
		return NPERR_OUT_OF_MEMORY_ERROR;
	memcpy(content, tag, taglen);
	content[taglen] = '=';
	memcpy(content+taglen+1, buf, len);
	
	sprintf(headers, "Content-type: application/x-www-form-urlencoded\r\n"
			 "Content-Length: %u\r\n\r\n", (unsigned int) content_len);
	hdrlen = strlen(headers);
	sendbuf = (char *) NPN_MemAlloc(hdrlen + content_len);
	if (sendbuf == NULL)
		return NPERR_OUT_OF_MEMORY_ERROR;
	memcpy(sendbuf, headers, hdrlen);
	memcpy(sendbuf + hdrlen, content, content_len);
	sendbuf[hdrlen + content_len] = 0;
	NPN_MemFree(content);
	printf("Sending:\n---\n%s---\n", sendbuf);
	printf("Url: '%s', target: '%s', len: %ld\n", url, target, hdrlen + len);
	rv = NPN_PostURL(instance, url, target, hdrlen + content_len, sendbuf, FALSE);

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
        PluginInstance* This = NULL;
	NPError rv;
	int r, i, datalen, b64datalen;
	u8 *data = NULL, *b64data = NULL;
	char *postUrl = NULL, *dataToSign = NULL, *fieldName = NULL;

	printf("NPP_New()\n");
	if (instance == NULL)
		return NPERR_INVALID_INSTANCE_ERROR;
	instance->pdata = NPN_MemAlloc(sizeof(PluginInstance));
	
	This = (PluginInstance*) instance->pdata;

	if (This == NULL)
		return NPERR_OUT_OF_MEMORY_ERROR;

	This->ctx = NULL;
	This->card = NULL;
	This->p15card = NULL;
	
	for (i = 0; i < argc; i++) {
		if (strcmp(argn[i], "wsxaction") == 0) {
			postUrl = strdup(argv[i]);
		} else if (strcmp(argn[i], "wsxdatatosign") == 0) {
			dataToSign = strdup(argv[i]);
		} else if (strcmp(argn[i], "wsxname") == 0) {
			fieldName = strdup(argv[i]);
		} else
			printf("'%s' = '%s'\n", argn[i], argv[i]);
	}
	if (postUrl == NULL || dataToSign == NULL) {
		r = NPERR_GENERIC_ERROR;
		goto err;
	}
	if (fieldName == NULL)
		fieldName = strdup("SignedData");
	This->signdata = dataToSign;
	This->signdata_len = strlen(dataToSign);

	r = create_envelope(This, &data, &datalen);
	if (r) {
		r = NPERR_GENERIC_ERROR;
		goto err;
	}
	b64datalen = datalen * 4 / 3 + 4;
	b64data = (u8 *) malloc(b64datalen);
	r = sc_base64_encode(data, datalen, b64data, b64datalen, 0);
	if (r) {
		r = NPERR_GENERIC_ERROR;
		goto err;
	}
	printf("Posting to '%s'\n", postUrl);
	printf("Data to sign: %s\n", dataToSign);
	printf("Signed: %s\n", b64data);
	rv = post_data(instance, postUrl, "_self", strlen((char *) b64data), (char *) b64data,
		       fieldName);
	printf("post_data returned %d\n", rv);
	r = NPERR_NO_ERROR;
err:
	if (fieldName)
		free(fieldName);
	if (dataToSign)
		free(dataToSign);
	if (postUrl)
		free(postUrl);
	if (data)
		free(data);
	if (b64data)
		free(b64data);
	return r;
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
	
	NPN_MemFree(instance->pdata);
	instance->pdata = NULL;

	return NPERR_NO_ERROR;
}



NPError 
NPP_SetWindow(NPP instance, NPWindow* window)
{
	PluginInstance* This;
	Display *dpy;
	NPSetWindowCallbackStruct *ws;
	Window win;
	
	printf("NPP_SetWindow()\n");

	if (instance == NULL)
		return NPERR_INVALID_INSTANCE_ERROR;

	if (window == NULL)
		return NPERR_NO_ERROR;

	This = (PluginInstance*) instance->pdata;
	ws = (NPSetWindowCallbackStruct *) window->ws_info;
	dpy = ws->display;
	win = (Window) window->window;
	
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
