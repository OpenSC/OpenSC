/*
 * iso7816.h: ISO-7816 defines
 */

#ifndef _ISO7816_TYPES_H
#define _ISO7816_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

#define ISO7816_TAG_FCP		0x62
#define ISO7816_TAG_FCP_SIZE	0x80
#define ISO7816_TAG_FCP_TYPE	0x82
#define ISO7816_TAG_FCP_ID	0x83
#define ISO7816_TAG_FCP_ACLS	0x86


#define ISO7816_FILE_TYPE_TRANSPARENT_EF	0x01
#define ISO7816_FILE_TYPE_DF			0x38

#ifdef __cplusplus
}
#endif

#endif
