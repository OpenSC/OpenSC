#ifndef __part10_h__
#define __part10_h__

/* Copied from pcsc-lite reader.h */

/**
 * TeleTrust Class 2 reader tags
 */
#define CM_IOCTL_GET_FEATURE_REQUEST SCARD_CTL_CODE(3400)

#define FEATURE_VERIFY_PIN_START  0x01 /**< OMNIKEY Proposal */
#define FEATURE_VERIFY_PIN_FINISH 0x02 /**< OMNIKEY Proposal */
#define FEATURE_MODIFY_PIN_START  0x03 /**< OMNIKEY Proposal */
#define FEATURE_MODIFY_PIN_FINISH 0x04 /**< OMNIKEY Proposal */
#define FEATURE_GET_KEY_PRESSED   0x05 /**< OMNIKEY Proposal */
#define FEATURE_VERIFY_PIN_DIRECT 0x06 /**< USB CCID PIN Verify */
#define FEATURE_MODIFY_PIN_DIRECT 0x07 /**< USB CCID PIN Modify */
#define FEATURE_MCT_READERDIRECT  0x08 /**< KOBIL Proposal */
#define FEATURE_MCT_UNIVERSAL     0x09 /**< KOBIL Proposal */
#define FEATURE_IFD_PIN_PROP      0x0A /**< Gemplus Proposal */
#define FEATURE_ABORT             0x0B /**< SCM Proposal */

/* structures used (but not defined) in PCSC Part 10 revision 2.01.02:
 * "IFDs with Secure Pin Entry Capabilities" */

typedef unsigned __int8 uint8_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int32 uint32_t;

/* Set structure elements aligment on bytes
 * http://gcc.gnu.org/onlinedocs/gcc/Structure_002dPacking-Pragmas.html */
#ifdef __APPLE__
#pragma pack(1)
#else
#pragma pack(push, 1)
#endif

/** the structure must be 6-bytes long */
typedef struct
{
	uint8_t tag;
	uint8_t length;
	uint32_t value;	/**< This value is always in BIG ENDIAN format as documented in PCSC v2 part 10 ch 2.2 page 2. You can use ntohl() for example */
} PCSC_TLV_STRUCTURE;

/** the wLangId and wPINMaxExtraDigit are 16-bits long so are subject to byte
 * ordering */
#define HOST_TO_CCID_16(x) (x)
#define HOST_TO_CCID_32(x) (x)

/** structure used with \ref FEATURE_VERIFY_PIN_DIRECT */
typedef struct
{
	uint8_t bTimerOut;	/**< timeout is seconds (00 means use default timeout) */
	uint8_t bTimerOut2; /**< timeout in seconds after first key stroke */
	uint8_t bmFormatString; /**< formatting options */
	uint8_t bmPINBlockString; /**< bits 7-4 bit size of PIN length in APDU,
	                        * bits 3-0 PIN block size in bytes after
	                        * justification and formatting */
	uint8_t bmPINLengthFormat; /**< bits 7-5 RFU,
	                         * bit 4 set if system units are bytes, clear if
	                         * system units are bits,
	                         * bits 3-0 PIN length position in system units */
	uint16_t wPINMaxExtraDigit; /**< 0xXXYY where XX is minimum PIN size in digits,
	                            and YY is maximum PIN size in digits */
	uint8_t bEntryValidationCondition; /**< Conditions under which PIN entry should
	                                 * be considered complete */
	uint8_t bNumberMessage; /**< Number of messages to display for PIN verification */
	uint16_t wLangId; /**< Language for messages */
	uint8_t bMsgIndex; /**< Message index (should be 00) */
	uint8_t bTeoPrologue[3]; /**< T=1 block prologue field to use (fill with 00) */
	uint32_t ulDataLength; /**< length of Data to be sent to the ICC */
	uint8_t abData[1]; /**< Data to send to the ICC */
} PIN_VERIFY_STRUCTURE;

/** structure used with \ref FEATURE_MODIFY_PIN_DIRECT */
typedef struct
{
	uint8_t bTimerOut;	/**< timeout is seconds (00 means use default timeout) */
	uint8_t bTimerOut2; /**< timeout in seconds after first key stroke */
	uint8_t bmFormatString; /**< formatting options */
	uint8_t bmPINBlockString; /**< bits 7-4 bit size of PIN length in APDU,
	                        * bits 3-0 PIN block size in bytes after
	                        * justification and formatting */
	uint8_t bmPINLengthFormat; /**< bits 7-5 RFU,
	                         * bit 4 set if system units are bytes, clear if
	                         * system units are bits,
	                         * bits 3-0 PIN length position in system units */
	uint8_t bInsertionOffsetOld; /**< Insertion position offset in bytes for
	                             the current PIN */
	uint8_t bInsertionOffsetNew; /**< Insertion position offset in bytes for
	                             the new PIN */
	uint16_t wPINMaxExtraDigit;
	                         /**< 0xXXYY where XX is minimum PIN size in digits,
	                            and YY is maximum PIN size in digits */
	uint8_t bConfirmPIN; /**< Flags governing need for confirmation of new PIN */
	uint8_t bEntryValidationCondition; /**< Conditions under which PIN entry should
	                                 * be considered complete */
	uint8_t bNumberMessage; /**< Number of messages to display for PIN verification*/
	uint16_t wLangId; /**< Language for messages */
	uint8_t bMsgIndex1; /**< index of 1st prompting message */
	uint8_t bMsgIndex2; /**< index of 2d prompting message */
	uint8_t bMsgIndex3; /**< index of 3d prompting message */
	uint8_t bTeoPrologue[3]; /**< T=1 block prologue field to use (fill with 00) */
	uint32_t ulDataLength; /**< length of Data to be sent to the ICC */
	uint8_t abData[1]; /**< Data to send to the ICC */
} PIN_MODIFY_STRUCTURE;

/* restore default structure elements alignment */
#ifdef __APPLE__
#pragma pack()
#else
#pragma pack(pop)
#endif
#endif
