#
# PKCS15 r/w profile for Cryptoflex cards
#
CardInfo
	Label		"OpenSC Card"
	Manufacturer	"OpenSC Project"
	MinPinLength	1
	MaxPinLength	8
	PinEncoding	ascii-numeric
	PinPadChar	0x00
	PrKeyAccessFlags RSA 0x1D

	# This is the AAK (ie. transport key) required for
	# creating files in the MF
	Key		AUT1 0x0001 "=Muscle00"

DF MF
	Path		3F00
	ACL		*=AUT1

DF key1df
	Parent		PKCS15-AppDF
	FileID		4B01
	Size		750	# Sufficient for a 1024-bit key
	ACL		*=AUT1 FILES=NONE

DF key2df
	Parent		PKCS15-AppDF
	FileID		4B02
	Size		750	# Sufficient for a 1024-bit key
	ACL		*=AUT1 FILES=NONE

EF pinfile-chv1
	Parent		key1df
	FileID		0000
	Structure	transparent
	Size		23
	ACL		*=NEVER UPDATE=AUT1

EF pinfile-chv2
	Parent		key2df
	FileID		0000
	Structure	transparent
	Size		23
	ACL		*=NEVER UPDATE=AUT1

EF template-private-key-1
	Parent		key1df
	FileID		0012
	Structure	transparent
	Size		330
	ACL		*=AUT1 READ=NEVER

EF template-private-key-2
	Parent		key2df
	FileID		0012
	Structure	transparent
	Size		330
	ACL		*=AUT1 READ=NEVER

EF template-public-key-1
	Parent		PKCS15-AppDF
	FileID		5201
	Structure	transparent
	ACL		*=AUT1 READ=NONE

EF template-public-key-2
	Parent		PKCS15-AppDF
	FileID		5202
	Structure	transparent
	ACL		*=AUT1 READ=NONE

EF PKCS15-DIR
	ACL		*=NEVER READ=NONE UPDATE=AUT1

EF PKCS15-ODF
	ACL		*=NEVER READ=NONE UPDATE=AUT1

EF PKCS15-AODF
	ACL		*=NEVER READ=NONE UPDATE=AUT1

EF PKCS15-PrKDF
	ACL		*=NEVER READ=NONE UPDATE=AUT1

EF PKCS15-PuKDF
	ACL		*=NEVER READ=NONE UPDATE=AUT1

EF PKCS15-CDF
	ACL		*=NEVER READ=NONE UPDATE=AUT1

# CHV1. 3 attempts for the PIN, and 10 for the PUK
PIN CHV1
	File		pinfile-chv1
	Reference	0x01
	Attempts	3 10

# CHV2. 3 attempts for the PIN, and 10 for the PUK
PIN CHV2
	File		pinfile-chv2
	Reference	0x01
	Attempts	3 10

PrivateKey AuthKey
	Reference	0x00
	Index		1
	File		template-private-key-1

PrivateKey SignKey
	Reference	0x00
	Index		1
	File		template-private-key-2
