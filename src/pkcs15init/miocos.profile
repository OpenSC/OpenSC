#
# PKCS15 r/w profile for MioCOS cards
#
CardInfo
	Label		"OpenSC Card"
	Manufacturer	"OpenSC Project"
	MinPinLength	1
	MaxPinLength	8
	PinEncoding	ascii-numeric
	PinPadChar	0x00
	PrKeyAccessFlags RSA 0x1D

EF pinfile-chv1
	Path		3F000000
	Structure	transparent
	Size		20
	ACL		*=NONE

EF pinfile-chv2
	Parent		PKCS15-AppDF
	FileID		5002
	Size		23
	ACL		*=NONE

EF template-private-key-1
	Parent		PKCS15-AppDF
	FileID		4B01
	Size		330
	ACL		*=NONE CRYPTO=CHV1

EF template-private-key-2
	Parent		PKCS15-AppDF
	FileID		4B02
	Size		330
	ACL		*=NONE CRYPTO=CHV2

EF template-public-key-1
	Parent		PKCS15-AppDF
	FileID		5201
	Structure	transparent
	ACL		*=NONE READ=NONE

EF template-public-key-2
	Parent		PKCS15-AppDF
	FileID		5202
	Structure	transparent
	ACL		*=NONE READ=NONE

EF PKCS15-DIR
	ACL		*=NEVER READ=NONE UPDATE=CHV1

EF PKCS15-ODF
	ACL		*=NEVER READ=NONE UPDATE=CHV1

EF PKCS15-AODF
	ACL		*=NEVER READ=NONE UPDATE=CHV1

EF PKCS15-PrKDF
	ACL		*=NEVER READ=NONE UPDATE=CHV1

EF PKCS15-PuKDF
	ACL		*=NEVER READ=NONE UPDATE=CHV1

EF PKCS15-CDF
	ACL		*=NEVER READ=NONE UPDATE=CHV1

# CHV1. 3 attempts for the PIN, and 10 for the PUK
PIN CHV1
	File		pinfile-chv1
	Reference	0x01
	Attempts	3 10

# CHV2. 3 attempts for the PIN, and 10 for the PUK
PIN CHV2
	File		pinfile-chv2
	Reference	0x02
	Attempts	3 10

PrivateKey AuthKey
	Reference	0x01
	Index		1
	File		template-private-key-1

PrivateKey SignKey
	Reference	0x02
	Index		1
	File		template-private-key-2
