#
# PKCS 15 r/w profile for GPK cards
#
CardInfo
	Label		"OpenSC Card (GPK)"
	Manufacturer	"OpenSC Project"
	MinPinLength	0
	MaxPinLength	8
	#PinEncoding

	# This is the secure messaging key required for
	# creating files in the MF
	Key		PRO 0x0001 "=TEST KEYTEST KEY"

# This is the application DF
DF
	Path		3F005015
	AID		A0:00:00:00:63:50:4B:43:53:2D:31:35
	ACL		*=NONE

# Currently we do not support PIN files that can be updated
# by CHV2. Far too messy.
EF pinfile
	Path		3F0050150000
	Structure	0x21	# GPK specific
	RecordLength	8
	Size		32
	ACL		*=NEVER

EF PKCS15-DIR
	Path		3F002F00
	ACL		*=NONE

EF PKCS15-ODF
	Path		3F0050155031
	ACL		*=NONE

EF PKCS15-TokenInfo
	Path		3F0050155032
	ACL		*=NONE

EF PKCS15-AODF
	Path		3F0050154401
	ACL		*=NEVER READ=NONE UPDATE=CHV2

EF PKCS15-PrKDF
	Path		3F0050154402
	ACL		*=NEVER READ=NONE UPDATE=CHV2

EF PKCS15-CDF
	Path		3F0050154403
	ACL		*=NEVER READ=NONE UPDATE=CHV2

EF pk1
	Path		3F0050150001
	ACL		*=NEVER

EF pk2
	Path		3F0050150002
	ACL		*=NEVER

# CVH1. 7 attempts for the PIN, and 3 for the PUK
# Reference 0x8 means "PIN0 in the local EFsc" in GPK parlance
PIN CHV1
	File		pinfile
	Label		"Authentication PIN"
	Reference	0x8
	Attempts	7 3
	AuthID		01

# CVH2. 7 attempts for the PIN, and 3 for the PUK
# Reference 0xA means "PIN2 in the local EFsc" in GPK parlance
PIN CHV2
	File		pinfile
	Label		"Non-repudiation PIN"
	Reference	0xA
	Attempts	7 3
	Offset		16
	AuthID		02

PrivateKey AuthKey
	Label		"Authentication Key"
	File		pk1
	ID		45
	AuthID		01	# Requires CHV1
	KeyUsage	sign

PrivateKey SignKey
	Label		"Non-repudiation Key"
	File		pk2
	ID		46
	AuthID		02	# Requires CHV2
	KeyUsage	NonRepudiation
