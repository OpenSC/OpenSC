#
# PKCS 15 r/w profile for GPK cards
#
CardInfo
	Label		"OpenSC Card (GPK)"
	Manufacturer	"OpenSC Project"
	MinPinLength	1
	MaxPinLength	8
	PinEncoding	BCD
	PrKeyAccessFlags RSA 0x1D
	PrKeyAccessFlags DSA 0x12

	# This is the secure messaging key required for
	# creating files in the MF
	Key		PRO 0x0001 "=TEST KEYTEST KEY"

# This is the application DF
DF
	Path		3F005015
	AID		A0:00:00:00:63:50:4B:43:53:2D:31:35
	ACL		*=NONE

# Note: many commands use the short file ID (i.e. the lower 5 bits
# of the FID) so you must be careful when picking FIDs for the
# public key and PIN files.

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

# Private key files.
# GPK private key files will never let you read the private key
# part, so it's okay to set READ=NONE. What's more, we need
# read access so we're able to update the file.
EF pk1
	Path		3F005015000E
	Structure	0x2C	# GPK specific
	ACL		*=NEVER READ=NONE UPDATE=CHV2 WRITE=CHV2

EF pk2
	Path		3F005015000F
	Structure	0x2C	# GPK specific
	ACL		*=NEVER READ=NONE UPDATE=CHV2 WRITE=CHV2

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
