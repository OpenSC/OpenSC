#
# PKCS15 r/w profile for GPK cards
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

# Note: many commands use the short file ID (i.e. the lower 5 bits
# of the FID) so you must be careful when picking FIDs for the
# public key and PIN files.

# Currently we do not support PIN files that can be updated
# by CHV2. Far too messy.
EF pinfile
	Parent		PKCS15-AppDF
	FileID		0000
	Structure	0x21	# GPK specific
	RecordLength	8
	Size		32
	ACL		*=NEVER

# Private key files.
# GPK private key files will never let you read the private key
# part, so it's okay to set READ=NONE. What's more, we need
# read access so we're able to update the file.
EF template-private-key
	Parent		PKCS15-AppDF
	FileID		0006	# This is the base FileID
	Structure	0x2C	# GPK specific
	ACL		*=NEVER READ=NONE UPDATE=CHV1 WRITE=CHV1

EF template-public-key
	Parent		PKCS15-AppDF
	FileID		8000
	Structure	transparent
	ACL		*=NONE

# CVH1. 7 attempts for the PIN, and 3 for the PUK
# Reference 0x8 means "PIN0 in the local EFsc" in GPK parlance
PIN CHV1
	File		pinfile
	Reference	0x8
	Attempts	7 3

# CVH2. 7 attempts for the PIN, and 3 for the PUK
# Reference 0xA means "PIN2 in the local EFsc" in GPK parlance
PIN CHV2
	File		pinfile
	Reference	0xA
	Attempts	7 3
	Offset		16
