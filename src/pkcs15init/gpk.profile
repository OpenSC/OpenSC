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
	Key		PRO1 "=TEST KEYTEST KEY"

# The PIN file.
# The GPK supports just one PIN file per DF, and the file can hold
# up to 8 pins (or 4 PIN/PUK pairs).
#
# Note1: many commands use the short file ID (i.e. the lower 5 bits
#	of the FID) so you must be careful when picking FIDs for the
#	public key and PIN files.

EF pinfile
	Parent		PKCS15-AppDF
	FileID		0000
	Structure	0x21	# GPK specific
	RecordLength	8
	Size		64	# room for 8 pins
	ACL		*=NEVER

# Private key files.
# GPK private key files will never let you read the private key
# part, so it's okay to set READ=NONE. What's more, we may need
# read access so we're able to check the key size/type.
EF template-private-key
	Parent		PKCS15-AppDF
	FileID		0006	# This is the base FileID
	Structure	0x2C	# GPK specific
	ACL		*=NEVER READ=NONE CRYPTO=$PIN UPDATE=$PIN WRITE=$PIN

EF template-public-key
	Parent		PKCS15-AppDF
	FileID		8000
	Structure	transparent
	ACL		*=NONE

# Certificate template
EF template-certificate
	Parent		PKCS15-AppDF
	FileID		9000
	Structure	transparent
	ACL		*=NONE

# Define an SO pin
# This PIN is not used yet
#PIN sopin
#	File		sopinfile
#	Reference	0
