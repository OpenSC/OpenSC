#
# PKCS15 r/w profile for Cryptoflex cards
#
CardInfo
	Label		"OpenSC Card"
	Manufacturer	"OpenSC Project"
	MinPinLength	1
	MaxPinLength	8
	PinEncoding	ascii-numeric
	PinPadChar	0x2d	# '-'
	PrKeyAccessFlags RSA 0x1D

	# This is the AAK (ie. transport key) required for
	# creating files in the MF
	Key		AUT1 0x0001 "=Muscle00"

EF chv1file
	FileID		0000
	Path		50154B01
	Structure	transparent
	Size		23
	ACL		*=NEVER UPDATE=AUT1

EF chv2file
	FileID		0000
	Path		50154B02
	Structure	transparent
	Size		23
	ACL		*=NEVER UPDATE=AUT1

EF template-private-key
	FileID		0012	# This is the base FileID
	Structure	transparent
	ACL		*=NEVER UPDATE=AUT1

EF template-public-key
	FileID		1012
	Structure	transparent
	ACL		*=NONE

# CVH1. 3 attempts for the PIN, and 10 for the PUK
PIN CHV1
	File		chv1file
	Reference	0x1
	Attempts	3 10

# CVH2. 3 attempts for the PIN, and 10 for the PUK
PIN CHV2
	File		chv2file
	Reference	0x1
	Attempts	3 10
