#
# PKCS15 r/w profile for GPK cards
#
cardinfo {
    max-pin-length	= 8;
    pin-encoding	= BCD;
    pin-pad-char	= 0x00;
}

# Define reference for SO PIN
PIN so-pin {
    file	= pinfile;
    reference	= 0x08;
}

# Additional filesystem info.
# This is added to the file system info specified in the
# main profile.
filesystem {
    DF MF {
	ACL	= CREATE=PRO1;

        DF PKCS15-AppDF {
            # The PIN file.
            # The GPK supports just one PIN file per DF, and the file
            # can hold up to 8 pins (or 4 PIN/PUK pairs).
            #
            # Note1: many commands use the short file ID (i.e. the lower
	    # 5 bits of the FID) so you must be careful when picking FIDs
	    # for the public key and PIN files.

            EF pinfile {
    	        file-id		= 0000;
    	        structure	= 0x21;	# GPK specific
    	        record-length	= 8;
    	        size		= 64;	# room for 8 pins
    	        ACL		= *=NEVER;
            }

            # Private key files.
            # GPK private key files will never let you read the private key
            # part, so it's okay to set READ=NONE. What's more, we may need
            # read access so we're able to check the key size/type.
            EF template-private-key {
    	        file-id		= 0006;	# This is the base FileID
    	        structure	= 0x2C;	# GPK specific
    	        ACL		= *=NEVER,
					READ=NONE,
					CRYPTO=$PIN,
					UPDATE=$PIN,
					WRITE=$PIN;
            }

	    # Extractable private keys are stored in transparent EFs.
	    # Encryption of the content is performed by libopensc.
            EF template-extractable-key {
    	        file-id		= 7000;
    	        structure	= transparent;
    	        ACL		= *=NEVER,
					READ=$PIN,
					UPDATE=$PIN,
					WRITE=$PIN;
            }

	    # data objects are stored in transparent EFs.
            EF template-data {
    	        file-id		= 5000;
    	        structure	= transparent;
    	        ACL		= *=NEVER,
					READ=NONE,
					UPDATE=$PIN,
					WRITE=$PIN;
            }

            EF template-public-key {
    	        file-id		= 8000;
    	        structure	= transparent;
    	        ACL		= *=NONE;
            }

            # Certificate template
            EF template-certificate {
    	        file-id		= 9000;
    	        structure	= transparent;
    	        ACL		= *=NONE;
            }
	}
    }
}
