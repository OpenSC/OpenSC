#
# PKCS15 profile, generic information.
# This profile is loaded before any card specific profile.
#

cardinfo {
	min-pin-length	= 6;
	# max length should be overridden in the per-card profile
	max-pin-length	= 12; # To be defined
}

# Default settings.
# This option block will always be processed.
option default {
	macros {
		protected	= *=$SOPIN, READ=NONE;
		unprotected	= *=NONE;
		so-pin-flags	= local, initialized, soPin;
		so-min-pin-length = 8;
		so-pin-attempts	= 3;
		so-auth-id	= 3;
		odf-size	= 256;
		aodf-size	= 256;
		cdf-size	= 512;
		prkdf-size	= 256;
		pukdf-size	= 256;
		dodf-size	= 256;
	}
}

# Define reasonable limits for PINs and PUK
# Note that we do not set a file path or reference
# for the user pin; that is done dynamically.
PIN user-pin {
	attempts	= 3;
	flags	= local, initialized;
}

PIN so-pin {
	auth-id	= $so-auth-id;
	attempts	= $so-pin-attempts;
	min-length	= $so-min-pin-length;
	flags	= $so-pin-flags;
}

filesystem {
	DF MF {
		path	= 3F00;
		type	= DF;

		# This is the DIR file
		EF DIR {
			type	= EF;
			file-id	= 2F00;
			acl		= *=NONE;
		}

		# Here comes the application DF
		DF PKCS15-AppDF {
			type	= DF;
			aid		= D2:76:00:01:24:01;
			acl		= *=NONE;

			EF PKCS15-TokenInfo {
				ACL		= $unprotected;
			}

			EF PKCS15-PrKDF {
				size		= $prkdf-size;
				acl		= $protected;
			}

			EF PKCS15-PuKDF {
				size		= $pukdf-size;
				acl		= $protected;
			}

			EF PKCS15-CDF {
				acl		= $unprotected;
			}

			# This template defines files for keys, certificates etc.
			#
			# When instantiating the template, each file id will be
			# combined with the last octet of the object's pkcs15 id
			# to form a unique file ID.
			template key-domain {

				# This is a dummy entry - pkcs15-init insists that
				# this is present
				EF private-key {
					file-id	= 5F48;
					ACL	= *=NEVER, CRYPTO=$PIN, UPDATE=CHV3;
				}
			}
		}
	}
}
