#
# PKCS15 profile, generic information.
# This profile is loaded before any card specific profile.
#

cardinfo {
    label		= "OpenSC Card";
    manufacturer	= "OpenSC Project";
    min-pin-length	= 4;
    # max length should be overridden in the per-card profile
    max-pin-length	= 8;
}

# Default settings.
# This option block will always be processed.
option default {
    macros {
        protected	= *=$SOPIN, READ=NONE;
        unprotected	= *=NONE;
	so-pin-flags	= local, initialized, needs-padding, soPin;
	so-min-pin-length = 6;
	so-pin-attempts	= 2;
	so-auth-id	= FF;
	so-puk-attempts	= 4;
	so-min-puk-length = 6;
	default-df-size	= 256;
    }
}

# This option sets up the card so that a single
# user PIN protects all files
option onepin {
    macros {
        protected	= *=$PIN, READ=NONE;
        unprotected	= *=NONE;
	so-pin-flags	= local, initialized, needs-padding;
	so-min-pin-length = 4;
	so-pin-attempts	= 3;
	so-auth-id	= 1;
	so-puk-attempts	= 7;
	so-min-puk-length = 4;
    }
}

# This option is for cards with very little memory
option small {
    macros {
	default-df-size	= 128;
    }
}

# Define reasonable limits for PINs and PUK
# Note that we do not set a file path or reference
# for the user pin; that is done dynamically.
PIN user-pin {
    attempts	= 3;
    flags	= local, initialized, needs-padding;
}
PIN user-puk {
    attempts	= 7;
}
PIN so-pin {
    auth-id	= $so-auth-id;
    attempts	= $so-pin-attempts;
    min-length	= $so-min-pin-length;
    flags	= $so-pin-flags;
}
PIN so-puk {
    attempts	= $so-puk-attempts;
    min-length	= $so-min-puk-length;
}

filesystem {
    DF MF {
        path	= 3F00;
        type	= DF;

	# This is the DIR file
	EF DIR {
	    type	= EF;
	    file-id	= 2F00;
	    size	= 128;
	    acl		= *=NONE;
	}

	# Here comes the application DF
	DF PKCS15-AppDF {
	    type	= DF;
	    file-id	= 5015;
	    aid		= A0:00:00:00:63:50:4B:43:53:2D:31:35;
	    acl		= *=NONE;
	    size	= 5000;

	    EF PKCS15-ODF {
	        file-id		= 5031;
		size		= $default-df-size;
		ACL		= $unprotected;
	    }

	    EF PKCS15-TokenInfo {
		file-id		= 5032;
		ACL		= $unprotected;
	    }

	    EF PKCS15-AODF {
	        file-id		= 4401;
		size		= $default-df-size;
		ACL		= $protected;
	    }

	    EF PKCS15-PrKDF {
	        file-id		= 4402;
		size		= $default-df-size;
		acl		= $protected;
	    }

	    EF PKCS15-PuKDF {
	        file-id		= 4403;
		size		= $default-df-size;
		acl		= $protected;
	    }

	    EF PKCS15-CDF {
	        file-id		= 4404;
		size		= "2 * $default-df-size";
		acl		= $protected;
	    }

	    EF PKCS15-DODF {
	        file-id		= 4405;
		size		= $default-df-size;
		ACL		= $protected;
	    }

	}
    }
}
