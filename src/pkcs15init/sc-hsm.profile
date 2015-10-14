#
# PKCS15 r/w profile for SmartCard-HSM cards
#
cardinfo {
    label               = "SmartCard-HSM";
    manufacturer        = "CardContact";

    max-pin-length      = 15;
    min-pin-length      = 6;
    pin-encoding        = ascii-numeric;
}

filesystem {
	# Here comes the application DF
	DF PKCS15-AppDF {
		type	= DF;
		exclusive-aid = E8:2B:06:01:04:01:81:C3:1F:02:01;
		acl		= *=NONE;
	}
}
