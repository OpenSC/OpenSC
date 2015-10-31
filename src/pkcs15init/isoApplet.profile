#
# PKCS15 profile for the isoApplet JavaCard Applet.
# 	- init driver: pkcs15-isoApplet.c
# 	- card driver: card-isoApplet.c
#

cardinfo {
	label          ="JavaCard isoApplet";
	manufacturer   = "unknown";
	min-pin-length = 4;
	max-pin-length = 16;
	pin-pad-char   = 0x00;
}

pkcs15 {
	# Method to calculate ID of the crypto objects
	#	mozilla: SHA1(modulus) for RSA, SHA1(pub) for DSA
	#	rfc2459: SHA1(SequenceASN1 of public key components as ASN1 integers)
	#	native: 'E' + number_of_present_objects_of_the_same_type
	# default value: 'native'
	pkcs15-id-style = native;
}

option default {
	macros {
		unusedspace-size = 128;
		odf-size   = 256;
		aodf-size  = 256;
		cdf-size   = 512;
		prkdf-size = 512;
		pukdf-size = 512;
		dodf-size  = 256;
	}
}

PIN so-pin {
	attempts   = 3;
	max-length = 16;
	min-length = 4; 
	reference  = 1;
	flags = case-sensitive, needs-padding, initialized;
}

PIN so-puk {
	attempts   = 3;
	max-length = 16;
	min-length = 16;
	reference  = 2;
	flags = unblockingPin, unblock-disabled, case-sensitive, change-disabled, initialized;
}

filesystem {
	DF MF {
		path = 3F00;
		type = DF;

		# This is the DIR file
		EF DIR {
			type    = EF;
			file-id = 2F00;
			size    = 128;
			acl     = *=NONE;
		}

		# Here comes the application DF
		DF PKCS15-AppDF {
			type    = DF;
			file-id = 5015;
			aid     = A0:00:00:00:63:50:4B:43:53:2D:31:35;
			acl     = *=NONE, DELETE=$PIN;
			size    = 5000;
		
			EF PKCS15-ODF {
				file-id = 5031;
				size    = $odf-size;
				ACL     = *=NONE;
			}

			EF PKCS15-TokenInfo {
				file-id = 5032;
				ACL     = *=NONE;
			}

			EF PKCS15-UnusedSpace {
				file-id = 5033;
				size    = $unusedspace-size;
				ACL     = *=NONE;
			}

			EF PKCS15-AODF {
				file-id = 4401;
				size    = $aodf-size;
				ACL     = *=$PIN, READ=NONE;
			}

			EF PKCS15-PrKDF {
				file-id = 4402;
				size    = $prkdf-size;
				acl     = *=$PIN, READ=NONE;
			}

			EF PKCS15-PuKDF {
				file-id = 4403;
				size    = $pukdf-size;
				acl     = *=$PIN, READ=NONE;
			}

			EF PKCS15-CDF {
				file-id = 4404;
				size    = $cdf-size;
				acl     = *=$PIN, READ=NONE;
			}

			EF PKCS15-DODF {
				file-id = 4405;
				size    = $dodf-size;
				ACL     = *=$PIN, READ=NONE;
			}

			template key-domain {

				BSO private-key {
					ACL = *=$PIN, READ=NEVER;
				}

				# EF extractable-key {
				#   file-id = 3100;
				#   acl = *=NEVER, READ=$PIN, UPDATE=$PIN,
				#         ERASE=$PIN;
				# }

				EF data {
					file-id = 3200;
					acl     = *=NEVER, UPDATE=$PIN, READ=NONE,
					          DELETE-SELF=$PIN, ERASE=$PIN;
				}

				EF privdata {
					file-id = 3500;
					acl     = *=NEVER, UPDATE=$PIN, READ=$PIN,
					          DELETE-SELF=$PIN, ERASE=$PIN;
				}

				EF public-key {
					file-id = 3300;
					acl     = *=NEVER, UPDATE=$PIN, READ=NONE,
					          DELETE-SELF=$PIN, ERASE=$PIN;
				}

				EF certificate {
					file-id = 3400;
					acl     = *=NEVER, UPDATE=$PIN, READ=NONE,
					          DELETE-SELF=$PIN, ERASE=$PIN;
				}
			}
		}
	}
}
