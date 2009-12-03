
cardinfo {
	label 			= "westcos";
	manufacturer	= "CEV";

	max-pin-length	= 8;
	min-pin-length	= 4;
	pin-encoding	= BCD;
	pin-pad-char	= 0xff;
	
}

# Default settings.
# This option block will always be processed.
option default {
	macros {
		protected	= *=$PIN, READ=NONE;
		unprotected	= *=NONE;
		private		= *=$PIN;
		so-pin-flags	= local, initialized, needs-padding; #, soPin;
		so-min-pin-length = 6;
		so-pin-attempts	= 2;
		so-auth-id	= 1; #FF;
		so-puk-attempts	= 4;
		so-min-puk-length = 6;
		unusedspace-size = 128;
		odf-size	= 256;
		aodf-size	= 256;
		cdf-size	= 512;
		prkdf-size	= 256;
		pukdf-size	= 256;
		dodf-size	= 256;
	}
}

PIN so-pin {
	auth-id = 1; 
	reference = 1;
	attempts	= 3;
	min-length  = 4;
	max-length  = 8;
	flags = local, initialized, needs-padding;
}
PIN so-puk {
	auth-id = 2; 
	reference = 2;
	attempts	= 10;
	min-length  = 4;
	max-length  = 8;
	flags = local, initialized, needs-padding;
}
PIN user-pin {
	auth-id = 1; 
	reference = 1;
	attempts	= 3;
	min-length  = 4;
	max-length  = 8;
	flags = local, initialized, needs-padding;
}
PIN user-puk {
	auth-id = 2;
	reference = 2;
	attempts	= 10;
	min-length  = 4;
	max-length  = 8;
	flags = local, initialized, needs-padding;
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
			acl		= $unprotected;
		}

		# Here comes the application DF
		DF PKCS15-AppDF {
			type	= DF;
			file-id	= 5015;
			aid		= A0:00:00:00:63:50:4B:43:53:2D:31:35;
			acl		= $unprotected;
			size	= 5000;

			EF PINFILE {
				file-id		= AAAA;
				type		= INTERNAL-EF;
				structure	= TRANSPARENT;
				size		= 100;
				acl		= *=NEVER;
			}

			EF PKCS15-ODF {
				file-id		= 5031;
				size		= $odf-size;
				acl			= $unprotected;
			}

			EF PKCS15-TokenInfo {
				file-id		= 5032;
				acl			= $unprotected;
			}

			EF PKCS15-UnusedSpace {
				file-id		= 5033;
				size		= $unusedspace-size;
				acl			= $unprotected;
			}

			EF PKCS15-AODF {
				file-id		= 4401;
				size		= $aodf-size;
				acl			= $protected;
			}

			EF PKCS15-PrKDF {
				file-id		= 4402;
				size		= $prkdf-size;
				acl			= $protected;
			}

			EF PKCS15-PuKDF {
				file-id		= 4403;
				size		= $pukdf-size;
				acl			= $protected;
			}

			EF PKCS15-CDF {
				file-id		= 4404;
				size		= $cdf-size;
				acl			= $protected;
			}

			EF PKCS15-DODF {
				file-id		= 4405;
				size		= $dodf-size;
				ACL			= $protected;
			}


			# This template defines files for keys, certificates etc.
			#
			# When instantiating the template, each file id will be
			# combined with the last octet of the object's pkcs15 id
			# to form a unique file ID.
			template key-domain {
				EF private-key {
					file-id     = 0100;
					structure   = transparent;
					acl         = *=NEVER, READ=$PIN, UPDATE=$PIN, WRITE=$PIN, DELETE=$PIN;
				}

				EF public-key {
					file-id     = 0200;
					structure   = transparent;
					acl         = *=NEVER, READ=NONE, UPDATE=$PIN, WRITE=$PIN, DELETE=$PIN;
				}

				# Certificate template
				EF certificate {
					file-id     = 0300;
					structure   = transparent;
					acl         = *=NEVER, READ=NONE, UPDATE=$PIN, WRITE=$PIN, DELETE=$PIN;
				}

				# data objects are stored in transparent EFs.
				EF data {
					file-id     = 0400;
					structure   = transparent;
					acl         = *=NEVER, READ=NONE, UPDATE=$PIN, WRITE=$PIN, DELETE=$PIN;
				}

				# private data objects are stored in transparent EFs.
				EF privdata {
					file-id     = 0500;
					structure   = transparent;
					acl         = *=NEVER, READ=$PIN, UPDATE=$PIN, WRITE=$PIN, DELETE=$PIN;
				}
			}

		}
	}
}



