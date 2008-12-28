#
# PKCS15 r/w profile for JCOP cards
#
cardinfo {
    max-pin-length      = 16;
    pin-encoding        = ascii-numeric;
    pin-pad-char        = 0x00;
}

filesystem {
    DF MF {
        DF PKCS15-AppDF {
            acl = *=NONE, CREATE=CHV3;
            EF PKCS15-AODF {
                file-id         = 502E;
            }
            EF PKCS15-PrKDF {
                file-id         = 502C;
            }
            EF PKCS15-PuKDF {
                file-id         = 502B;
            }
            EF PKCS15-CDF {
                file-id         = 502D;
            }
            EF PKCS15-DODF {
                file-id         = 502F;
            }
            template key-domain {
                EF private-key {
                    file-id         = 3000;
                    acl             = *=NEVER, UPDATE=$PIN, CRYPTO=$PIN,
                                      ERASE=$SOPIN;
                }
                EF extractable-key {
                    file-id         = 3100;
                    acl             = *=NEVER, READ=$PIN, UPDATE=$PIN, 
                      ERASE=$SOPIN;
                }
                EF data {
                    file-id         = 3200;
                    acl             = *=NEVER, UPDATE=$PIN, READ=NONE, 
                                      ERASE=$SOPIN;
		}
                EF privdata {
                    file-id         = 3500;
                    acl             = *=NEVER, UPDATE=$PIN, READ=$PIN, 
                                      ERASE=$SOPIN;
                }
                EF public-key {
                    file-id         = 3300;
                    acl             = *=NEVER, UPDATE=$PIN, READ=NONE, 
                                      ERASE=$SOPIN;
                }
                EF certificate {
                    file-id         = 3400;
                    acl             = *=NEVER, UPDATE=$PIN, READ=NONE, 
                                      ERASE=$SOPIN;
                }
            }
            EF temp-pubkey {
                 file-id         = 0000;
                 acl             = *=NEVER, UPDATE=$PIN, READ=NONE, 
                                   ERASE=$SOPIN;
            }
        }
    }
}

