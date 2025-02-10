#
# PKCS15 profile for the PIV Applet.
#

cardinfo {
    label           = "Swissbit iShield Key Pro";
    manufacturer    = "Swissbit AG";
    min-pin-length  = 6;
    max-pin-length  = 8;
}

pkcs15 {
    do-last-update  = false;
    pkcs15-id-style = native;
}

option default {
    macros {
    protected   = *=$SOPIN, READ=NONE;
    unprotected = *=NONE;
    so-pin-flags    = local, initialized, needs-padding, soPin;
    so-min-pin-length = 6;
    so-pin-attempts = 5;
    so-auth-id  = FF;
    so-puk-attempts = 3;
    so-min-puk-length = 8;
    unusedspace-size = 128;
    odf-size    = 256;
    aodf-size   = 256;
    cdf-size    = 512;
    prkdf-size  = 256;
    pukdf-size  = 256;
    dodf-size   = 256;
    }
}

PIN user-pin {
    attempts    = 5;
    flags   = local, initialized, needs-padding;
}
PIN user-puk {
    attempts    = 3;
}
PIN so-pin {
    auth-id = $so-auth-id;
    attempts    = $so-pin-attempts;
    min-length  = $so-min-pin-length;
    flags   = $so-pin-flags;
}
PIN so-puk {
    attempts    = $so-puk-attempts;
    min-length  = $so-min-puk-length;
}