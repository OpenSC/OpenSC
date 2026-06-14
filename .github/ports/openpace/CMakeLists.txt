cmake_minimum_required(VERSION 3.15)
project(openpace C)

find_package(OpenSSL REQUIRED)

add_library(eac STATIC
    ca_lib.c
    cv_cert.c
    cvc_lookup.c
    x509_lookup.c
    eac_asn1.c
    eac.c
    eac_ca.c
    eac_dh.c
    eac_ecdh.c
    eac_kdf.c
    eac_lib.c
    eac_print.c
    eac_util.c
    misc.c
    objects.c
    pace.c
    pace_lib.c
    pace_mappings.c
    ri.c
    ri_lib.c
    ssl_compat.c
    ta.c
    ta_lib.c
)

target_include_directories(eac
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(eac PUBLIC OpenSSL::Crypto)

target_compile_definitions(eac PRIVATE
    HAVE_ASN1_STRING_GET0_DATA
    HAVE_DECL_OPENSSL_ZALLOC
    HAVE_DH_GET0_KEY
    HAVE_DH_GET0_PQG
    HAVE_DH_SET0_KEY
    HAVE_DH_SET0_PQG
    HAVE_ECDSA_SIG_GET0
    HAVE_ECDSA_SIG_SET0
    HAVE_EC_KEY_METHOD
    HAVE_RSA_GET0_KEY
    HAVE_RSA_SET0_KEY
    HAVE_EC_POINT_GET_AFFINE_COORDINATES
    HAVE_EC_POINT_SET_AFFINE_COORDINATES
    HAVE_EVP_PKEY_DUP
    "X509DIR=\"/\""
    "CVCDIR=\"/\""
)

install(TARGETS eac ARCHIVE DESTINATION lib)
install(DIRECTORY eac DESTINATION include)
