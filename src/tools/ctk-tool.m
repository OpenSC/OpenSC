#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <CryptoTokenKit/CryptoTokenKit.h>
#import <stdio.h>
#import <unistd.h>
#import <os/lock.h>

#import "ctk-tool-cmdline.h"

int numThreads;

// Global lock for thread-safe console output
static os_unfair_lock print_lock = OS_UNFAIR_LOCK_INIT;

void print_test_result(const char *algoName, BOOL success, CFErrorRef error, int threadID) {
    os_unfair_lock_lock(&print_lock);
    char label[100];

    if (numThreads > 1) {
        snprintf(label, sizeof(label), "thread %-3d ", threadID);
        label[sizeof(label)-1] = '\0';
    } else {
        label[0] = '\0';
    }

    if (success) {
        printf("    [OK]    %s%s\n", label, algoName);
    } else {
        NSError *nsError = (__bridge NSError *)error;
        printf("    [FAIL]  %s%s\n", label, algoName);
        printf("            %s\n", [[nsError localizedDescription] UTF8String]);
    }

    os_unfair_lock_unlock(&print_lock);
}

NSData* generate_test_data(NSUInteger length) {
    NSMutableData *data = [NSMutableData dataWithLength:length];
    (void)SecRandomCopyBytes(kSecRandomDefault, length, data.mutableBytes);
    return data;
}

// Generates input payload based on SecKey.h algorithm documentation
NSData* prepare_input_for_algorithm(SecKeyAlgorithm algo, SecKeyRef key) {
    NSString *algoStr = (__bridge NSString *)algo;

    CFDictionaryRef attributes = SecKeyCopyAttributes(key);
    NSNumber *keySize = (NSNumber *)CFDictionaryGetValue(attributes, kSecAttrKeySizeInBits);
    size_t blockSize = [keySize unsignedIntegerValue] / 8;
    CFRelease(attributes);

    // Case-insensitive search inside the algorithm string
    BOOL (^contains)(NSString *) = ^BOOL(NSString *search) {
        return [algoStr rangeOfString:search options:NSCaseInsensitiveSearch].location != NSNotFound;
    };

    // 1. RAW: Must match key block size exactly
    if (contains(@"Raw")) {
        return generate_test_data(blockSize);
    }

    // 2. DIGESTS: Must match exact hash length
    if (contains(@"Digest")) {
        if (contains(@"SHA1")) return generate_test_data(20);
        if (contains(@"SHA224")) return generate_test_data(28);
        if (contains(@"SHA256")) return generate_test_data(32);
        if (contains(@"SHA384")) return generate_test_data(48);
        if (contains(@"SHA512")) return generate_test_data(64);
        return generate_test_data(32); // Fallback
    }

    // 3. MESSAGE: API handles hashing, length is arbitrary
    if (contains(@"Message")) {
        return generate_test_data(arc4random_uniform(16385));
    }

    // 4. ENCRYPTION
    if (contains(@"Encryption")) {
        // GCM / ECIES accept arbitrary lengths
        if (contains(@"AESGCM")) {
            return generate_test_data(arc4random_uniform(16385));
        }
        // Classic RSA limits length based on padding (1 byte is always safe)
        return generate_test_data(1);
    }

    // Generic fallback
    return generate_test_data(32);
}

void run_algorithm_tests(SecKeyRef privateKey, SecKeyRef publicKey, int threadID) {
    // --- 1. SIGNATURE ALGORITHMS ---
    NSArray *signAlgorithms = @[
        // RSA Raw & PKCS1v15
        (__bridge id)kSecKeyAlgorithmRSASignatureRaw,
        (__bridge id)kSecKeyAlgorithmRSASignatureDigestPKCS1v15Raw,
        (__bridge id)kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1,
        (__bridge id)kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA224,
        (__bridge id)kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256,
        (__bridge id)kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384,
        (__bridge id)kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512,
        (__bridge id)kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA1,
        (__bridge id)kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA224,
        (__bridge id)kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256,
        (__bridge id)kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA384,
        (__bridge id)kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512,
        // RSA PSS
        (__bridge id)kSecKeyAlgorithmRSASignatureDigestPSSSHA1,
        (__bridge id)kSecKeyAlgorithmRSASignatureDigestPSSSHA224,
        (__bridge id)kSecKeyAlgorithmRSASignatureDigestPSSSHA256,
        (__bridge id)kSecKeyAlgorithmRSASignatureDigestPSSSHA384,
        (__bridge id)kSecKeyAlgorithmRSASignatureDigestPSSSHA512,
        (__bridge id)kSecKeyAlgorithmRSASignatureMessagePSSSHA1,
        (__bridge id)kSecKeyAlgorithmRSASignatureMessagePSSSHA224,
        (__bridge id)kSecKeyAlgorithmRSASignatureMessagePSSSHA256,
        (__bridge id)kSecKeyAlgorithmRSASignatureMessagePSSSHA384,
        (__bridge id)kSecKeyAlgorithmRSASignatureMessagePSSSHA512,
        // ECDSA
        (__bridge id)kSecKeyAlgorithmECDSASignatureDigestX962,
        (__bridge id)kSecKeyAlgorithmECDSASignatureDigestX962SHA1,
        (__bridge id)kSecKeyAlgorithmECDSASignatureDigestX962SHA224,
        (__bridge id)kSecKeyAlgorithmECDSASignatureDigestX962SHA256,
        (__bridge id)kSecKeyAlgorithmECDSASignatureDigestX962SHA384,
        (__bridge id)kSecKeyAlgorithmECDSASignatureDigestX962SHA512,
        (__bridge id)kSecKeyAlgorithmECDSASignatureMessageX962SHA1,
        (__bridge id)kSecKeyAlgorithmECDSASignatureMessageX962SHA224,
        (__bridge id)kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
        (__bridge id)kSecKeyAlgorithmECDSASignatureMessageX962SHA384,
        (__bridge id)kSecKeyAlgorithmECDSASignatureMessageX962SHA512,
        (__bridge id)kSecKeyAlgorithmECDSASignatureDigestRFC4754,
        (__bridge id)kSecKeyAlgorithmECDSASignatureDigestRFC4754SHA1,
        (__bridge id)kSecKeyAlgorithmECDSASignatureDigestRFC4754SHA224,
        (__bridge id)kSecKeyAlgorithmECDSASignatureDigestRFC4754SHA256,
        (__bridge id)kSecKeyAlgorithmECDSASignatureDigestRFC4754SHA384,
        (__bridge id)kSecKeyAlgorithmECDSASignatureDigestRFC4754SHA512,
        (__bridge id)kSecKeyAlgorithmECDSASignatureMessageRFC4754SHA1,
        (__bridge id)kSecKeyAlgorithmECDSASignatureMessageRFC4754SHA224,
        (__bridge id)kSecKeyAlgorithmECDSASignatureMessageRFC4754SHA256,
        (__bridge id)kSecKeyAlgorithmECDSASignatureMessageRFC4754SHA384,
        (__bridge id)kSecKeyAlgorithmECDSASignatureMessageRFC4754SHA512,
    ];

    for (id algoId in signAlgorithms) {
        SecKeyAlgorithm algo = (__bridge SecKeyAlgorithm)algoId;
        if (SecKeyIsAlgorithmSupported(privateKey, kSecKeyOperationTypeSign, algo)) {
            NSData *plainText = prepare_input_for_algorithm(algo, privateKey);
            CFErrorRef error = NULL;
            BOOL valid = NO;

            CFDataRef signature = SecKeyCreateSignature(privateKey, algo, (__bridge CFDataRef)plainText, &error);
            if (signature) {
                valid = SecKeyVerifySignature(publicKey, algo, (__bridge CFDataRef)plainText, signature, &error);
                CFRelease(signature);
            }
            print_test_result([(__bridge NSString *)algo UTF8String], valid, error, threadID);
            if (error) CFRelease(error);
        }
    }

    // --- 2. ENCRYPTION ALGORITHMS ---
    NSArray *encryptAlgorithms = @[
        // RSA
        (__bridge id)kSecKeyAlgorithmRSAEncryptionRaw,
        (__bridge id)kSecKeyAlgorithmRSAEncryptionPKCS1,
        (__bridge id)kSecKeyAlgorithmRSAEncryptionOAEPSHA1,
        (__bridge id)kSecKeyAlgorithmRSAEncryptionOAEPSHA224,
        (__bridge id)kSecKeyAlgorithmRSAEncryptionOAEPSHA256,
        (__bridge id)kSecKeyAlgorithmRSAEncryptionOAEPSHA384,
        (__bridge id)kSecKeyAlgorithmRSAEncryptionOAEPSHA512,
        (__bridge id)kSecKeyAlgorithmRSAEncryptionOAEPSHA1AESGCM,
        (__bridge id)kSecKeyAlgorithmRSAEncryptionOAEPSHA224AESGCM,
        (__bridge id)kSecKeyAlgorithmRSAEncryptionOAEPSHA256AESGCM,
        (__bridge id)kSecKeyAlgorithmRSAEncryptionOAEPSHA384AESGCM,
        (__bridge id)kSecKeyAlgorithmRSAEncryptionOAEPSHA512AESGCM,
        // ECIES
        (__bridge id)kSecKeyAlgorithmECIESEncryptionStandardX963SHA1AESGCM,
        (__bridge id)kSecKeyAlgorithmECIESEncryptionStandardX963SHA224AESGCM,
        (__bridge id)kSecKeyAlgorithmECIESEncryptionStandardX963SHA256AESGCM,
        (__bridge id)kSecKeyAlgorithmECIESEncryptionStandardX963SHA384AESGCM,
        (__bridge id)kSecKeyAlgorithmECIESEncryptionStandardX963SHA512AESGCM,
        (__bridge id)kSecKeyAlgorithmECIESEncryptionCofactorX963SHA1AESGCM,
        (__bridge id)kSecKeyAlgorithmECIESEncryptionCofactorX963SHA224AESGCM,
        (__bridge id)kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM,
        (__bridge id)kSecKeyAlgorithmECIESEncryptionCofactorX963SHA384AESGCM,
        (__bridge id)kSecKeyAlgorithmECIESEncryptionCofactorX963SHA512AESGCM,
        (__bridge id)kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA224AESGCM,
        (__bridge id)kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA256AESGCM,
        (__bridge id)kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA384AESGCM,
        (__bridge id)kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA512AESGCM,
        (__bridge id)kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA224AESGCM,
        (__bridge id)kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM,
        (__bridge id)kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA384AESGCM,
        (__bridge id)kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA512AESGCM
    ];

    for (id algoId in encryptAlgorithms) {
        SecKeyAlgorithm algo = (__bridge SecKeyAlgorithm)algoId;
        if (SecKeyIsAlgorithmSupported(privateKey, kSecKeyOperationTypeDecrypt, algo)) {
            NSData *plainText = prepare_input_for_algorithm(algo, privateKey);
            CFErrorRef error = NULL;
            BOOL valid = NO;

            CFDataRef cipherText = SecKeyCreateEncryptedData(publicKey, algo, (__bridge CFDataRef)plainText, &error);
            if (cipherText) {
                CFDataRef decrypted = SecKeyCreateDecryptedData(privateKey, algo, cipherText, &error);
                if (decrypted) {
                    valid = [plainText isEqualToData:(__bridge NSData *)decrypted];
                    CFRelease(decrypted);
                }
                CFRelease(cipherText);
            }
            print_test_result([(__bridge NSString *)algo UTF8String], valid, error, threadID);
            if (error) CFRelease(error);
        }
    }

    // --- 3. KEY EXCHANGE ALGORITHMS (ECDH) ---
    NSArray *exchangeAlgorithms = @[
        (__bridge id)kSecKeyAlgorithmECDHKeyExchangeCofactor,
        (__bridge id)kSecKeyAlgorithmECDHKeyExchangeStandard,
        /*
        (__bridge id)kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA224,
        (__bridge id)kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA256,
        (__bridge id)kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA384,
        (__bridge id)kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA512,
        (__bridge id)kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA1,
        (__bridge id)kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA224,
        (__bridge id)kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA256,
        (__bridge id)kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA384,
        (__bridge id)kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA512
        */
    ];

    for (id algoId in exchangeAlgorithms) {
        SecKeyAlgorithm algo = (__bridge SecKeyAlgorithm)algoId;
        if (SecKeyIsAlgorithmSupported(privateKey, kSecKeyOperationTypeKeyExchange, algo)) {
            CFErrorRef error = NULL;
            NSMutableDictionary *parameters = nil;

            if ([(__bridge NSString *)algo containsString:@"X963SHA"]) {
                parameters = [NSMutableDictionary dictionary];
                parameters[(__bridge NSString *)kSecKeyKeyExchangeParameterRequestedSize] = @(32);
            }

            CFDataRef sharedSecret = SecKeyCopyKeyExchangeResult(privateKey, algo, publicKey, (__bridge CFDictionaryRef)parameters, &error);
            BOOL valid = (sharedSecret != NULL);

            print_test_result([(__bridge NSString *)algo UTF8String], valid, error, threadID);

            if (sharedSecret) CFRelease(sharedSecret);
            if (error) CFRelease(error);
        }
    }
}

NSString* make_safe_filename(NSString *input) {
    if (!input || input.length == 0) return @"Unknown_Identity";

    NSMutableCharacterSet *allowedChars = [NSMutableCharacterSet alphanumericCharacterSet];
    [allowedChars addCharactersInString:@"_-"];

    NSCharacterSet *forbiddenChars = [allowedChars invertedSet];
    NSArray *parts = [input componentsSeparatedByCharactersInSet:forbiddenChars];
    NSString *combined = [parts componentsJoinedByString:@"_"];

    // Truncate if filename is too long
    if (combined.length > 64) {
        combined = [combined substringToIndex:64];
    }
    return combined;
}

void display_identity_details(SecCertificateRef cert, id accessControl) {

    if (accessControl) {
        printf("  X.509 Identity:  %s\n", [[accessControl description] UTF8String]);
    } else {
        printf("  X.509 Identity:\n");
    }

    // 1. Extract Subject
    NSString *subject = (__bridge_transfer NSString *)SecCertificateCopySubjectSummary(cert);
    printf("    Subject:          %s\n", subject ? [subject UTF8String] : "Unknown");

    // 2. Extract Issuer, Serial Number and Validity via native Key-Value query
    CFArrayRef keys = (__bridge CFArrayRef)@[
        (__bridge id)kSecOIDX509V1IssuerName,
        (__bridge id)kSecOIDX509V1SerialNumber,
        (__bridge id)kSecOIDX509V1ValidityNotAfter,
        (__bridge id)kSecOIDX509V1ValidityNotBefore
    ];

    CFDictionaryRef values = SecCertificateCopyValues(cert, keys, NULL);
    if (values) {
        CFDictionaryRef issuerDict = CFDictionaryGetValue(values, kSecOIDX509V1IssuerName);
        if (issuerDict) {
            id issuerValue = (__bridge id)CFDictionaryGetValue(issuerDict, kSecPropertyKeyValue);
            NSString *compactIssuer = nil;

            if ([issuerValue isKindOfClass:[NSArray class]]) {
                NSString *backupOrganization = nil;

                // Iterate directly over the flat array of dictionaries
                for (id component in (NSArray *)issuerValue) {
                    if ([component isKindOfClass:[NSDictionary class]]) {
                        NSString *label = [component[@"label"] description];
                        NSString *value = [component[@"value"] description];

                        // Find Common Name (2.5.4.3)
                        if ([label isEqualToString:@"2.5.4.3"]) {
                            compactIssuer = value;
                            break;
                        }
                        // Find Organization (2.5.4.10) as backup
                        if ([label isEqualToString:@"2.5.4.10"]) {
                            backupOrganization = value;
                        }
                    }
                }

                // Fallback to Organization if CN is missing
                if (!compactIssuer) {
                    compactIssuer = backupOrganization ?: @"Unknown CA";
                }
            } else {
                compactIssuer = [issuerValue description];
            }

            printf("    Issuer:           %s\n", [compactIssuer UTF8String]);
        } else {
            printf("    Issuer:           Unknown\n");
        }

        // Extract Serial Number
        CFDictionaryRef serialDict = CFDictionaryGetValue(values, kSecOIDX509V1SerialNumber);
        if (serialDict) {
            id serialValue = (__bridge id)CFDictionaryGetValue(serialDict, kSecPropertyKeyValue);
            if ([serialValue isKindOfClass:[NSData class]]) {
                NSData *serialData = (NSData *)serialValue;
                NSMutableString *serialStr = [NSMutableString stringWithCapacity:serialData.length * 2];
                const unsigned char *bytes = serialData.bytes;
                for (NSUInteger i = 0; i < serialData.length; i++) {
                    [serialStr appendFormat:@"%02X", bytes[i]];
                }
                printf("    Serial Number:    %s\n", [serialStr UTF8String]);
            } else {
                printf("    Serial Number:    %s\n", [[serialValue description] UTF8String]);
            }
        }

        // Extract Start Date
        CFDictionaryRef notBeforeDict = CFDictionaryGetValue(values, kSecOIDX509V1ValidityNotBefore);
        if (notBeforeDict) {
            id dateValue = (__bridge id)CFDictionaryGetValue(notBeforeDict, kSecPropertyKeyValue);
            if ([dateValue isKindOfClass:[NSNumber class]]) {
                NSDate *startDate = [NSDate dateWithTimeIntervalSinceReferenceDate:[dateValue doubleValue]];
                printf("    Valid From:       %s\n", [[startDate description] UTF8String]);
            } else {
                printf("    Valid From:       %s\n", [[dateValue description] UTF8String]);
            }
        }

        // Extract Expiry Date
        CFDictionaryRef notAfterDict = CFDictionaryGetValue(values, kSecOIDX509V1ValidityNotAfter);
        if (notAfterDict) {
            id dateValue = (__bridge id)CFDictionaryGetValue(notAfterDict, kSecPropertyKeyValue);
            if ([dateValue isKindOfClass:[NSNumber class]]) {
                NSDate *expiryDate = [NSDate dateWithTimeIntervalSinceReferenceDate:[dateValue doubleValue]];
                printf("    Valid Until:      %s\n", [[expiryDate description] UTF8String]);
            } else {
                printf("    Valid Until:      %s\n", [[dateValue description] UTF8String]);
            }
        }
        CFRelease(values);
    }

    // 3. Extract Public Key details
    SecKeyRef publicKey = SecCertificateCopyKey(cert);
    if (publicKey) {
        CFDictionaryRef attributes = SecKeyCopyAttributes(publicKey);
        if (attributes) {
            NSString *keyType = (__bridge NSString *)CFDictionaryGetValue(attributes, kSecAttrKeyType);
            NSNumber *keySize = (__bridge NSNumber *)CFDictionaryGetValue(attributes, kSecAttrKeySizeInBits);

            NSString *humanType = @"Unknown";
            if ([keyType isEqualToString:(__bridge NSString *)kSecAttrKeyTypeRSA]) humanType = @"RSA";
            if ([keyType isEqualToString:(__bridge NSString *)kSecAttrKeyTypeECSECPrimeRandom]) humanType = @"ECC";

            printf("    Public Key Type:  %s (%d bits)\n", [humanType UTF8String], [keySize intValue]);
            CFRelease(attributes);
        }
        CFRelease(publicKey);
    }
}

BOOL export_certificate(SecCertificateRef cert, NSString *targetDirectory, BOOL asPEM) {
    // Derive base filename from subject
    NSString *subject = (__bridge_transfer NSString *)SecCertificateCopySubjectSummary(cert);
    NSString *safeSubject = make_safe_filename(subject);

    CFDataRef derDataRef = SecCertificateCopyData(cert);
    if (!derDataRef) return NO;
    NSData *certData = (__bridge NSData *)derDataRef;

    // Ensure uniqueness by appending data hash
    NSUInteger dataHash = [certData hash];
    NSString *filename = [NSString stringWithFormat:@"%@_%lX", safeSubject, (unsigned long)dataHash];
    NSString *extension = asPEM ? @"pem" : @"cer";
    NSString *fullPath = [[targetDirectory stringByAppendingPathComponent:filename] stringByAppendingPathExtension:extension];

    // Apply PEM formatting if requested
    if (asPEM) {
        NSString *base64String = [certData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
        NSString *pemString = [NSString stringWithFormat:@"-----BEGIN CERTIFICATE-----\n%@\n-----END CERTIFICATE-----\n", base64String];
        certData = [pemString dataUsingEncoding:NSUTF8StringEncoding];
    }

    // Write file
    NSError *error = nil;
    BOOL success = [certData writeToFile:fullPath options:NSDataWritingAtomic error:&error];
    CFRelease(derDataRef);

    if (success) {
        printf("    Exported to:      %s\n", [fullPath UTF8String]);
    } else {
        printf("    Export failed:    %s\n", [[error localizedDescription] UTF8String]);
    }

    return success;
}

void list_objects(BOOL exportCerts, BOOL asPEM) {

    TKTokenWatcher *watcher = [[TKTokenWatcher alloc] init];
    NSArray<NSString *> *tokenIDs = watcher.tokenIDs;

    if (tokenIDs.count == 0) {
        printf("No hardware tokens (smart cards) found by CryptoTokenKit.\n");
        return;
    }

    for (NSString *tokenID in tokenIDs) {
        printf("Token ID:  %s\n", [tokenID UTF8String]);

        NSDictionary *identityQuery = @{
            (__bridge id)kSecClass: (__bridge id)kSecClassIdentity,
            (__bridge id)kSecAttrTokenID: tokenID,
            (__bridge id)kSecReturnRef: @YES,
            (__bridge id)kSecReturnAttributes: @YES,
            (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll
        };

        CFTypeRef identityResult = NULL;
        OSStatus identityStatus = SecItemCopyMatching((__bridge CFDictionaryRef)identityQuery, &identityResult);

        if (identityStatus == errSecSuccess) {
            NSArray *identities = (__bridge_transfer NSArray *)identityResult;
            for (NSDictionary *item in identities) {
                SecIdentityRef identity = (__bridge SecIdentityRef)item[(__bridge id)kSecValueRef];
                id accessControl = item[(__bridge id)kSecAttrAccessControl];

                SecCertificateRef cert = NULL;
                SecIdentityCopyCertificate(identity, &cert);

                if (cert) {
                    display_identity_details(cert, accessControl);

                    if (exportCerts) {
                        NSString *currentDir = [[NSFileManager defaultManager] currentDirectoryPath];
                        export_certificate(cert, currentDir, asPEM);
                    }

                    CFRelease(cert);
                }
            }
        } else if (identityStatus != errSecItemNotFound) {
            printf("  No identities found on this token (Status: %d)\n", (int)identityStatus);
        }

        // Fetching attributes only to keep listing non-interactive (prevents unwanted PIN prompts)
        NSDictionary *passwordQuery = @{
            (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
            (__bridge id)kSecAttrTokenID: tokenID,
            (__bridge id)kSecReturnAttributes: @YES,
            (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll
        };

        CFTypeRef passwordResult = NULL;
        OSStatus passwordStatus = SecItemCopyMatching((__bridge CFDictionaryRef)passwordQuery, &passwordResult);

        if (passwordStatus == errSecSuccess) {
            NSArray *passwordItems = (__bridge_transfer NSArray *)passwordResult;

            for (NSDictionary *pwdItem in passwordItems) {
                NSString *label = pwdItem[(__bridge id)kSecAttrLabel] ?: @"None";
                NSString *service = pwdItem[(__bridge id)kSecAttrService] ?: @"None";
                NSString *account = pwdItem[(__bridge id)kSecAttrAccount] ?: @"None";
                id pwdAccessControl = pwdItem[(__bridge id)kSecAttrAccessControl];

                if (pwdAccessControl) {
                    printf("  Generic Object:     %s\n", [[pwdAccessControl description] UTF8String]);
                } else {
                    printf("  Generic Object:\n");
                }
                printf("    Label:            %s\n", [label UTF8String]);
                printf("    Service/Type:     %s\n", [service UTF8String]);
                printf("    Account/ID:       %s\n", [account UTF8String]);
            }
            printf("    ------------------------------------------\n\n");
        } else if (passwordStatus != errSecItemNotFound) {
            printf("  Error querying generic passwords (Status: %d)\n", (int)passwordStatus);
        }

        if (identityStatus == errSecItemNotFound && passwordStatus == errSecItemNotFound) {
            printf("  No objects (Identities or Generic Objects) found on this token.\n");
        }
    }
}

void test_tokens(int numThreads) {

    TKTokenWatcher *watcher = [[TKTokenWatcher alloc] init];
    NSArray<NSString *> *tokenIDs = watcher.tokenIDs;

    if (tokenIDs.count == 0) {
        printf("No hardware tokens (smart cards) found by CryptoTokenKit.\n");
        return;
    }

    int slot = 0;
    for (NSString *tokenID in tokenIDs) {
        printf("Token ID:  %s\n", [tokenID UTF8String]);

        NSDictionary *query = @{
            (__bridge id)kSecClass: (__bridge id)kSecClassKey,
            (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPrivate,
            (__bridge id)kSecAttrTokenID: tokenID,
            (__bridge id)kSecReturnRef: @YES,
            (__bridge id)kSecReturnAttributes: @YES,
            (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll
        };

        CFTypeRef result = NULL;
        OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);

        if (status != errSecSuccess) {
            printf("  No private keys found on this token (Status: %d)\n", (int)status);
            continue;
        }

        NSArray *keys = (__bridge_transfer NSArray *)result;
        for (NSDictionary *item in keys) {
            SecKeyRef privateKey = (__bridge SecKeyRef)(item[(__bridge id)kSecValueRef]);
            SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);

            NSString *label = item[(__bridge id)kSecAttrLabel] ?: @"Unknown Label";
            id keyType = item[(__bridge id)kSecAttrKeyType];
            NSNumber *keySize = item[(__bridge id)kSecAttrKeySizeInBits];

            NSString *keyTypeStr = [keyType description];
            NSString *humanReadableType = @"Unknown";

            if ([keyTypeStr isEqualToString:(__bridge NSString *)kSecAttrKeyTypeRSA]) humanReadableType = @"RSA";
            if ([keyTypeStr isEqualToString:(__bridge NSString *)kSecAttrKeyTypeECSECPrimeRandom]) humanReadableType = @"ECC";

            printf("  Private Key:  %s\n", [label UTF8String]);
            printf("    Type:   %s (%d bits)\n", [humanReadableType UTF8String], [keySize intValue]);

            if (!publicKey) {
                printf("    Error:  Could not extract public key for verification.\n");
                continue;
            }

            dispatch_group_t testGroup = dispatch_group_create();
            dispatch_queue_t concurrentQueue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0);
            CFAbsoluteTime startTime = CFAbsoluteTimeGetCurrent();
            for (int i = 1; i <= numThreads; i++) {
                int currentThreadID = i;
                dispatch_group_async(testGroup, concurrentQueue, ^{
                    run_algorithm_tests(privateKey, publicKey, currentThreadID);
                });
            }
            dispatch_group_wait(testGroup, DISPATCH_TIME_FOREVER);
            CFAbsoluteTime endTime = CFAbsoluteTimeGetCurrent();
            CFAbsoluteTime executionTime = endTime - startTime;

            printf("  Done in %.4f seconds, running in %d thread%s\n", executionTime, numThreads, numThreads > 1 ? "s" : "");

            if (publicKey) CFRelease(publicKey);
        }
    }
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        struct gengetopt_args_info args_info;

        // Parse command line using generated parser
        if (cmdline_parser(argc, argv, &args_info) != 0) {
            return 1;
        }

        BOOL doList = args_info.list_objects_flag || args_info.export_certificates_flag;
        BOOL doTest = args_info.test_flag;

        if (!doList && !doTest) {
            printf("Please specify an action: --test or --list-objects\n");
            cmdline_parser_print_help();
            cmdline_parser_free(&args_info);
            return 1;
        }

        if (doList) {
            BOOL exportCerts = args_info.export_certificates_flag;
            BOOL asPEM = YES; // Default

            // Check formatted string if set
            if (args_info.certificate_format_orig && strcasecmp(args_info.certificate_format_orig, "DER") == 0) {
                asPEM = NO;
            }

            list_objects(exportCerts, asPEM);
        }

        if (doTest) {
            numThreads = args_info.test_threads_arg;
            if (numThreads < 1) numThreads = 1; // Fallback to 1 thread
            test_tokens(numThreads);
        }

        cmdline_parser_free(&args_info);
    }
    return 0;
}
