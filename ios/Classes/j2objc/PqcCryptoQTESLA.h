//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/qtesla/PqcCryptoQTESLA.java
//

#ifndef PqcCryptoQTESLA_H
#define PqcCryptoQTESLA_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class JavaSecuritySecureRandom;

@interface LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQTESLA : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

+ (jint)generateKeyPairIWithByteArray:(IOSByteArray *)publicKey
                        withByteArray:(IOSByteArray *)privateKey
         withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)secureRandom;

+ (jint)generateKeyPairIIIPWithByteArray:(IOSByteArray *)publicKey
                           withByteArray:(IOSByteArray *)privateKey
            withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)secureRandom;

+ (jint)generateKeyPairIIISizeWithByteArray:(IOSByteArray *)publicKey
                              withByteArray:(IOSByteArray *)privateKey
               withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)secureRandom;

+ (jint)generateKeyPairIIISpeedWithByteArray:(IOSByteArray *)publicKey
                               withByteArray:(IOSByteArray *)privateKey
                withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)secureRandom;

+ (jint)generateKeyPairIPWithByteArray:(IOSByteArray *)publicKey
                         withByteArray:(IOSByteArray *)privateKey
          withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)secureRandom;

+ (jint)signingIIIPWithByteArray:(IOSByteArray *)signature
                   withByteArray:(IOSByteArray *)message
                         withInt:(jint)messageOffset
                         withInt:(jint)messageLength
                   withByteArray:(IOSByteArray *)privateKey
    withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)secureRandom;

+ (jint)signingIPWithByteArray:(IOSByteArray *)signature
                 withByteArray:(IOSByteArray *)message
                       withInt:(jint)messageOffset
                       withInt:(jint)messageLength
                 withByteArray:(IOSByteArray *)privateKey
  withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)secureRandom;

#pragma mark Package-Private

+ (jint)signingIWithByteArray:(IOSByteArray *)signature
                withByteArray:(IOSByteArray *)message
                      withInt:(jint)messageOffset
                      withInt:(jint)messageLength
                withByteArray:(IOSByteArray *)privateKey
 withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)secureRandom;

+ (jint)signingIIISizeWithByteArray:(IOSByteArray *)signature
                      withByteArray:(IOSByteArray *)message
                            withInt:(jint)messageOffset
                            withInt:(jint)messageLength
                      withByteArray:(IOSByteArray *)privateKey
       withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)secureRandom;

+ (jint)signingIIISpeedWithByteArray:(IOSByteArray *)signature
                       withByteArray:(IOSByteArray *)message
                             withInt:(jint)messageOffset
                             withInt:(jint)messageLength
                       withByteArray:(IOSByteArray *)privateKey
        withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)secureRandom;

+ (jint)verifyingIWithByteArray:(IOSByteArray *)message
                  withByteArray:(IOSByteArray *)signature
                        withInt:(jint)signatureOffset
                        withInt:(jint)signatureLength
                  withByteArray:(IOSByteArray *)publicKey;

+ (jint)verifyingIIISizeWithByteArray:(IOSByteArray *)message
                        withByteArray:(IOSByteArray *)signature
                              withInt:(jint)signatureOffset
                              withInt:(jint)signatureLength
                        withByteArray:(IOSByteArray *)publicKey;

+ (jint)verifyingIIISpeedWithByteArray:(IOSByteArray *)message
                         withByteArray:(IOSByteArray *)signature
                               withInt:(jint)signatureOffset
                               withInt:(jint)signatureLength
                         withByteArray:(IOSByteArray *)publicKey;

+ (jint)verifyingPIWithByteArray:(IOSByteArray *)message
                   withByteArray:(IOSByteArray *)signature
                         withInt:(jint)signatureOffset
                         withInt:(jint)signatureLength
                   withByteArray:(IOSByteArray *)publicKey;

+ (jint)verifyingPIIIWithByteArray:(IOSByteArray *)message
                     withByteArray:(IOSByteArray *)signature
                           withInt:(jint)signatureOffset
                           withInt:(jint)signatureLength
                     withByteArray:(IOSByteArray *)publicKey;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQTESLA)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQTESLA_init(LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQTESLA *self);

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQTESLA *new_LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQTESLA_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQTESLA *create_LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQTESLA_init(void);

FOUNDATION_EXPORT jint LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQTESLA_generateKeyPairIWithByteArray_withByteArray_withJavaSecuritySecureRandom_(IOSByteArray *publicKey, IOSByteArray *privateKey, JavaSecuritySecureRandom *secureRandom);

FOUNDATION_EXPORT jint LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQTESLA_generateKeyPairIIISizeWithByteArray_withByteArray_withJavaSecuritySecureRandom_(IOSByteArray *publicKey, IOSByteArray *privateKey, JavaSecuritySecureRandom *secureRandom);

FOUNDATION_EXPORT jint LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQTESLA_generateKeyPairIIISpeedWithByteArray_withByteArray_withJavaSecuritySecureRandom_(IOSByteArray *publicKey, IOSByteArray *privateKey, JavaSecuritySecureRandom *secureRandom);

FOUNDATION_EXPORT jint LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQTESLA_generateKeyPairIPWithByteArray_withByteArray_withJavaSecuritySecureRandom_(IOSByteArray *publicKey, IOSByteArray *privateKey, JavaSecuritySecureRandom *secureRandom);

FOUNDATION_EXPORT jint LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQTESLA_generateKeyPairIIIPWithByteArray_withByteArray_withJavaSecuritySecureRandom_(IOSByteArray *publicKey, IOSByteArray *privateKey, JavaSecuritySecureRandom *secureRandom);

FOUNDATION_EXPORT jint LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQTESLA_signingIWithByteArray_withByteArray_withInt_withInt_withByteArray_withJavaSecuritySecureRandom_(IOSByteArray *signature, IOSByteArray *message, jint messageOffset, jint messageLength, IOSByteArray *privateKey, JavaSecuritySecureRandom *secureRandom);

FOUNDATION_EXPORT jint LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQTESLA_signingIIISizeWithByteArray_withByteArray_withInt_withInt_withByteArray_withJavaSecuritySecureRandom_(IOSByteArray *signature, IOSByteArray *message, jint messageOffset, jint messageLength, IOSByteArray *privateKey, JavaSecuritySecureRandom *secureRandom);

FOUNDATION_EXPORT jint LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQTESLA_signingIIISpeedWithByteArray_withByteArray_withInt_withInt_withByteArray_withJavaSecuritySecureRandom_(IOSByteArray *signature, IOSByteArray *message, jint messageOffset, jint messageLength, IOSByteArray *privateKey, JavaSecuritySecureRandom *secureRandom);

FOUNDATION_EXPORT jint LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQTESLA_signingIPWithByteArray_withByteArray_withInt_withInt_withByteArray_withJavaSecuritySecureRandom_(IOSByteArray *signature, IOSByteArray *message, jint messageOffset, jint messageLength, IOSByteArray *privateKey, JavaSecuritySecureRandom *secureRandom);

FOUNDATION_EXPORT jint LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQTESLA_signingIIIPWithByteArray_withByteArray_withInt_withInt_withByteArray_withJavaSecuritySecureRandom_(IOSByteArray *signature, IOSByteArray *message, jint messageOffset, jint messageLength, IOSByteArray *privateKey, JavaSecuritySecureRandom *secureRandom);

FOUNDATION_EXPORT jint LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQTESLA_verifyingIWithByteArray_withByteArray_withInt_withInt_withByteArray_(IOSByteArray *message, IOSByteArray *signature, jint signatureOffset, jint signatureLength, IOSByteArray *publicKey);

FOUNDATION_EXPORT jint LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQTESLA_verifyingIIISizeWithByteArray_withByteArray_withInt_withInt_withByteArray_(IOSByteArray *message, IOSByteArray *signature, jint signatureOffset, jint signatureLength, IOSByteArray *publicKey);

FOUNDATION_EXPORT jint LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQTESLA_verifyingIIISpeedWithByteArray_withByteArray_withInt_withInt_withByteArray_(IOSByteArray *message, IOSByteArray *signature, jint signatureOffset, jint signatureLength, IOSByteArray *publicKey);

FOUNDATION_EXPORT jint LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQTESLA_verifyingPIWithByteArray_withByteArray_withInt_withInt_withByteArray_(IOSByteArray *message, IOSByteArray *signature, jint signatureOffset, jint signatureLength, IOSByteArray *publicKey);

FOUNDATION_EXPORT jint LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQTESLA_verifyingPIIIWithByteArray_withByteArray_withInt_withInt_withByteArray_(IOSByteArray *message, IOSByteArray *signature, jint signatureOffset, jint signatureLength, IOSByteArray *publicKey);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQTESLA)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PqcCryptoQTESLA_H
