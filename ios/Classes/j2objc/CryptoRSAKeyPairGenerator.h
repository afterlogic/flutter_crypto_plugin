//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/generators/CryptoRSAKeyPairGenerator.java
//

#ifndef CryptoRSAKeyPairGenerator_H
#define CryptoRSAKeyPairGenerator_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "AsymmetricCipherKeyPairGenerator.h"
#include "J2ObjC_header.h"

@class JavaMathBigInteger;
@class LibOrgBouncycastleCryptoAsymmetricCipherKeyPair;
@class LibOrgBouncycastleCryptoKeyGenerationParameters;
@class LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;

@interface LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator : NSObject < LibOrgBouncycastleCryptoAsymmetricCipherKeyPairGenerator >

#pragma mark Public

- (instancetype __nonnull)init;

- (LibOrgBouncycastleCryptoAsymmetricCipherKeyPair *)generateKeyPair;

- (LibOrgBouncycastleCryptoAsymmetricCipherKeyPair *)generateKeyPairWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)publicParam
                                                                    withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)privateParam;

- (void)init__WithLibOrgBouncycastleCryptoKeyGenerationParameters:(LibOrgBouncycastleCryptoKeyGenerationParameters *)param OBJC_METHOD_FAMILY_NONE;

#pragma mark Protected

- (JavaMathBigInteger *)chooseRandomPrimeWithInt:(jint)bitlength
                          withJavaMathBigInteger:(JavaMathBigInteger *)e
                          withJavaMathBigInteger:(JavaMathBigInteger *)sqrdBound;

- (jboolean)isProbablePrimeWithJavaMathBigInteger:(JavaMathBigInteger *)x;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator_init(LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator *new_LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator *create_LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // CryptoRSAKeyPairGenerator_H
