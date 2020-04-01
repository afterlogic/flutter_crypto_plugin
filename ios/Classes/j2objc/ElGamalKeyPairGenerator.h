//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/generators/ElGamalKeyPairGenerator.java
//

#ifndef ElGamalKeyPairGenerator_H
#define ElGamalKeyPairGenerator_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "AsymmetricCipherKeyPairGenerator.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleCryptoAsymmetricCipherKeyPair;
@class LibOrgBouncycastleCryptoKeyGenerationParameters;

@interface LibOrgBouncycastleCryptoGeneratorsElGamalKeyPairGenerator : NSObject < LibOrgBouncycastleCryptoAsymmetricCipherKeyPairGenerator >

#pragma mark Public

- (instancetype __nonnull)init;

- (LibOrgBouncycastleCryptoAsymmetricCipherKeyPair *)generateKeyPair;

- (void)init__WithLibOrgBouncycastleCryptoKeyGenerationParameters:(LibOrgBouncycastleCryptoKeyGenerationParameters *)param OBJC_METHOD_FAMILY_NONE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoGeneratorsElGamalKeyPairGenerator)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoGeneratorsElGamalKeyPairGenerator_init(LibOrgBouncycastleCryptoGeneratorsElGamalKeyPairGenerator *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoGeneratorsElGamalKeyPairGenerator *new_LibOrgBouncycastleCryptoGeneratorsElGamalKeyPairGenerator_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoGeneratorsElGamalKeyPairGenerator *create_LibOrgBouncycastleCryptoGeneratorsElGamalKeyPairGenerator_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoGeneratorsElGamalKeyPairGenerator)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ElGamalKeyPairGenerator_H