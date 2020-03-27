//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/generators/X448KeyPairGenerator.java
//

#ifndef X448KeyPairGenerator_H
#define X448KeyPairGenerator_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "AsymmetricCipherKeyPairGenerator.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleCryptoAsymmetricCipherKeyPair;
@class LibOrgBouncycastleCryptoKeyGenerationParameters;

@interface LibOrgBouncycastleCryptoGeneratorsX448KeyPairGenerator : NSObject < LibOrgBouncycastleCryptoAsymmetricCipherKeyPairGenerator >

#pragma mark Public

- (instancetype __nonnull)init;

- (LibOrgBouncycastleCryptoAsymmetricCipherKeyPair *)generateKeyPair;

- (void)init__WithLibOrgBouncycastleCryptoKeyGenerationParameters:(LibOrgBouncycastleCryptoKeyGenerationParameters *)parameters OBJC_METHOD_FAMILY_NONE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoGeneratorsX448KeyPairGenerator)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoGeneratorsX448KeyPairGenerator_init(LibOrgBouncycastleCryptoGeneratorsX448KeyPairGenerator *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoGeneratorsX448KeyPairGenerator *new_LibOrgBouncycastleCryptoGeneratorsX448KeyPairGenerator_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoGeneratorsX448KeyPairGenerator *create_LibOrgBouncycastleCryptoGeneratorsX448KeyPairGenerator_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoGeneratorsX448KeyPairGenerator)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // X448KeyPairGenerator_H
