//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/ntru/NTRUEncryptionKeyPairGenerator.java
//

#ifndef NTRUEncryptionKeyPairGenerator_H
#define NTRUEncryptionKeyPairGenerator_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "AsymmetricCipherKeyPairGenerator.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleCryptoAsymmetricCipherKeyPair;
@class LibOrgBouncycastleCryptoKeyGenerationParameters;

@interface LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionKeyPairGenerator : NSObject < LibOrgBouncycastleCryptoAsymmetricCipherKeyPairGenerator >

#pragma mark Public

- (instancetype __nonnull)init;

- (LibOrgBouncycastleCryptoAsymmetricCipherKeyPair *)generateKeyPair;

- (void)init__WithLibOrgBouncycastleCryptoKeyGenerationParameters:(LibOrgBouncycastleCryptoKeyGenerationParameters *)param OBJC_METHOD_FAMILY_NONE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionKeyPairGenerator)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionKeyPairGenerator_init(LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionKeyPairGenerator *self);

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionKeyPairGenerator *new_LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionKeyPairGenerator_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionKeyPairGenerator *create_LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionKeyPairGenerator_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionKeyPairGenerator)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // NTRUEncryptionKeyPairGenerator_H