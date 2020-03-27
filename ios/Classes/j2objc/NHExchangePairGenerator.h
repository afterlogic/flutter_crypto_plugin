//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/newhope/NHExchangePairGenerator.java
//

#ifndef NHExchangePairGenerator_H
#define NHExchangePairGenerator_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ExchangePairGenerator.h"
#include "J2ObjC_header.h"

@class JavaSecuritySecureRandom;
@class LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;
@class LibOrgBouncycastlePqcCryptoExchangePair;

@interface LibOrgBouncycastlePqcCryptoNewhopeNHExchangePairGenerator : NSObject < LibOrgBouncycastlePqcCryptoExchangePairGenerator >

#pragma mark Public

- (instancetype __nonnull)initWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

- (LibOrgBouncycastlePqcCryptoExchangePair *)GenerateExchangeWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)senderPublicKey;

- (LibOrgBouncycastlePqcCryptoExchangePair *)generateExchangeWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)senderPublicKey;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcCryptoNewhopeNHExchangePairGenerator)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoNewhopeNHExchangePairGenerator_initWithJavaSecuritySecureRandom_(LibOrgBouncycastlePqcCryptoNewhopeNHExchangePairGenerator *self, JavaSecuritySecureRandom *random);

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoNewhopeNHExchangePairGenerator *new_LibOrgBouncycastlePqcCryptoNewhopeNHExchangePairGenerator_initWithJavaSecuritySecureRandom_(JavaSecuritySecureRandom *random) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoNewhopeNHExchangePairGenerator *create_LibOrgBouncycastlePqcCryptoNewhopeNHExchangePairGenerator_initWithJavaSecuritySecureRandom_(JavaSecuritySecureRandom *random);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcCryptoNewhopeNHExchangePairGenerator)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // NHExchangePairGenerator_H