//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/ExchangePairGenerator.java
//

#ifndef ExchangePairGenerator_H
#define ExchangePairGenerator_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;
@class LibOrgBouncycastlePqcCryptoExchangePair;

@protocol LibOrgBouncycastlePqcCryptoExchangePairGenerator < JavaObject >

- (LibOrgBouncycastlePqcCryptoExchangePair *)GenerateExchangeWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)senderPublicKey;

- (LibOrgBouncycastlePqcCryptoExchangePair *)generateExchangeWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)senderPublicKey;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcCryptoExchangePairGenerator)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcCryptoExchangePairGenerator)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ExchangePairGenerator_H
