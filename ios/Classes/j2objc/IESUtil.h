//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/util/IESUtil.java
//

#ifndef IESUtil_H
#define IESUtil_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class LibOrgBouncycastleCryptoBufferedBlockCipher;
@class LibOrgBouncycastleJceSpecIESParameterSpec;

@interface LibOrgBouncycastleJcajceProviderAsymmetricUtilIESUtil : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

+ (LibOrgBouncycastleJceSpecIESParameterSpec *)guessParameterSpecWithLibOrgBouncycastleCryptoBufferedBlockCipher:(LibOrgBouncycastleCryptoBufferedBlockCipher *)iesBlockCipher
                                                                                                   withByteArray:(IOSByteArray *)nonce;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricUtilIESUtil)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricUtilIESUtil_init(LibOrgBouncycastleJcajceProviderAsymmetricUtilIESUtil *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricUtilIESUtil *new_LibOrgBouncycastleJcajceProviderAsymmetricUtilIESUtil_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricUtilIESUtil *create_LibOrgBouncycastleJcajceProviderAsymmetricUtilIESUtil_init(void);

FOUNDATION_EXPORT LibOrgBouncycastleJceSpecIESParameterSpec *LibOrgBouncycastleJcajceProviderAsymmetricUtilIESUtil_guessParameterSpecWithLibOrgBouncycastleCryptoBufferedBlockCipher_withByteArray_(LibOrgBouncycastleCryptoBufferedBlockCipher *iesBlockCipher, IOSByteArray *nonce);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricUtilIESUtil)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // IESUtil_H
