//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/params/GOST3410KeyParameters.java
//

#ifndef GOST3410KeyParameters_H
#define GOST3410KeyParameters_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "AsymmetricKeyParameter.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleCryptoParamsGOST3410Parameters;

@interface LibOrgBouncycastleCryptoParamsGOST3410KeyParameters : LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter

#pragma mark Public

- (instancetype __nonnull)initWithBoolean:(jboolean)isPrivate
withLibOrgBouncycastleCryptoParamsGOST3410Parameters:(LibOrgBouncycastleCryptoParamsGOST3410Parameters *)params;

- (LibOrgBouncycastleCryptoParamsGOST3410Parameters *)getParameters;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithBoolean:(jboolean)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoParamsGOST3410KeyParameters)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoParamsGOST3410KeyParameters_initWithBoolean_withLibOrgBouncycastleCryptoParamsGOST3410Parameters_(LibOrgBouncycastleCryptoParamsGOST3410KeyParameters *self, jboolean isPrivate, LibOrgBouncycastleCryptoParamsGOST3410Parameters *params);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsGOST3410KeyParameters *new_LibOrgBouncycastleCryptoParamsGOST3410KeyParameters_initWithBoolean_withLibOrgBouncycastleCryptoParamsGOST3410Parameters_(jboolean isPrivate, LibOrgBouncycastleCryptoParamsGOST3410Parameters *params) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsGOST3410KeyParameters *create_LibOrgBouncycastleCryptoParamsGOST3410KeyParameters_initWithBoolean_withLibOrgBouncycastleCryptoParamsGOST3410Parameters_(jboolean isPrivate, LibOrgBouncycastleCryptoParamsGOST3410Parameters *params);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoParamsGOST3410KeyParameters)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // GOST3410KeyParameters_H
