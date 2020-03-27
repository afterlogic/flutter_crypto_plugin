//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/params/XDHUPublicParameters.java
//

#ifndef XDHUPublicParameters_H
#define XDHUPublicParameters_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "CipherParameters.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;

@interface LibOrgBouncycastleCryptoParamsXDHUPublicParameters : NSObject < LibOrgBouncycastleCryptoCipherParameters >

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)staticPublicKey
                              withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)ephemeralPublicKey;

- (LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)getEphemeralPublicKey;

- (LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)getStaticPublicKey;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoParamsXDHUPublicParameters)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoParamsXDHUPublicParameters_initWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_(LibOrgBouncycastleCryptoParamsXDHUPublicParameters *self, LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *staticPublicKey, LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *ephemeralPublicKey);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsXDHUPublicParameters *new_LibOrgBouncycastleCryptoParamsXDHUPublicParameters_initWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *staticPublicKey, LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *ephemeralPublicKey) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsXDHUPublicParameters *create_LibOrgBouncycastleCryptoParamsXDHUPublicParameters_initWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *staticPublicKey, LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *ephemeralPublicKey);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoParamsXDHUPublicParameters)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // XDHUPublicParameters_H
