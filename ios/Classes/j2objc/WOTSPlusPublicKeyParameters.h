//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/xmss/WOTSPlusPublicKeyParameters.java
//

#ifndef WOTSPlusPublicKeyParameters_H
#define WOTSPlusPublicKeyParameters_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSObjectArray;
@class LibOrgBouncycastlePqcCryptoXmssWOTSPlusParameters;

@interface LibOrgBouncycastlePqcCryptoXmssWOTSPlusPublicKeyParameters : NSObject

#pragma mark Protected

- (instancetype __nonnull)initWithLibOrgBouncycastlePqcCryptoXmssWOTSPlusParameters:(LibOrgBouncycastlePqcCryptoXmssWOTSPlusParameters *)params
                                                                     withByteArray2:(IOSObjectArray *)publicKey;

- (IOSObjectArray *)toByteArray;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcCryptoXmssWOTSPlusPublicKeyParameters)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoXmssWOTSPlusPublicKeyParameters_initWithLibOrgBouncycastlePqcCryptoXmssWOTSPlusParameters_withByteArray2_(LibOrgBouncycastlePqcCryptoXmssWOTSPlusPublicKeyParameters *self, LibOrgBouncycastlePqcCryptoXmssWOTSPlusParameters *params, IOSObjectArray *publicKey);

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoXmssWOTSPlusPublicKeyParameters *new_LibOrgBouncycastlePqcCryptoXmssWOTSPlusPublicKeyParameters_initWithLibOrgBouncycastlePqcCryptoXmssWOTSPlusParameters_withByteArray2_(LibOrgBouncycastlePqcCryptoXmssWOTSPlusParameters *params, IOSObjectArray *publicKey) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoXmssWOTSPlusPublicKeyParameters *create_LibOrgBouncycastlePqcCryptoXmssWOTSPlusPublicKeyParameters_initWithLibOrgBouncycastlePqcCryptoXmssWOTSPlusParameters_withByteArray2_(LibOrgBouncycastlePqcCryptoXmssWOTSPlusParameters *params, IOSObjectArray *publicKey);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcCryptoXmssWOTSPlusPublicKeyParameters)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // WOTSPlusPublicKeyParameters_H
