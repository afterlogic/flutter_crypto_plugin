//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/xmss/XMSSMTParameters.java
//

#ifndef XMSSMTParameters_H
#define XMSSMTParameters_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class LibOrgBouncycastlePqcCryptoXmssWOTSPlus;
@class LibOrgBouncycastlePqcCryptoXmssXMSSParameters;
@protocol LibOrgBouncycastleCryptoDigest;

@interface LibOrgBouncycastlePqcCryptoXmssXMSSMTParameters : NSObject

#pragma mark Public

- (instancetype __nonnull)initWithInt:(jint)height
                              withInt:(jint)layers
   withLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)digest;

- (jint)getDigestSize;

- (jint)getHeight;

- (jint)getLayers;

- (jint)getWinternitzParameter;

#pragma mark Protected

- (id<LibOrgBouncycastleCryptoDigest>)getDigest;

- (jint)getLen;

- (LibOrgBouncycastlePqcCryptoXmssWOTSPlus *)getWOTSPlus;

- (LibOrgBouncycastlePqcCryptoXmssXMSSParameters *)getXMSSParameters;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcCryptoXmssXMSSMTParameters)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoXmssXMSSMTParameters_initWithInt_withInt_withLibOrgBouncycastleCryptoDigest_(LibOrgBouncycastlePqcCryptoXmssXMSSMTParameters *self, jint height, jint layers, id<LibOrgBouncycastleCryptoDigest> digest);

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoXmssXMSSMTParameters *new_LibOrgBouncycastlePqcCryptoXmssXMSSMTParameters_initWithInt_withInt_withLibOrgBouncycastleCryptoDigest_(jint height, jint layers, id<LibOrgBouncycastleCryptoDigest> digest) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoXmssXMSSMTParameters *create_LibOrgBouncycastlePqcCryptoXmssXMSSMTParameters_initWithInt_withInt_withLibOrgBouncycastleCryptoDigest_(jint height, jint layers, id<LibOrgBouncycastleCryptoDigest> digest);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcCryptoXmssXMSSMTParameters)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // XMSSMTParameters_H
