//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/asn1/RainbowPrivateKey.java
//

#ifndef RainbowPrivateKey_H
#define RainbowPrivateKey_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class IOSIntArray;
@class IOSObjectArray;
@class IOSShortArray;
@class LibOrgBouncycastleAsn1ASN1Integer;
@class LibOrgBouncycastleAsn1ASN1Primitive;

@interface LibOrgBouncycastlePqcAsn1RainbowPrivateKey : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithShortArray2:(IOSObjectArray *)invA1
                               withShortArray:(IOSShortArray *)b1
                              withShortArray2:(IOSObjectArray *)invA2
                               withShortArray:(IOSShortArray *)b2
                                 withIntArray:(IOSIntArray *)vi
withLibOrgBouncycastlePqcCryptoRainbowLayerArray:(IOSObjectArray *)layers;

- (IOSShortArray *)getB1;

- (IOSShortArray *)getB2;

+ (LibOrgBouncycastlePqcAsn1RainbowPrivateKey *)getInstanceWithId:(id)o;

- (IOSObjectArray *)getInvA1;

- (IOSObjectArray *)getInvA2;

- (IOSObjectArray *)getLayers;

- (LibOrgBouncycastleAsn1ASN1Integer *)getVersion;

- (IOSIntArray *)getVi;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcAsn1RainbowPrivateKey)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcAsn1RainbowPrivateKey_initWithShortArray2_withShortArray_withShortArray2_withShortArray_withIntArray_withLibOrgBouncycastlePqcCryptoRainbowLayerArray_(LibOrgBouncycastlePqcAsn1RainbowPrivateKey *self, IOSObjectArray *invA1, IOSShortArray *b1, IOSObjectArray *invA2, IOSShortArray *b2, IOSIntArray *vi, IOSObjectArray *layers);

FOUNDATION_EXPORT LibOrgBouncycastlePqcAsn1RainbowPrivateKey *new_LibOrgBouncycastlePqcAsn1RainbowPrivateKey_initWithShortArray2_withShortArray_withShortArray2_withShortArray_withIntArray_withLibOrgBouncycastlePqcCryptoRainbowLayerArray_(IOSObjectArray *invA1, IOSShortArray *b1, IOSObjectArray *invA2, IOSShortArray *b2, IOSIntArray *vi, IOSObjectArray *layers) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcAsn1RainbowPrivateKey *create_LibOrgBouncycastlePqcAsn1RainbowPrivateKey_initWithShortArray2_withShortArray_withShortArray2_withShortArray_withIntArray_withLibOrgBouncycastlePqcCryptoRainbowLayerArray_(IOSObjectArray *invA1, IOSShortArray *b1, IOSObjectArray *invA2, IOSShortArray *b2, IOSIntArray *vi, IOSObjectArray *layers);

FOUNDATION_EXPORT LibOrgBouncycastlePqcAsn1RainbowPrivateKey *LibOrgBouncycastlePqcAsn1RainbowPrivateKey_getInstanceWithId_(id o);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcAsn1RainbowPrivateKey)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // RainbowPrivateKey_H
