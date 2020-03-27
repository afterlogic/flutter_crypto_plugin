//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/ec/ECPair.java
//

#ifndef ECPair_H
#define ECPair_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class LibOrgBouncycastleMathEcECPoint;

@interface LibOrgBouncycastleCryptoEcECPair : NSObject

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)x
                              withLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)y;

- (jboolean)equalsWithLibOrgBouncycastleCryptoEcECPair:(LibOrgBouncycastleCryptoEcECPair *)other;

- (jboolean)isEqual:(id)other;

- (LibOrgBouncycastleMathEcECPoint *)getX;

- (LibOrgBouncycastleMathEcECPoint *)getY;

- (NSUInteger)hash;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoEcECPair)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoEcECPair_initWithLibOrgBouncycastleMathEcECPoint_withLibOrgBouncycastleMathEcECPoint_(LibOrgBouncycastleCryptoEcECPair *self, LibOrgBouncycastleMathEcECPoint *x, LibOrgBouncycastleMathEcECPoint *y);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEcECPair *new_LibOrgBouncycastleCryptoEcECPair_initWithLibOrgBouncycastleMathEcECPoint_withLibOrgBouncycastleMathEcECPoint_(LibOrgBouncycastleMathEcECPoint *x, LibOrgBouncycastleMathEcECPoint *y) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEcECPair *create_LibOrgBouncycastleCryptoEcECPair_initWithLibOrgBouncycastleMathEcECPoint_withLibOrgBouncycastleMathEcECPoint_(LibOrgBouncycastleMathEcECPoint *x, LibOrgBouncycastleMathEcECPoint *y);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoEcECPair)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ECPair_H
