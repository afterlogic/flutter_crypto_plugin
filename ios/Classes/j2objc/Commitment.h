//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/Commitment.java
//

#ifndef Commitment_H
#define Commitment_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;

@interface LibOrgBouncycastleCryptoCommitment : NSObject

#pragma mark Public

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)secret
                              withByteArray:(IOSByteArray *)commitment;

- (IOSByteArray *)getCommitment;

- (IOSByteArray *)getSecret;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoCommitment)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoCommitment_initWithByteArray_withByteArray_(LibOrgBouncycastleCryptoCommitment *self, IOSByteArray *secret, IOSByteArray *commitment);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoCommitment *new_LibOrgBouncycastleCryptoCommitment_initWithByteArray_withByteArray_(IOSByteArray *secret, IOSByteArray *commitment) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoCommitment *create_LibOrgBouncycastleCryptoCommitment_initWithByteArray_withByteArray_(IOSByteArray *secret, IOSByteArray *commitment);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoCommitment)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // Commitment_H
