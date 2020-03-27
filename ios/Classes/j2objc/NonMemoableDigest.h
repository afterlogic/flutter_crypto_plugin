//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/digests/NonMemoableDigest.java
//

#ifndef NonMemoableDigest_H
#define NonMemoableDigest_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ExtendedDigest.h"
#include "J2ObjC_header.h"

@class IOSByteArray;

@interface LibOrgBouncycastleCryptoDigestsNonMemoableDigest : NSObject < LibOrgBouncycastleCryptoExtendedDigest >

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoExtendedDigest:(id<LibOrgBouncycastleCryptoExtendedDigest>)baseDigest;

- (jint)doFinalWithByteArray:(IOSByteArray *)outArg
                     withInt:(jint)outOff;

- (NSString *)getAlgorithmName;

- (jint)getByteLength;

- (jint)getDigestSize;

- (void)reset;

- (void)updateWithByte:(jbyte)inArg;

- (void)updateWithByteArray:(IOSByteArray *)inArg
                    withInt:(jint)inOff
                    withInt:(jint)len;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoDigestsNonMemoableDigest)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoDigestsNonMemoableDigest_initWithLibOrgBouncycastleCryptoExtendedDigest_(LibOrgBouncycastleCryptoDigestsNonMemoableDigest *self, id<LibOrgBouncycastleCryptoExtendedDigest> baseDigest);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoDigestsNonMemoableDigest *new_LibOrgBouncycastleCryptoDigestsNonMemoableDigest_initWithLibOrgBouncycastleCryptoExtendedDigest_(id<LibOrgBouncycastleCryptoExtendedDigest> baseDigest) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoDigestsNonMemoableDigest *create_LibOrgBouncycastleCryptoDigestsNonMemoableDigest_initWithLibOrgBouncycastleCryptoExtendedDigest_(id<LibOrgBouncycastleCryptoExtendedDigest> baseDigest);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoDigestsNonMemoableDigest)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // NonMemoableDigest_H