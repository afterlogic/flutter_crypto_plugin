//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/digests/GeneralDigest.java
//

#ifndef GeneralDigest_H
#define GeneralDigest_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ExtendedDigest.h"
#include "J2ObjC_header.h"
#include "Memoable.h"

@class IOSByteArray;

@interface LibOrgBouncycastleCryptoDigestsGeneralDigest : NSObject < LibOrgBouncycastleCryptoExtendedDigest, LibOrgBouncycastleUtilMemoable >

#pragma mark Public

- (void)finish;

- (jint)getByteLength;

- (void)reset;

- (void)updateWithByte:(jbyte)inArg;

- (void)updateWithByteArray:(IOSByteArray *)inArg
                    withInt:(jint)inOff
                    withInt:(jint)len;

#pragma mark Protected

- (instancetype __nonnull)init;

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)encodedState;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoDigestsGeneralDigest:(LibOrgBouncycastleCryptoDigestsGeneralDigest *)t;

- (void)copyInWithLibOrgBouncycastleCryptoDigestsGeneralDigest:(LibOrgBouncycastleCryptoDigestsGeneralDigest *)t OBJC_METHOD_FAMILY_NONE;

- (void)populateStateWithByteArray:(IOSByteArray *)state;

- (void)processBlock;

- (void)processLengthWithLong:(jlong)bitLength;

- (void)processWordWithByteArray:(IOSByteArray *)inArg
                         withInt:(jint)inOff;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoDigestsGeneralDigest)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoDigestsGeneralDigest_init(LibOrgBouncycastleCryptoDigestsGeneralDigest *self);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoDigestsGeneralDigest_initWithLibOrgBouncycastleCryptoDigestsGeneralDigest_(LibOrgBouncycastleCryptoDigestsGeneralDigest *self, LibOrgBouncycastleCryptoDigestsGeneralDigest *t);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoDigestsGeneralDigest_initWithByteArray_(LibOrgBouncycastleCryptoDigestsGeneralDigest *self, IOSByteArray *encodedState);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoDigestsGeneralDigest)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // GeneralDigest_H
