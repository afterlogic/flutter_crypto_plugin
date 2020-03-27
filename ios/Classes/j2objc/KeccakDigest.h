//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/digests/KeccakDigest.java
//

#ifndef KeccakDigest_H
#define KeccakDigest_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ExtendedDigest.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class IOSLongArray;

@interface LibOrgBouncycastleCryptoDigestsKeccakDigest : NSObject < LibOrgBouncycastleCryptoExtendedDigest > {
 @public
  IOSLongArray *state_;
  IOSByteArray *dataQueue_;
  jint rate_;
  jint bitsInQueue_;
  jint fixedOutputLength_;
  jboolean squeezing_;
}

#pragma mark Public

- (instancetype __nonnull)init;

- (instancetype __nonnull)initWithInt:(jint)bitLength;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoDigestsKeccakDigest:(LibOrgBouncycastleCryptoDigestsKeccakDigest *)source;

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

#pragma mark Protected

- (void)absorbWithByteArray:(IOSByteArray *)data
                    withInt:(jint)off
                    withInt:(jint)len;

- (void)absorbBitsWithInt:(jint)data
                  withInt:(jint)bits;

- (jint)doFinalWithByteArray:(IOSByteArray *)outArg
                     withInt:(jint)outOff
                    withByte:(jbyte)partialByte
                     withInt:(jint)partialBits;

- (void)squeezeWithByteArray:(IOSByteArray *)output
                     withInt:(jint)offset
                    withLong:(jlong)outputLength;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleCryptoDigestsKeccakDigest)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoDigestsKeccakDigest, state_, IOSLongArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoDigestsKeccakDigest, dataQueue_, IOSByteArray *)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoDigestsKeccakDigest_init(LibOrgBouncycastleCryptoDigestsKeccakDigest *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoDigestsKeccakDigest *new_LibOrgBouncycastleCryptoDigestsKeccakDigest_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoDigestsKeccakDigest *create_LibOrgBouncycastleCryptoDigestsKeccakDigest_init(void);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoDigestsKeccakDigest_initWithInt_(LibOrgBouncycastleCryptoDigestsKeccakDigest *self, jint bitLength);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoDigestsKeccakDigest *new_LibOrgBouncycastleCryptoDigestsKeccakDigest_initWithInt_(jint bitLength) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoDigestsKeccakDigest *create_LibOrgBouncycastleCryptoDigestsKeccakDigest_initWithInt_(jint bitLength);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoDigestsKeccakDigest_initWithLibOrgBouncycastleCryptoDigestsKeccakDigest_(LibOrgBouncycastleCryptoDigestsKeccakDigest *self, LibOrgBouncycastleCryptoDigestsKeccakDigest *source);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoDigestsKeccakDigest *new_LibOrgBouncycastleCryptoDigestsKeccakDigest_initWithLibOrgBouncycastleCryptoDigestsKeccakDigest_(LibOrgBouncycastleCryptoDigestsKeccakDigest *source) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoDigestsKeccakDigest *create_LibOrgBouncycastleCryptoDigestsKeccakDigest_initWithLibOrgBouncycastleCryptoDigestsKeccakDigest_(LibOrgBouncycastleCryptoDigestsKeccakDigest *source);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoDigestsKeccakDigest)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // KeccakDigest_H
