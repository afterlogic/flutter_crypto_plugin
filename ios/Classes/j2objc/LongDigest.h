//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/digests/LongDigest.java
//

#ifndef LongDigest_H
#define LongDigest_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "EncodableDigest.h"
#include "ExtendedDigest.h"
#include "J2ObjC_header.h"
#include "Memoable.h"

@class IOSByteArray;
@class IOSLongArray;

@interface LibOrgBouncycastleCryptoDigestsLongDigest : NSObject < LibOrgBouncycastleCryptoExtendedDigest, LibOrgBouncycastleUtilMemoable, LibOrgBouncycastleCryptoDigestsEncodableDigest > {
 @public
  jlong H1_;
  jlong H2_;
  jlong H3_;
  jlong H4_;
  jlong H5_;
  jlong H6_;
  jlong H7_;
  jlong H8_;
}
@property (readonly, class) IOSLongArray *K NS_SWIFT_NAME(K);

+ (IOSLongArray *)K;

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

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoDigestsLongDigest:(LibOrgBouncycastleCryptoDigestsLongDigest *)t;

- (void)copyInWithLibOrgBouncycastleCryptoDigestsLongDigest:(LibOrgBouncycastleCryptoDigestsLongDigest *)t OBJC_METHOD_FAMILY_NONE;

- (jint)getEncodedStateSize;

- (void)populateStateWithByteArray:(IOSByteArray *)state;

- (void)processBlock;

- (void)processLengthWithLong:(jlong)lowW
                     withLong:(jlong)hiW;

- (void)processWordWithByteArray:(IOSByteArray *)inArg
                         withInt:(jint)inOff;

- (void)restoreStateWithByteArray:(IOSByteArray *)encodedState;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleCryptoDigestsLongDigest)

inline IOSLongArray *LibOrgBouncycastleCryptoDigestsLongDigest_get_K(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT IOSLongArray *LibOrgBouncycastleCryptoDigestsLongDigest_K;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoDigestsLongDigest, K, IOSLongArray *)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoDigestsLongDigest_init(LibOrgBouncycastleCryptoDigestsLongDigest *self);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoDigestsLongDigest_initWithLibOrgBouncycastleCryptoDigestsLongDigest_(LibOrgBouncycastleCryptoDigestsLongDigest *self, LibOrgBouncycastleCryptoDigestsLongDigest *t);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoDigestsLongDigest)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // LongDigest_H